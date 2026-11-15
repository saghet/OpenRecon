import asyncio
import difflib
import json
import logging
import re
import shutil
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import httpx
import tldextract

from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import get_httpx_verify

logger = logging.getLogger(__name__)

# Minimal keyboard adjacency map for typosquatting generation
_QWERTY_ADJACENT = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu", "z": "asx",
}

# Unicode homoglyphs (IDN) for lookalike detection
_IDN_HOMOGLYPHS = {
    "a": ["а"],  # Cyrillic small letter a
    "e": ["е"],  # Cyrillic small letter ie
    "o": ["о"],  # Cyrillic small letter o
    "p": ["р"],  # Cyrillic small letter er
    "c": ["с"],  # Cyrillic small letter es
    "i": ["і"],  # Cyrillic small letter byelorussian-ukrainian i
}


class DRPEngine:
    """
    Digital Risk Protection Engine.
    - Integrates dnstwist (when installed) or expanded native permutations (homoglyphs,
      IDN punycode, transposition, repetition, keyboard adjacency, omission, brand affixes).
    - Uses async DNS/MX resolution + independent HTTP page signals.
    - Never classifies a domain as phishing solely by name similarity.
    """

    def __init__(self, timeout: float = 3.0, max_candidates: int = 80, max_concurrency: int = 20):
        self.timeout = timeout
        self.max_candidates = max_candidates
        self.max_concurrency = max_concurrency
        self.has_dnstwist = shutil.which("dnstwist") is not None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    def generate_permutations(self, domain: str) -> Set[str]:
        extracted = tldextract.extract(domain)
        name = extracted.domain.lower()
        suffix = extracted.suffix.lower()

        if not name or not suffix:
            return set()

        variants: Set[str] = set()

        # 1. ASCII homoglyphs
        replacements = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"]}
        for char, subs in replacements.items():
            if char in name:
                for sub in subs:
                    variants.add(f"{name.replace(char, sub)}.{suffix}")

        # 2. IDN Punycode homoglyphs
        for i, ch in enumerate(name):
            for glyph in _IDN_HOMOGLYPHS.get(ch, []):
                idn_label = name[:i] + glyph + name[i + 1:]
                try:
                    puny = idn_label.encode("idna").decode("ascii")
                    variants.add(f"{puny}.{suffix}")
                except Exception:
                    pass

        # 3. Omission & Repetition
        for i in range(len(name)):
            if len(name) > 2:
                variants.add(f"{name[:i] + name[i + 1:]}.{suffix}")
            variants.add(f"{name[:i] + name[i] + name[i:]}.{suffix}")

        # 4. Transposition
        for i in range(len(name) - 1):
            if name[i] != name[i + 1]:
                swapped = name[:i] + name[i + 1] + name[i] + name[i + 2:]
                variants.add(f"{swapped}.{suffix}")

        # 5. Keyboard adjacency (first 6 chars to bound space)
        for i, ch in enumerate(name[:6]):
            for adj in _QWERTY_ADJACENT.get(ch, "")[:2]:
                variants.add(f"{name[:i] + adj + name[i + 1:]}.{suffix}")

        # 6. Brand phishing prefixes/suffixes
        for keyword in ["login-", "secure-", "auth-", "sso-", "portal-", "-app", "-support", "-corp", "-verify"]:
            if keyword.endswith("-"):
                variants.add(f"{keyword}{name}.{suffix}")
            else:
                variants.add(f"{name}{keyword}.{suffix}")

        variants.discard(domain.lower())
        return set(sorted(variants)[: self.max_candidates])

    async def _run_dnstwist(self, domain: str) -> Optional[List[Dict[str, Any]]]:
        if not self.has_dnstwist:
            return None
        try:
            proc = await asyncio.create_subprocess_exec(
                "dnstwist", "--registered", "--mxcheck", "--format", "json", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            data = json.loads(stdout.decode("utf-8", errors="ignore") or "[]")
            return data if isinstance(data, list) else None
        except Exception as e:
            logger.warning(f"dnstwist execution failed for {domain}, using native fallback: {e}")
            return None

    async def _fetch_http_title(self, candidate: str) -> Optional[str]:
        guard = SecurityGovernanceGuard.validate_target_safety(f"https://{candidate}")
        if not guard.get("safe"):
            return None
        try:
            async with httpx.AsyncClient(timeout=4.0, verify=get_httpx_verify(), follow_redirects=False) as client:
                resp = await client.get(f"https://{candidate}")
                m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                return m.group(1).strip()[:120] if m else f"HTTP {resp.status_code}"
        except Exception:
            return None

    def _resolve_dns_sync(self, candidate: str) -> Dict[str, Any]:
        resolved_ip = None
        has_mx = False
        try:
            answers = self.resolver.resolve(candidate, "A")
            if answers:
                resolved_ip = answers[0].to_text()
        except Exception:
            pass
        if resolved_ip:
            try:
                mx_answers = self.resolver.resolve(candidate, "MX")
                if mx_answers:
                    has_mx = True
            except Exception:
                pass
        return {"resolved_ip": resolved_ip, "has_mx": has_mx}

    @staticmethod
    def assess_phishing_confidence(
        brand_title: Optional[str],
        candidate_title: Optional[str],
        has_a: bool,
        has_mx: bool,
    ) -> Dict[str, Any]:
        """Multi-signal confidence scoring: never labels phishing by domain similarity alone."""
        signals: List[str] = []
        score = 0.0
        if has_a:
            signals.append("dns_a_active")
            score += 0.30
        if has_mx:
            signals.append("dns_mx_active")
            score += 0.25
        title_sim = 0.0
        if candidate_title:
            signals.append("http_live")
            score += 0.15
            if brand_title:
                title_sim = difflib.SequenceMatcher(None, brand_title.lower(), candidate_title.lower()).ratio()
                if title_sim >= 0.65:
                    signals.append("http_title_similarity")
                    score += 0.30

        classification = "SUSPICIOUS_LOOKALIKE"
        if score >= 0.75 and "http_title_similarity" in signals:
            classification = "POTENTIAL_PHISHING_MULTI_SIGNAL"
        elif has_a and has_mx:
            classification = "ACTIVE_INFRASTRUCTURE_WITH_MX"

        severity = "HIGH" if (has_mx and ("http_title_similarity" in signals or score >= 0.65)) else ("MEDIUM" if has_a else "LOW")
        return {
            "confidence": round(min(1.0, score), 2),
            "signals": signals,
            "title_similarity": round(title_sim, 2),
            "classification": classification,
            "severity": severity,
        }

    async def scan_typosquatting(self, domain: str) -> List[Dict[str, Any]]:
        brand_title = await self._fetch_http_title(domain)
        dnstwist_data = await self._run_dnstwist(domain)
        findings: List[Dict[str, Any]] = []

        if dnstwist_data is not None:
            for item in dnstwist_data:
                cand = str(item.get("domain", "")).lower().strip()
                if not cand or cand == domain.lower():
                    continue
                ips = item.get("dns_a") or []
                mxs = item.get("dns_mx") or []
                resolved_ip = ips[0] if isinstance(ips, list) and ips else None
                has_mx = bool(mxs)
                if not resolved_ip:
                    continue
                cand_title = await self._fetch_http_title(cand)
                assessment = self.assess_phishing_confidence(brand_title, cand_title, True, has_mx)
                findings.append({
                    "lookalike_domain": cand,
                    "resolved_ip": resolved_ip,
                    "has_mx_records": has_mx,
                    "http_title": cand_title,
                    "fuzzer": item.get("fuzzer", "dnstwist"),
                    **assessment,
                    "details": f"[{assessment['classification']}] IP: {resolved_ip}, MX: {has_mx}, Signals: {','.join(assessment['signals'])}",
                })
            return findings

        permutations = self.generate_permutations(domain)
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _check(candidate: str) -> Optional[Dict[str, Any]]:
            async with sem:
                dns_info = await asyncio.to_thread(self._resolve_dns_sync, candidate)
                if not dns_info["resolved_ip"]:
                    return None
                cand_title = await self._fetch_http_title(candidate)
                assessment = self.assess_phishing_confidence(
                    brand_title, cand_title, True, dns_info["has_mx"]
                )
                return {
                    "lookalike_domain": candidate,
                    "resolved_ip": dns_info["resolved_ip"],
                    "has_mx_records": dns_info["has_mx"],
                    "http_title": cand_title,
                    "fuzzer": "openrecon_native",
                    **assessment,
                    "details": f"[{assessment['classification']}] IP: {dns_info['resolved_ip']}, MX: {dns_info['has_mx']}, Signals: {','.join(assessment['signals'])}",
                }

        results = await asyncio.gather(*[_check(c) for c in permutations])
        return [r for r in results if r is not None]
