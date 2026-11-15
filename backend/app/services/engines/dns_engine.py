import asyncio
import json
import logging
import shutil
import uuid
from typing import Any, Dict, List, Optional, Set

import dns.resolver
import httpx

from app.core.tls_config import get_httpx_verify

logger = logging.getLogger(__name__)


class DNSEngine:
    """
    Hybrid Async DNS & Subdomain Discovery Engine.
    - Combines Subfinder (JSON), Amass passive (if available), and crt.sh.
    - Preserves per-subdomain discovery provenance.
    - Detects and eliminates Wildcard DNS false positives.
    - Uses dnsx (if installed) or bounded async concurrency via dnspython.
    """

    def __init__(self, timeout: float = 8.0, max_concurrency: int = 25):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.has_subfinder = shutil.which("subfinder") is not None
        self.has_amass = shutil.which("amass") is not None
        self.has_dnsx = shutil.which("dnsx") is not None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    async def _run_subfinder(self, domain: str) -> Dict[str, Set[str]]:
        found: Dict[str, Set[str]] = {}
        if not self.has_subfinder:
            return found
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent", "-all", "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    host = str(obj.get("host", "")).strip().lower()
                    src = str(obj.get("source", "subfinder")).strip() or "subfinder"
                except json.JSONDecodeError:
                    host = line.lower()
                    src = "subfinder"
                if host and (host == domain or host.endswith(f".{domain}")):
                    found.setdefault(host, set()).add(f"subfinder:{src}")
        except Exception as e:
            logger.warning(f"Subfinder execution error for {domain}: {e}")
        return found

    async def _run_amass_passive(self, domain: str) -> Dict[str, Set[str]]:
        found: Dict[str, Set[str]] = {}
        if not self.has_amass:
            return found
        try:
            proc = await asyncio.create_subprocess_exec(
                "amass", "enum", "-passive", "-d", domain, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90.0)
            for line in stdout.decode("utf-8", errors="ignore").splitlines():
                host = line.strip().lower()
                if host and (host == domain or host.endswith(f".{domain}")):
                    found.setdefault(host, set()).add("amass_passive")
        except Exception as e:
            logger.warning(f"Amass passive execution error for {domain}: {e}")
        return found

    async def _query_crtsh(self, domain: str) -> Dict[str, Set[str]]:
        found: Dict[str, Set[str]] = {}
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with httpx.AsyncClient(timeout=15.0, verify=get_httpx_verify()) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    for entry in resp.json():
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and (sub == domain or sub.endswith(f".{domain}")) and not any(c in sub for c in ["@", " "]):
                                found.setdefault(sub, set()).add("crt.sh")
        except Exception as e:
            logger.warning(f"crt.sh query failed for {domain}: {e}")
        return found

    def detect_wildcard_ips(self, domain: str) -> Set[str]:
        """Probes random non-existent subdomains to detect catch-all wildcard DNS IPs."""
        wildcard_ips: Set[str] = set()
        probe_hits: List[Set[str]] = []
        for _ in range(2):
            token = uuid.uuid4().hex[:12]
            probe_host = f"openrecon-wc-{token}.{domain}"
            ips = self._resolve_all_a(probe_host)
            if ips:
                probe_hits.append(ips)
        if len(probe_hits) == 2:
            wildcard_ips = probe_hits[0].intersection(probe_hits[1])
        return wildcard_ips

    def _resolve_all_a(self, hostname: str) -> Set[str]:
        ips: Set[str] = set()
        try:
            answers = self.resolver.resolve(hostname, "A")
            for rdata in answers:
                ips.add(rdata.to_text())
        except Exception:
            pass
        return ips

    @staticmethod
    def _infer_cloud_provider(ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        if ip.startswith("104.") or ip.startswith("172.67."):
            return "Cloudflare"
        if ip.startswith("52.") or ip.startswith("54.") or ip.startswith("3."):
            return "AWS"
        if ip.startswith("34.") or ip.startswith("35."):
            return "Google Cloud"
        if ip.startswith("20.") or ip.startswith("40."):
            return "Microsoft Azure"
        return None

    def resolve_host(self, hostname: str):
        ips = self._resolve_all_a(hostname)
        if not ips:
            return None, None
        first_ip = sorted(ips)[0]
        return first_ip, self._infer_cloud_provider(first_ip)

    async def discover_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        domain = domain.strip().lower()
        merged: Dict[str, Set[str]] = {domain: {"seed"}}

        # Run passive discovery sources concurrently
        source_maps = await asyncio.gather(
            self._run_subfinder(domain),
            self._run_amass_passive(domain),
            self._query_crtsh(domain),
            return_exceptions=True,
        )
        for sm in source_maps:
            if isinstance(sm, dict):
                for host, srcs in sm.items():
                    merged.setdefault(host, set()).update(srcs)

        # Detect wildcard DNS once per apex domain
        wildcard_ips = await asyncio.to_thread(self.detect_wildcard_ips, domain)

        sem = asyncio.Semaphore(self.max_concurrency)

        async def _resolve_entry(sub: str, srcs: Set[str]) -> Optional[Dict[str, Any]]:
            async with sem:
                ips = await asyncio.to_thread(self._resolve_all_a, sub)
                # Filter out wildcard-only resolutions (except for apex domain itself)
                if wildcard_ips and sub != domain and ips and ips.issubset(wildcard_ips):
                    logger.debug(f"Filtered wildcard DNS subdomain: {sub} -> {ips}")
                    return None
                resolved_ip = sorted(ips)[0] if ips else None
                return {
                    "subdomain": sub,
                    "ip_address": resolved_ip,
                    "is_live": resolved_ip is not None,
                    "cloud_provider": self._infer_cloud_provider(resolved_ip),
                    "discovery_source": ",".join(sorted(srcs)),
                    "wildcard_filtered": False,
                }

        tasks = [_resolve_entry(sub, srcs) for sub, srcs in sorted(merged.items())]
        resolved_results = await asyncio.gather(*tasks)
        return [r for r in resolved_results if r is not None]
