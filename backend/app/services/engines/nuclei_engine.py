import asyncio
import json
import logging
import shutil
from typing import Any, Dict, List

from app.core.evidence_sanitizer import EvidenceSanitizer

logger = logging.getLogger(__name__)

# Never execute destructive, DoS, fuzzing, or intrusive exploitation templates automatically
EXCLUDED_DANGEROUS_TAGS = "dos,fuzz,intrusive,bruteforce"


class NucleiEngine:
    """
    Vulnerability and Exposure Scanner wrapper for ProjectDiscovery Nuclei (v3 JSONL).
    - Non-blocking async subprocess execution.
    - Strictly excludes destructive/DoS/fuzzing templates.
    - Preserves sanitized HTTP evidence and distinguishes version-only indications
      from active proof-based detections.
    """

    def __init__(self, timeout: float = 120.0):
        self.has_nuclei = shutil.which("nuclei") is not None
        self.timeout = timeout

    @staticmethod
    def parse_jsonl_output(raw_stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            classification = info.get("classification", {}) or {}
            cve_raw = classification.get("cve-id")
            cve_id = cve_raw[0] if isinstance(cve_raw, list) and cve_raw else (cve_raw if isinstance(cve_raw, str) else None)

            severity = str(info.get("severity", "INFO")).upper()
            matcher_name = item.get("matcher-name") or ""
            matched_at = item.get("matched-at") or item.get("host") or ""
            extracted = item.get("extracted-results") or []
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            # Version-only heuristic: detections solely based on banner/version without active exploit proof
            is_version_indication = (
                severity == "INFO"
                or "version" in matcher_name.lower()
                or ("detect" in tags and not item.get("request"))
            )

            raw_evidence_parts = [
                f"template={item.get('template-id', 'unknown')}",
                f"matched_at={matched_at}",
                f"matcher={matcher_name}",
            ]
            if extracted:
                raw_evidence_parts.append(f"extracted={','.join(str(x) for x in extracted[:5])}")
            if item.get("curl-command"):
                raw_evidence_parts.append(f"curl={item.get('curl-command')}")

            sanitized_evidence = EvidenceSanitizer.sanitize_raw_content(" | ".join(raw_evidence_parts), max_chars=2048)

            findings.append({
                "title": info.get("name", "Unknown Finding"),
                "severity": severity,
                "cve_id": cve_id,
                "cvss_score": classification.get("cvss-score"),
                "epss_score": classification.get("epss-score"),
                "cwe_id": (classification.get("cwe-id") or [None])[0] if isinstance(classification.get("cwe-id"), list) else classification.get("cwe-id"),
                "description": info.get("description"),
                "remediation": info.get("remediation"),
                "template_id": item.get("template-id"),
                "matched_at": matched_at,
                "matcher_name": matcher_name,
                "evidence": sanitized_evidence,
                "is_version_only_indication": is_version_indication,
                "detector": "nuclei",
            })
        return findings

    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        if not self.has_nuclei:
            return []

        try:
            cmd = [
                "nuclei",
                "-u", target_url,
                "-tags", "exposure,misconfig,panel,default-login,cve",
                "-etags", EXCLUDED_DANGEROUS_TAGS,
                "-severity", "low,medium,high,critical",
                "-rate-limit", "15",
                "-silent",
                "-jsonl",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            return self.parse_jsonl_output(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            logger.warning(f"Nuclei scan error on {target_url}: {e}")
            return []
