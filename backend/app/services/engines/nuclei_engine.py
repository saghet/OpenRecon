import shutil
import subprocess
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class NucleiEngine:
    """
    Vulnerability and Exposure Scanner wrapper for ProjectDiscovery Nuclei.
    Runs non-destructive exposure and misconfiguration templates.
    """

    def __init__(self):
        self.has_nuclei = shutil.which("nuclei") is not None

    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        findings = []

        if not self.has_nuclei:
            return findings

        try:
            cmd = [
                "nuclei",
                "-u", target_url,
                "-tags", "exposure,misconfig,panel,default-login",
                "-severity", "low,medium,high,critical",
                "-rate-limit", "15",
                "-silent",
                "-json"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.stdout:
                for line in proc.stdout.splitlines():
                    try:
                        item = json.loads(line)
                        info = item.get("info", {})
                        findings.append({
                            "title": info.get("name", "Unknown Finding"),
                            "severity": info.get("severity", "INFO").upper(),
                            "cve_id": (info.get("classification", {}).get("cve-id") or [None])[0] if isinstance(info.get("classification", {}).get("cve-id"), list) else None,
                            "cvss_score": info.get("classification", {}).get("cvss-score"),
                            "epss_score": info.get("classification", {}).get("epss-score"),
                            "description": info.get("description"),
                            "remediation": info.get("remediation"),
                            "template_id": item.get("template-id"),
                            "detector": "nuclei"
                        })
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Nuclei scan error on {target_url}: {e}")

        return findings
