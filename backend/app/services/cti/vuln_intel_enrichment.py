"""
Vulnerability Intelligence Enrichment (CISA KEV + FIRST EPSS + NVD) for OpenRecon 3.0.
Explicitly distinguishes:
- identified_vulnerability
- known_exploited (CISA KEV)
- exploitation_probability (FIRST EPSS)
- confirmed_exposure (verified on target)
- mitigation_available
"""

import logging
import re
from typing import Any, Dict, Optional, Set

import httpx

from app.core.tls_config import get_httpx_verify

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EPSS_API = "https://api.first.org/data/v1/epss"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class VulnIntelEnrichmentService:
    def __init__(self, kev_catalog: Optional[Set[str]] = None):
        self.kev_catalog: Set[str] = {c.upper() for c in (kev_catalog or set())}

    async def refresh_cisa_kev(self, timeout: float = 12.0) -> int:
        async with httpx.AsyncClient(timeout=timeout, verify=get_httpx_verify()) as client:
            resp = await client.get(_CISA_KEV_URL)
            if resp.status_code != 200:
                raise RuntimeError(f"CISA KEV feed HTTP {resp.status_code}")
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            self.kev_catalog = {v["cveID"].upper() for v in vulns if v.get("cveID")}
            return len(self.kev_catalog)

    async def fetch_epss(self, cve_id: str, timeout: float = 8.0) -> Dict[str, Optional[float]]:
        cve_norm = cve_id.strip().upper()
        if not _CVE_RE.match(cve_norm):
            raise ValueError(f"Invalid CVE identifier: '{cve_id}'")
        async with httpx.AsyncClient(timeout=timeout, verify=get_httpx_verify()) as client:
            resp = await client.get(_EPSS_API, params={"cve": cve_norm})
            if resp.status_code != 200:
                return {"epss": None, "percentile": None}
            items = resp.json().get("data", [])
            if not items:
                return {"epss": 0.0, "percentile": 0.0}
            return {
                "epss": float(items[0].get("epss", 0.0)),
                "percentile": float(items[0].get("percentile", 0.0)),
            }

    async def evaluate_cve_posture(
        self,
        cve_id: str,
        confirmed_exposure: bool = False,
        mitigation_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        cve_norm = cve_id.strip().upper()
        if not _CVE_RE.match(cve_norm):
            raise ValueError(f"Invalid CVE identifier: '{cve_id}'")

        known_exploited = cve_norm in self.kev_catalog
        epss_data = await self.fetch_epss(cve_norm)

        return {
            "cve_id": cve_norm,
            "identified_vulnerability": True,
            "known_exploited": known_exploited,
            "exploitation_probability": {
                "epss_score": epss_data.get("epss"),
                "epss_percentile": epss_data.get("percentile"),
            },
            "confirmed_exposure": bool(confirmed_exposure),
            "mitigation_available": bool(mitigation_notes),
            "mitigation_guidance": mitigation_notes or "Verify vendor advisory / patch availability in NVD.",
        }
