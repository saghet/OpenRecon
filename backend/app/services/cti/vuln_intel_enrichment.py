"""
Vulnerability Intelligence Enrichment (CISA KEV + FIRST EPSS + CISA Vulnrichment SSVC) for OpenRecon 3.0.
Explicitly distinguishes:
- identified_vulnerability
- known_exploited (CISA KEV)
- exploitation_probability (FIRST EPSS)
- ssvc_decision (CISA Vulnrichment CVE JSON 5.0 ADP)
- confirmed_exposure (verified on target)
- mitigation_available
"""

import logging
import re
import time
from typing import Any, Dict, Optional, Set, Tuple

import httpx

from app.core.tls_config import get_httpx_verify

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EPSS_API = "https://api.first.org/data/v1/epss"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class VulnIntelEnrichmentService:
    def __init__(self, kev_catalog: Optional[Set[str]] = None, epss_ttl_seconds: int = 3600):
        self.kev_catalog: Set[str] = {c.upper() for c in (kev_catalog or set())}
        self.epss_ttl_seconds = epss_ttl_seconds
        self._epss_cache: Dict[str, Tuple[float, Dict[str, Optional[float]]]] = {}

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

        cached = self._epss_cache.get(cve_norm)
        if cached and (time.monotonic() - cached[0]) < self.epss_ttl_seconds:
            return cached[1]

        try:
            async with httpx.AsyncClient(timeout=timeout, verify=get_httpx_verify()) as client:
                resp = await client.get(_EPSS_API, params={"cve": cve_norm})
                if resp.status_code != 200:
                    return {"epss": None, "percentile": None}
                items = resp.json().get("data", [])
                if not items:
                    result = {"epss": None, "percentile": None}
                else:
                    result = {
                        "epss": float(items[0].get("epss", 0.0)),
                        "percentile": float(items[0].get("percentile", 0.0)),
                    }
                self._epss_cache[cve_norm] = (time.monotonic(), result)
                return result
        except Exception as exc:
            logger.warning(f"EPSS lookup failed for {cve_norm}: {exc}")
            return {"epss": None, "percentile": None}

    @staticmethod
    def parse_vulnrichment_adp(cve_record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses a CISA Vulnrichment CVE JSON 5.x record's ADP container to extract
        SSVC decision points (Exploitation, Automatable, Technical Impact), CWE, and CVSS.
        """
        adp_list = (cve_record.get("containers") or {}).get("adp") or []
        ssvc: Dict[str, str] = {}
        cwe_ids: list[str] = []
        cvss_score: Optional[float] = None

        for adp in adp_list:
            for metric in adp.get("metrics") or []:
                other = metric.get("other") or {}
                if other.get("type") == "ssvc":
                    for opt in (other.get("content") or {}).get("options") or []:
                        if isinstance(opt, dict):
                            for k, v in opt.items():
                                ssvc[str(k)] = str(v)
                for cvss_key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                    if cvss_key in metric and isinstance(metric[cvss_key], dict):
                        score = metric[cvss_key].get("baseScore")
                        if score is not None:
                            cvss_score = float(score)

            for pt in adp.get("problemTypes") or []:
                for desc in pt.get("descriptions") or []:
                    if desc.get("cweId"):
                        cwe_ids.append(str(desc["cweId"]))

        return {
            "ssvc": ssvc,
            "cwe_ids": cwe_ids,
            "adp_cvss_score": cvss_score,
        }

    async def evaluate_cve_posture(
        self,
        cve_id: str,
        confirmed_exposure: bool = False,
        mitigation_notes: Optional[str] = None,
        vulnrichment_record: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cve_norm = cve_id.strip().upper()
        if not _CVE_RE.match(cve_norm):
            raise ValueError(f"Invalid CVE identifier: '{cve_id}'")

        known_exploited = cve_norm in self.kev_catalog
        epss_data = await self.fetch_epss(cve_norm)
        adp_info = self.parse_vulnrichment_adp(vulnrichment_record) if vulnrichment_record else {"ssvc": {}, "cwe_ids": [], "adp_cvss_score": None}

        return {
            "cve_id": cve_norm,
            "identified_vulnerability": True,
            "known_exploited": known_exploited,
            "exploitation_probability": {
                "epss_score": epss_data.get("epss"),
                "epss_percentile": epss_data.get("percentile"),
            },
            "ssvc": adp_info["ssvc"],
            "cwe_ids": adp_info["cwe_ids"],
            "adp_cvss_score": adp_info["adp_cvss_score"],
            "confirmed_exposure": bool(confirmed_exposure),
            "mitigation_available": bool(mitigation_notes),
            "mitigation_guidance": mitigation_notes or "Verify vendor advisory / patch availability in NVD.",
        }
