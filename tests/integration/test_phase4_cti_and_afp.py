"""
Phase 4 CTI, Correlation & Anti-False-Positive Integration Tests:
- STIX 2.1 Export/Import, TLP markings, expiration, deduplication
- CISA KEV + EPSS posture separation
- CorrelationGraphEngine inferred vs confirmed edges
- AntiFalsePositiveEngine 8-stage pipeline & AI Critical/High guardrail
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.models.evidence import FindingValidationState
from app.services.correlation.graph_engine import CorrelationGraphEngine
from app.services.cti.stix_taxii_service import STIX21TaxiiService
from app.services.cti.vuln_intel_enrichment import VulnIntelEnrichmentService
from app.services.validation import AntiFalsePositiveEngine, CandidateFinding


class TestPhase4CTIAndAFP(unittest.TestCase):
    def test_01_stix21_export_import_deduplication_and_tlp(self):
        bundle = STIX21TaxiiService.build_stix21_bundle(
            indicators=[
                {"type": "ipv4-addr", "value": "203.0.113.10", "confidence": 90, "source": "OpenCTI"},
                {"type": "ipv4-addr", "value": "203.0.113.10", "confidence": 60, "source": "Duplicate"},
                {"type": "domain-name", "value": "evil.example.com", "confidence": 85, "source": "MISP"},
            ],
            tlp="TLP:GREEN",
            default_ttl_days=14,
        )
        self.assertEqual(bundle["type"], "bundle")
        # 1 identity + 2 deduplicated indicators
        self.assertEqual(len(bundle["objects"]), 3)

        imported = STIX21TaxiiService.parse_and_deduplicate_stix_bundle(bundle)
        self.assertEqual(imported["imported_count"], 2)
        self.assertEqual(imported["items"][0]["tlp"], "TLP:GREEN")
        self.assertIsNotNone(imported["items"][0]["valid_until"])

    def test_02_vuln_intel_enrichment_kev_epss_separation(self):
        svc = VulnIntelEnrichmentService(kev_catalog={"CVE-2024-21762"})
        with patch.object(svc, "fetch_epss", new=AsyncMock(return_value={"epss": 0.94, "percentile": 0.99})):
            posture = asyncio.run(
                svc.evaluate_cve_posture(
                    "CVE-2024-21762",
                    confirmed_exposure=False,
                    mitigation_notes="Upgrade FortiOS to patched release.",
                )
            )
        self.assertTrue(posture["identified_vulnerability"])
        self.assertTrue(posture["known_exploited"])
        self.assertEqual(posture["exploitation_probability"]["epss_score"], 0.94)
        self.assertFalse(posture["confirmed_exposure"])
        self.assertTrue(posture["mitigation_available"])

    def test_03_correlation_graph_distinguishes_inferred_vs_confirmed(self):
        g = CorrelationGraphEngine()
        g.add_node("org_1", "Acme", "ORGANIZATION")
        g.add_node("dom_1", "acme.com", "DOMAIN")
        g.add_node("actor_1", "APT-X", "ACTOR")

        g.add_edge("org_1", "dom_1", "OWNS", confidence=100, evidence="WHOIS", source="RDAP")
        g.add_edge("dom_1", "actor_1", "ATTRIBUTED_TO", confidence=55, evidence="Heuristic", source="OSINT")

        self.assertFalse(g.edges[0]["is_inferred"])
        self.assertEqual(g.edges[0]["source"], "RDAP")
        self.assertTrue(g.edges[1]["is_inferred"])

    def test_04_anti_false_positive_pipeline_and_ai_guardrail(self):
        afp = AntiFalsePositiveEngine()

        # AI cannot alter CRITICAL/HIGH findings
        crit = CandidateFinding(
            finding_id="F-1",
            organization_id=1,
            asset="vpn.example.com",
            title="CVE-2024-21762 Out-of-band Write",
            severity="CRITICAL",
            source="Nuclei",
            raw_evidence="HTTP/1.1 200 OK FortiOS SSL VPN banner match",
            detection_method="BANNER_MATCH",
            confidence=0.9,
        )
        with self.assertRaises(PermissionError):
            afp.process_finding(crit, actor="deepseek_ai", is_ai_actor=True)

        # Confirmed with second verifier
        res_conf = afp.process_finding(crit, second_verifier=lambda _c: True, actor="soc_analyst")
        self.assertEqual(res_conf["state"], FindingValidationState.CONFIRMADO.value)

        # Duplicate detection
        res_dup = afp.process_finding(crit, actor="soc_analyst")
        self.assertTrue(res_dup["deduplicated"])

        # False positive when second verifier fails
        fp_cand = CandidateFinding(
            finding_id="F-2",
            organization_id=1,
            asset="app.example.com",
            title="Exposed Admin Panel",
            severity="MEDIUM",
            source="HTTPEngine",
            raw_evidence="HTTP 403 Forbidden Cloudflare blockpage",
            detection_method="HTTP_PROBE",
            confidence=0.7,
        )
        res_fp = afp.process_finding(fp_cand, second_verifier=lambda _c: False, actor="vuln_validator")
        self.assertEqual(res_fp["state"], FindingValidationState.FALSO_POSITIVO.value)


if __name__ == "__main__":
    unittest.main()
