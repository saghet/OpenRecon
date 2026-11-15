"""
Master Engineering Improvement Program — Verification & Controlled Benchmark Suite.
Tests P0 security fixes, Common Finding Contract & Deduplication, STIX 2.1 wiring,
DNSEngine Wildcard Filtering, NucleiEngine v3 JSONL, DRPEngine Multi-Signal,
CISA Vulnrichment SSVC parsing, and RiskEngine missing-data handling.
"""

import json
import os
import sys
import time
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services.cti.vuln_intel_enrichment import VulnIntelEnrichmentService
from app.services.email_intel.paste_searcher import PasteSearcher
from app.services.email_intel.zehef_adapter import ZehefAdapter
from app.services.engines.dns_engine import DNSEngine
from app.services.engines.drp_engine import DRPEngine
from app.services.engines.nuclei_engine import EXCLUDED_DANGEROUS_TAGS, NucleiEngine
from app.services.risk.risk_engine import IntelligentRiskEngine
from app.services.validation.anti_false_positive import AntiFalsePositiveEngine, CandidateFinding
from app.services.validation.finding_contract import GlobalFindingDeduplicator, NormalizedFinding


class TestMasterImprovementProgram(unittest.IsolatedAsyncioTestCase):
    def test_01_all_api_v1_routers_enforce_token_when_configured(self):
        client = TestClient(app)
        with patch.object(settings, "OPENRECON_API_TOKEN", "test-master-token-123"):
            for path in ("/api/v1/organizations/", "/api/v1/opencti/health", "/api/v1/cti/misp/health"):
                r_unauth = client.get(path)
                self.assertEqual(r_unauth.status_code, 401, f"Expected 401 on {path}")

            r_auth = client.get(
                "/api/v1/organizations/",
                headers={"X-OpenRecon-Token": "test-master-token-123"},
            )
            self.assertNotEqual(r_auth.status_code, 401)

    async def test_02_paste_searcher_sanitizes_secrets_in_preview(self):
        searcher = PasteSearcher(ZehefAdapter())
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = "leaked token ghp_1234567890abcdef1234567890abcdef1234 and sk-abcdefghijklmnopqrstuvwxyz1234"
        fake_resp.json.return_value = [{"id": "abc123", "time": "2026-11-15"}]

        fake_client = AsyncMock()
        fake_client.get = AsyncMock(return_value=fake_resp)
        fake_client.__aenter__ = AsyncMock(return_value=fake_client)
        fake_client.__aexit__ = AsyncMock(return_value=False)

        with patch.object(searcher.adapter, "get_client", return_value=fake_client):
            findings, evidences = await searcher.search_pastes("analyst@example.com")

        self.assertGreaterEqual(len(evidences), 1)
        preview = evidences[0]["raw_content_preview"]
        self.assertNotIn("ghp_1234567890abcdef1234567890abcdef1234", preview)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz1234", preview)
        self.assertIn("[REDACTED", preview)

    def test_03_global_deduplicator_preserves_independent_evidences(self):
        dedup = GlobalFindingDeduplicator()
        f1 = NormalizedFinding(
            organization_id=1,
            entity_type="subdomain",
            entity_value="api.example.com",
            finding_type="vulnerability",
            source="nuclei",
            severity="HIGH",
            confidence=0.80,
            evidence="HTTP 200 matched template CVE-2024-9999",
            canonical_key="CVE-2024-9999",
        )
        f2 = NormalizedFinding(
            organization_id=1,
            entity_type="subdomain",
            entity_value="API.EXAMPLE.COM ",
            finding_type="vulnerability",
            source="shodan_internetdb",
            severity="HIGH",
            confidence=0.90,
            evidence="Banner confirms vulnerable service version for CVE-2024-9999",
            canonical_key="CVE-2024-9999",
        )
        r1 = dedup.ingest(f1)
        r2 = dedup.ingest(f2)

        self.assertFalse(r1["deduplicated"])
        self.assertTrue(r2["deduplicated"])
        self.assertEqual(r2["corroboration_count"], 2)
        self.assertEqual(len(dedup.all_findings()), 1)
        merged = dedup.all_findings()[0]
        self.assertEqual(set(merged.sources_seen), {"nuclei", "shodan_internetdb"})
        self.assertEqual(len(merged.evidence_refs), 2)
        self.assertEqual(merged.confidence, 0.90)

    def test_04_stix21_valid_uuid_and_opencti_endpoints(self):
        client = TestClient(app)
        resp = client.post(
            "/api/v1/opencti/export-stix",
            json={
                "tlp": "TLP:GREEN",
                "indicators": [
                    {"type": "domain-name", "value": "malicious.example", "source": "otx", "confidence": 85},
                    {"type": "domain-name", "value": "malicious.example", "source": "otx", "confidence": 85},
                ],
            },
        )
        self.assertEqual(resp.status_code, 200)
        bundle = resp.json()
        identity = bundle["objects"][0]
        self.assertTrue(identity["id"].startswith("identity--"))
        uuid.UUID(identity["id"].split("--", 1)[1])  # Must be a valid RFC 4122 UUID

        imp = client.post("/api/v1/opencti/import-stix", json=bundle)
        self.assertEqual(imp.status_code, 200)
        self.assertEqual(imp.json()["imported_count"], 1)

    async def test_05_dns_engine_wildcard_elimination_and_provenance(self):
        engine = DNSEngine()
        engine.has_subfinder = True
        engine.has_amass = False

        async def mock_subfinder(_domain):
            return {"api.example.com": {"subfinder:crtsh"}, "wc-noise.example.com": {"subfinder:brute"}}

        async def mock_crtsh(_domain):
            return {"api.example.com": {"crt.sh"}}

        def mock_resolve_all(host):
            if host.startswith("openrecon-wc-") or host == "wc-noise.example.com":
                return {"198.51.100.99"}  # Wildcard IP
            if host in ("api.example.com", "example.com"):
                return {"93.184.216.34"}
            return set()

        with (
            patch.object(engine, "_run_subfinder", side_effect=mock_subfinder),
            patch.object(engine, "_query_crtsh", side_effect=mock_crtsh),
            patch.object(engine, "_resolve_all_a", side_effect=mock_resolve_all),
        ):
            results = await engine.discover_subdomains("example.com")

        hosts = {r["subdomain"]: r for r in results}
        self.assertNotIn("wc-noise.example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertEqual(hosts["api.example.com"]["discovery_source"], "crt.sh,subfinder:crtsh")

    def test_06_nuclei_jsonl_evidence_and_version_indication(self):
        self.assertIn("dos", EXCLUDED_DANGEROUS_TAGS)
        self.assertIn("fuzz", EXCLUDED_DANGEROUS_TAGS)
        sample_jsonl = "\n".join([
            json.dumps({
                "template-id": "apache-detect",
                "matched-at": "https://example.com",
                "matcher-name": "version",
                "info": {"name": "Apache Version Detect", "severity": "info", "tags": ["tech", "detect"]},
            }),
            json.dumps({
                "template-id": "CVE-2024-12345",
                "matched-at": "https://example.com/admin",
                "matcher-name": "body-match",
                "curl-command": "curl -H 'Authorization: Bearer secret123456789012345' https://example.com/admin",
                "info": {
                    "name": "Exposed Admin Auth Bypass",
                    "severity": "high",
                    "tags": ["cve", "exposure"],
                    "classification": {"cve-id": ["CVE-2024-12345"], "cvss-score": 8.2},
                },
            }),
        ])
        parsed = NucleiEngine.parse_jsonl_output(sample_jsonl)
        self.assertEqual(len(parsed), 2)
        self.assertTrue(parsed[0]["is_version_only_indication"])
        self.assertFalse(parsed[1]["is_version_only_indication"])
        self.assertNotIn("secret123456789012345", parsed[1]["evidence"])

    def test_07_drp_idn_and_multi_signal_phishing_guard(self):
        drp = DRPEngine(max_candidates=60)
        perms = drp.generate_permutations("example.com")
        self.assertGreater(len(perms), 25)
        self.assertTrue(any(p.startswith("xn--") for p in perms))

        # Domain similarity alone (no HTTP match) must NOT classify as phishing
        low_signal = DRPEngine.assess_phishing_confidence("Example Corp Login", None, True, False)
        self.assertNotEqual(low_signal["classification"], "POTENTIAL_PHISHING_MULTI_SIGNAL")

        # Multi-signal (A + MX + HTTP title similarity) elevates confidence
        high_signal = DRPEngine.assess_phishing_confidence("Example Corp Login", "Example Corp Login Portal", True, True)
        self.assertEqual(high_signal["classification"], "POTENTIAL_PHISHING_MULTI_SIGNAL")
        self.assertEqual(high_signal["severity"], "HIGH")

    def test_08_vulnrichment_ssvc_and_risk_missing_data_transparency(self):
        cve_json = {
            "containers": {
                "adp": [{
                    "metrics": [
                        {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}, {"Automatable": "yes"}]}}},
                        {"cvssV3_1": {"baseScore": 9.8}},
                    ],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}]}],
                }]
            }
        }
        adp = VulnIntelEnrichmentService.parse_vulnrichment_adp(cve_json)
        self.assertEqual(adp["ssvc"]["Exploitation"], "active")
        self.assertEqual(adp["cwe_ids"], ["CWE-78"])
        self.assertEqual(adp["adp_cvss_score"], 9.8)

        risk_engine = IntelligentRiskEngine()
        res_missing = risk_engine.calculate_vulnerability_risk({"severity": "HIGH", "validation_state": "PROBABLE"})
        self.assertIn("epss_score", res_missing["missing_signals"])
        self.assertIn("cisa_kev", res_missing["missing_signals"])
        self.assertLess(res_missing["data_completeness"], 1.0)

        res_full = risk_engine.calculate_vulnerability_risk(
            {"cvss_score": 9.8, "epss_score": 0.92, "cisa_kev": True, "ssvc": adp["ssvc"], "validation_state": "CONFIRMADA"},
            asset={"is_live": True, "criticality": "CRITICAL"},
        )
        self.assertEqual(res_full["data_completeness"], 1.0)
        self.assertEqual(res_full["tier"], "CRÍTICO")

    def test_09_controlled_benchmark_dedup_and_afp_throughput(self):
        dedup = GlobalFindingDeduplicator()
        afp = AntiFalsePositiveEngine()
        t0 = time.perf_counter()
        for i in range(200):
            # 100 unique findings x 2 sources = 50% duplicate rate
            idx = i % 100
            src = "nuclei" if i < 100 else "httpx"
            nf = NormalizedFinding(
                organization_id=1,
                entity_type="subdomain",
                entity_value=f"sub{idx}.example.com",
                finding_type="exposure",
                source=src,
                severity="MEDIUM",
                evidence=f"Observed header exposure on sub{idx}.example.com via {src}",
                canonical_key="missing-csp",
            )
            dedup.ingest(nf)
            afp.process_finding(CandidateFinding(
                finding_id=nf.finding_id,
                organization_id=1,
                asset=nf.entity_value,
                title="missing-csp",
                severity="MEDIUM",
                source=src,
                raw_evidence=nf.evidence,
                detection_method="exposure",
                confidence=0.85,
                second_check_passed=True,
            ))
        elapsed = time.perf_counter() - t0
        self.assertEqual(len(dedup.all_findings()), 100)
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
