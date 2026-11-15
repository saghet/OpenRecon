import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.models.domain_intel import IndicatorInputType, ProviderQueryStatus, RelationshipConfidenceType
from app.services.domain_intel.base import DomainIntelCache, ProviderResponse
from app.services.domain_intel.risk_and_correlation import assess_domain_risk, build_domain_correlation_graph
from app.services.domain_intel.webosint_adapters import (
    CertSpotterConnector,
    DNSSecurityConnector,
    DomainExposureConnector,
    EPSSAndKEVEnricher,
    HackerTargetReverseIPConnector,
    IPASNConnector,
    ShodanInternetDBConnector,
    WhoisFreaksHistoryConnector,
    WhoisXMLReputationConnector,
)


class TestDomainIntelWebOSINT(unittest.TestCase):
    def setUp(self):
        DomainIntelCache.clear_memory()

    def test_01_shodan_internetdb_live_and_error_states(self):
        conn = ShodanInternetDBConnector()
        live = asyncio.run(conn.query("1.1.1.1"))
        self.assertIn(live.status, (ProviderQueryStatus.SUCCESS, ProviderQueryStatus.NO_DATA, ProviderQueryStatus.TIMEOUT, ProviderQueryStatus.CONNECTION_ERROR))
        if live.status == ProviderQueryStatus.SUCCESS:
            self.assertEqual(live.data["ip"], "1.1.1.1")
            cached = asyncio.run(conn.query("1.1.1.1"))
            self.assertTrue(cached.from_cache)

        # Simulated 429 & Timeout must never be cached
        DomainIntelCache.clear_memory()
        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(return_value=MagicMock(status_code=429))):
            r429 = asyncio.run(conn.query("8.8.8.8"))
        self.assertEqual(r429.status, ProviderQueryStatus.RATE_LIMITED)
        self.assertIsNone(conn.cache.get("8.8.8.8"))

        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(side_effect=httpx.TimeoutException("t"))):
            rtout = asyncio.run(conn.query("8.8.4.4"))
        self.assertEqual(rtout.status, ProviderQueryStatus.TIMEOUT)

    def test_02_epss_kev_false_positive_mitigation(self):
        enricher = EPSSAndKEVEnricher()
        enricher.cache.set("cisa_kev_map", {"CVE-2024-0001": {"vendorProject": "Acme", "product": "Web"}}, ttl_seconds=60)
        epss_resp = MagicMock(
            status_code=200,
            json=lambda: {
                "data": [
                    {"cve": "CVE-2024-0001", "epss": "0.85", "percentile": "0.99"},
                    {"cve": "CVE-2020-9999", "epss": "0.002", "percentile": "0.10"},
                ]
            },
        )
        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(return_value=epss_resp)):
            res = asyncio.run(enricher.enrich_cves(["CVE-2024-0001", "CVE-2020-9999"]))

        self.assertEqual(res.status, ProviderQueryStatus.SUCCESS)
        self.assertEqual(res.data["kev_count"], 1)
        by_cve = {c["cve"]: c for c in res.data["enriched_cves"]}
        self.assertTrue(by_cve["CVE-2024-0001"]["in_cisa_kev"])
        self.assertFalse(by_cve["CVE-2024-0001"]["likely_false_positive_or_low_priority"])
        self.assertTrue(by_cve["CVE-2020-9999"]["likely_false_positive_or_low_priority"])

    def test_03_cert_spotter_and_rate_limit(self):
        cs = CertSpotterConnector()
        mock_200 = MagicMock(
            status_code=200,
            json=lambda: [
                {
                    "id": "12345",
                    "tbs_sha256": "abc",
                    "not_before": "2026-01-01T00:00:00Z",
                    "not_after": "2026-12-31T00:00:00Z",
                    "issuer": {"name": "Let's Encrypt"},
                    "dns_names": ["api.example.com", "*.example.com"],
                }
            ],
        )
        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(return_value=mock_200)):
            res = asyncio.run(cs.query("example.com"))
        self.assertEqual(res.status, ProviderQueryStatus.SUCCESS)
        self.assertIn("api.example.com", res.data["subdomains"])

    def test_04_shared_infrastructure_anti_false_positive(self):
        ip_asn = IPASNConnector()
        mock_ip = MagicMock(
            status_code=200,
            json=lambda: {"ip": "104.16.1.1", "org": "AS13335 Cloudflare, Inc.", "country": "US", "city": "SF"},
        )
        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(return_value=mock_ip)):
            res = asyncio.run(ip_asn.query("104.16.1.1"))
        self.assertTrue(res.data["is_shared_infrastructure"])

        graph, indicators = build_domain_correlation_graph(
            "shared-tenant.example",
            {
                "dns": ProviderResponse("dns", ProviderQueryStatus.SUCCESS, {"A": ["104.16.1.1"]}),
                "ip_asn": res,
            },
        )
        asn_inds = [i for i in indicators if i["indicator_type"] == "ASN"]
        self.assertEqual(len(asn_inds), 1)
        self.assertEqual(asn_inds[0]["relationship_type"], RelationshipConfidenceType.INSUFFICIENT_EVIDENCE)

        risk = assess_domain_risk({"ip_asn": res})
        self.assertTrue(any("Infraestructura compartida" in lim for lim in risk["limitations"]))

    def test_05_dns_security_live_example_com(self):
        dns_sec = DNSSecurityConnector()
        res = asyncio.run(dns_sec.query("example.com", IndicatorInputType.DOMAIN))
        self.assertEqual(res.status, ProviderQueryStatus.SUCCESS)
        self.assertIn("dns_security_score", res.data)

    def test_06_domain_exposure_email_intel_correlation(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.close()
        try:
            c = sqlite3.connect(tmp.name)
            c.executescript(
                """
                CREATE TABLE email_intel_investigations (
                    id TEXT PRIMARY KEY, target_email TEXT, risk_level TEXT, exposure_score REAL, created_at TEXT, status TEXT
                );
                CREATE TABLE email_intel_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT, source TEXT, leak_date TEXT, exposed_data_types TEXT, verifiable_reference TEXT
                );
                INSERT INTO email_intel_investigations VALUES ('EI-1', 'admin@corp.test', 'HIGH', 70.0, '2026-11-14T00:00:00Z', 'COMPLETED');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date, exposed_data_types, verifiable_reference)
                VALUES ('EI-1', 'XposedOrNot · CorpBreach', '2025-01-01', '["Passwords"]', 'https://xposedornot.com/xposed#CorpBreach');
                """
            )
            c.commit()
            c.close()

            exp = DomainExposureConnector(sqlite_path=tmp.name)
            with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(side_effect=httpx.TimeoutException("t"))):
                res = asyncio.run(exp.query("corp.test"))
            self.assertEqual(res.status, ProviderQueryStatus.SUCCESS)
            self.assertEqual(res.data["email_intel_correlation"]["total_leaks"], 1)
            self.assertEqual(res.data["lunarcyber_status"], "TIMEOUT")
        finally:
            os.unlink(tmp.name)

    def test_07_whoisfreaks_missing_key_omitted_by_config(self):
        wf = WhoisFreaksHistoryConnector()
        with patch.dict(os.environ, {}, clear=True):
            res = asyncio.run(wf.query("example.com"))
        self.assertEqual(res.status, ProviderQueryStatus.KEY_NOT_CONFIGURED)

    def test_08_whoisxml_and_hackertarget_shared_hosting(self):
        wx = WhoisXMLReputationConnector()
        with patch.dict(os.environ, {}, clear=True):
            res_missing = asyncio.run(wx.query("example.com"))
        self.assertEqual(res_missing.status, ProviderQueryStatus.KEY_NOT_CONFIGURED)

        ht = HackerTargetReverseIPConnector()
        mock_ht = MagicMock(status_code=200, text="a.com\nb.com\nc.com\nd.com\ne.com\n")
        with patch("app.services.domain_intel.webosint_adapters.safe_http_get_with_retry", new=AsyncMock(return_value=mock_ht)):
            res_ht = asyncio.run(ht.query("93.184.216.34"))
        self.assertEqual(res_ht.status, ProviderQueryStatus.SUCCESS)
        self.assertTrue(res_ht.data["shared_hosting_warning"])
        self.assertEqual(res_ht.data["co_hosted_count"], 5)

    def test_09_end_to_end_service_persistence_and_historical_diff(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.core.database import Base
        import app.models  # noqa: F401
        from app.services.domain_intel.service import DomainIntelligenceService

        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        try:
            svc = DomainIntelligenceService(db)
            with (
                patch("app.services.domain_intel.service.enforce_anti_ssrf_and_dns_rebinding", return_value=None),
                patch.object(svc.rdap, "query", new=AsyncMock(return_value=ProviderResponse("rdap_whois", ProviderQueryStatus.SUCCESS, {"nameservers": ["ns1.lab.test"]}))),
                patch.object(svc.dns_ct, "query_dns", new=AsyncMock(return_value=ProviderResponse("dns", ProviderQueryStatus.SUCCESS, {"A": ["93.184.216.34"], "NS": ["ns1.lab.test"], "MX": []}))),
                patch.object(svc.dns_ct, "query_ct", new=AsyncMock(return_value=ProviderResponse("crt_sh", ProviderQueryStatus.NO_DATA))),
                patch.object(svc.cert_spotter, "query", new=AsyncMock(return_value=ProviderResponse("cert_spotter", ProviderQueryStatus.NO_DATA))),
                patch.object(svc.dns_security, "query", new=AsyncMock(return_value=ProviderResponse("dns_security", ProviderQueryStatus.SUCCESS, {"spf": {"present": True}, "dmarc": {"present": True}, "dns_security_score": 55}))),
                patch.object(svc.domain_exposure, "query", new=AsyncMock(return_value=ProviderResponse("domain_exposure", ProviderQueryStatus.SUCCESS, {"email_intel_correlation": {"total_leaks": 0, "investigated_emails": []}}))),
                patch.object(svc.shodan, "query", new=AsyncMock(return_value=ProviderResponse("shodan_internetdb", ProviderQueryStatus.SUCCESS, {"ip": "93.184.216.34", "ports": [443], "vulns": [], "cpes": []}))),
                patch.object(svc.ip_asn, "query", new=AsyncMock(return_value=ProviderResponse("ip_asn", ProviderQueryStatus.SUCCESS, {"ip": "93.184.216.34", "asn": "AS15133", "org": "AS15133 Edgecast", "is_shared_infrastructure": False}))),
                patch.object(svc.hackertarget, "query", new=AsyncMock(return_value=ProviderResponse("hackertarget", ProviderQueryStatus.NO_DATA))),
            ):
                inv1 = asyncio.run(svc.investigate(
                    organization_id=1,
                    target="lab-domain.com",
                    use_cache=False,
                    enabled_providers=["rdap_whois", "dns", "crt_sh", "cert_spotter", "dns_security", "domain_exposure", "shodan_internetdb", "ip_asn", "epss_kev", "hackertarget"],
                ))
                self.assertEqual(inv1.status, "COMPLETED")
                s1 = json.loads(inv1.summary_json)
                self.assertFalse(s1["historical_diff"]["has_previous"])

                # Second run with new port 8443 -> historical_diff detects change
                with patch.object(svc.shodan, "query", new=AsyncMock(return_value=ProviderResponse("shodan_internetdb", ProviderQueryStatus.SUCCESS, {"ip": "93.184.216.34", "ports": [443, 8443], "vulns": [], "cpes": []}))):
                    inv2 = asyncio.run(svc.investigate(
                        organization_id=1,
                        target="lab-domain.com",
                        use_cache=False,
                        enabled_providers=["rdap_whois", "dns", "crt_sh", "cert_spotter", "dns_security", "domain_exposure", "shodan_internetdb", "ip_asn", "epss_kev", "hackertarget"],
                    ))
                s2 = json.loads(inv2.summary_json)
                self.assertTrue(s2["historical_diff"]["has_previous"])
                self.assertTrue(any("8443" in a["value"] for a in s2["historical_diff"]["added"]))
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
