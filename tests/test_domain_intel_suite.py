import json
import os
import sys
import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.database import Base, get_db
from app.main import app
from app.models.domain_intel import DomainRiskTier, IndicatorInputType, ProviderCredential, ProviderQueryStatus
from app.models.organization import Organization
from app.services.domain_intel.base import ProviderResponse
from app.services.domain_intel.connectors import AlienVaultOTXConnector, VirusTotalConnector
from app.services.domain_intel.risk_and_correlation import assess_domain_risk


class TestDomainIntelSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

        db = cls.SessionLocal()
        org1 = Organization(name="Org Alpha DomainIntel")
        org2 = Organization(name="Org Beta Isolated")
        db.add_all([org1, org2])
        db.commit()
        db.refresh(org1)
        db.refresh(org2)
        cls.org1_id = org1.id
        cls.org2_id = org2.id
        db.close()

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        cls.engine.dispose()

    def test_01_live_example_com_rdap_and_dns_plus_cache_and_export(self):
        """Prueba real controlada contra RDAP/DNS para example.com (RFC 2606), caché y exportación."""
        resp = self.client.post(
            "/api/v1/domain-intel/investigate",
            json={
                "organization_id": self.org1_id,
                "target": "example.com",
                "use_cache": True,
                "enabled_providers": ["rdap_whois", "dns", "virustotal", "otx"],
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["normalized_domain"], "example.com")
        self.assertEqual(data["input_type"], "DOMAIN")
        self.assertEqual(data["status"], "COMPLETED")

        by_prov = {p["provider_name"]: p for p in data["provider_results"]}
        self.assertIn("rdap_whois", by_prov)
        self.assertIn("dns", by_prov)
        # VT y OTX sin API Key configurada deben reportar KEY_NOT_CONFIGURED explícitamente
        self.assertEqual(by_prov["virustotal"]["status"], "KEY_NOT_CONFIGURED")
        self.assertEqual(by_prov["otx"]["status"], "KEY_NOT_CONFIGURED")

        # Segunda llamada debe devolver el mismo expediente desde caché
        resp_cached = self.client.post(
            "/api/v1/domain-intel/investigate",
            json={
                "organization_id": self.org1_id,
                "target": "example.com",
                "use_cache": True,
                "enabled_providers": ["rdap_whois", "dns", "virustotal", "otx"],
            },
        )
        self.assertEqual(resp_cached.status_code, 200)
        self.assertEqual(resp_cached.json()["id"], data["id"])

        # Exportación JSON, CSV y HTML
        inv_id = data["id"]
        for fmt in ("json", "csv", "html"):
            exp = self.client.get(f"/api/v1/domain-intel/investigations/{inv_id}/export?organization_id={self.org1_id}&format={fmt}")
            self.assertEqual(exp.status_code, 200)

        # Aislamiento de organizaciones: org2 no puede leer el expediente de org1
        iso = self.client.get(f"/api/v1/domain-intel/investigations/{inv_id}?organization_id={self.org2_id}")
        self.assertEqual(iso.status_code, 404)

    def test_02_credentials_encrypted_and_never_exposed(self):
        """Las API Keys se cifran en BD y nunca se devuelven en texto plano."""
        secret = "vt_test_key_never_expose_123456"
        res = self.client.post(
            "/api/v1/domain-intel/credentials",
            json={"organization_id": self.org1_id, "provider_name": "virustotal", "api_key": secret, "is_enabled": True},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["is_configured"])
        self.assertNotIn(secret, json.dumps(body))

        lst = self.client.get(f"/api/v1/domain-intel/credentials/{self.org1_id}")
        self.assertEqual(lst.status_code, 200)
        self.assertNotIn(secret, lst.text)

        db = self.SessionLocal()
        row = db.query(ProviderCredential).filter(ProviderCredential.organization_id == self.org1_id).first()
        self.assertIsNotNone(row)
        self.assertNotEqual(row.encrypted_api_key, secret)
        db.close()

    def test_03_ssrf_and_malformed_inputs_rejected_by_api(self):
        for bad in ("127.0.0.1", "169.254.169.254", "http://10.0.0.1/admin", "not a domain!"):
            r = self.client.post(
                "/api/v1/domain-intel/investigate",
                json={"organization_id": self.org1_id, "target": bad},
            )
            self.assertEqual(r.status_code, 400, f"Expected 400 for {bad}, got {r.status_code}")

    def test_04_connector_error_states_invalid_key_timeout_ratelimit_malformed(self):
        """Verifica manejo real de errores HTTP 401, 429, 404, Timeout, ConnectError y JSON malformado."""
        import asyncio

        vt = VirusTotalConnector()
        otx = AlienVaultOTXConnector()

        async def _run():
            # 1. Invalid key (401)
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(return_value=httpx.Response(401))):
                r1 = await vt.query("example.com", IndicatorInputType.DOMAIN, "bad_key")
                self.assertEqual(r1.status, ProviderQueryStatus.INVALID_KEY)

            # 2. Rate limited (429)
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(return_value=httpx.Response(429))):
                r2 = await otx.query("example.com", IndicatorInputType.DOMAIN, "k")
                self.assertEqual(r2.status, ProviderQueryStatus.RATE_LIMITED)

            # 3. Timeout
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(side_effect=httpx.TimeoutException("timeout"))):
                r3 = await vt.query("example.com", IndicatorInputType.DOMAIN, "k")
                self.assertEqual(r3.status, ProviderQueryStatus.TIMEOUT)

            # 4. Connection Error
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(side_effect=httpx.ConnectError("down"))):
                r4 = await otx.query("example.com", IndicatorInputType.DOMAIN, "k")
                self.assertEqual(r4.status, ProviderQueryStatus.CONNECTION_ERROR)

            # 5. Malformed JSON
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(return_value=httpx.Response(200, content=b"{not-json"))):
                r5 = await vt.query("example.com", IndicatorInputType.DOMAIN, "k")
                self.assertEqual(r5.status, ProviderQueryStatus.MALFORMED_RESPONSE)

            # 6. No Data (404)
            with patch("app.services.domain_intel.connectors.safe_http_get", new=AsyncMock(return_value=httpx.Response(404))):
                r6 = await vt.query("unknown-xyz.example", IndicatorInputType.DOMAIN, "k")
                self.assertEqual(r6.status, ProviderQueryStatus.NO_DATA)

        asyncio.run(_run())

    def test_05_risk_scoring_rules_contradictory_new_domain_malicious_and_no_data(self):
        # Caso A: Resultados contradictorios (VT 0 maliciosos pero URLhaus + ThreatFox reportan malware)
        contradictory = {
            "virustotal": ProviderResponse("virustotal", ProviderQueryStatus.SUCCESS, {"stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}),
            "urlhaus": ProviderResponse("urlhaus", ProviderQueryStatus.SUCCESS, {"malicious_urls_count": 3, "threat": "malware_download"}),
            "threatfox": ProviderResponse("threatfox", ProviderQueryStatus.SUCCESS, {"matches_count": 2, "malware_printable": "AgentTesla"}),
        }
        eval_a = assess_domain_risk(contradictory)
        self.assertIn(eval_a["risk_tier"], (DomainRiskTier.HIGH, DomainRiskTier.CRITICAL))

        # Caso B: Dominio recién registrado (< 30 días) sin otras detecciones
        recent_created = (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z"
        new_dom = {
            "rdap_whois": ProviderResponse("rdap_whois", ProviderQueryStatus.SUCCESS, {"created_at": recent_created}),
            "virustotal": ProviderResponse("virustotal", ProviderQueryStatus.SUCCESS, {"stats": {"malicious": 0, "suspicious": 0, "harmless": 10}}),
        }
        eval_b = assess_domain_risk(new_dom)
        self.assertEqual(eval_b["risk_tier"], DomainRiskTier.LOW)

        # Caso C: Sin información disponible -> UNKNOWN
        no_info = {
            "rdap_whois": ProviderResponse("rdap_whois", ProviderQueryStatus.NO_DATA),
            "virustotal": ProviderResponse("virustotal", ProviderQueryStatus.KEY_NOT_CONFIGURED),
        }
        eval_c = assess_domain_risk(no_info)
        self.assertEqual(eval_c["risk_tier"], DomainRiskTier.UNKNOWN)

    def test_06_roe_seed_scope_enforcement(self):
        """Con enforce_roe_scope=True solo se permiten dominios dentro de authorized_scope."""
        out_of_scope = self.client.post(
            "/api/v1/domain-intel/investigate",
            json={
                "organization_id": self.org1_id,
                "target": "bancoagrario.gov.co",
                "enforce_roe_scope": True,
                "authorized_scope": ["fdn.com.co"],
            },
        )
        self.assertEqual(out_of_scope.status_code, 400)
        self.assertIn("RoE", out_of_scope.json()["detail"])

        in_scope = self.client.post(
            "/api/v1/domain-intel/investigate",
            json={
                "organization_id": self.org1_id,
                "target": "example.com",
                "enforce_roe_scope": True,
                "authorized_scope": ["example.com"],
                "enabled_providers": ["dns"],
            },
        )
        self.assertEqual(in_scope.status_code, 200)


if __name__ == "__main__":
    unittest.main()
