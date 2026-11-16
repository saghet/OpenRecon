"""
Comprehensive Unit, Integration & E2E Tests for Selective WebCopilot Integration
into OpenRecon 3.0 (WebCopilotAdapter, URLNormalizer, NucleiEngine enrichment,
FastAPI /api/v1/web-recon endpoints, RoE, Anti-FP, Deduplication, and Kill-Switch).
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure backend is on sys.path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security_guard import SecurityGovernanceGuard
from app.main import app
from app.models.asset import Asset, AssetType
from app.models.evidence import EvidenceRecord, FindingValidationState
from app.models.exposure import Vulnerability
from app.models.organization import Organization, Seed, SeedType
from app.models.web_recon import DiscoveredEndpoint, WebOrgPolicy, WebScanExecution
from app.services.engines.nuclei_engine import NucleiEngine
from app.services.web_security.url_normalizer import (
    classify_gf_categories,
    deduplicate_urls,
    is_valid_hostname,
    normalize_url,
)
from app.services.web_security.webcopilot_adapter import WebCopilotAdapter, WebReconOptions


class TestWebCopilotIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls._tmp_db.close()
        cls.engine = create_engine(
            f"sqlite:///{cls._tmp_db.name}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        if os.path.exists(cls._tmp_db.name):
            os.unlink(cls._tmp_db.name)

    def setUp(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test_setup")
        self.db = self.SessionLocal()
        self.org = Organization(name=f"TestOrg-{id(self)}")
        self.db.add(self.org)
        self.db.commit()
        self.db.refresh(self.org)

        self.seed = Seed(
            organization_id=self.org.id,
            seed_type=SeedType.DOMAIN,
            value="example.com",
            is_active=1,
        )
        self.db.add(self.seed)
        self.db.commit()

        self.asset = Asset(
            organization_id=self.org.id,
            seed_id=self.seed.id,
            asset_type=AssetType.SUBDOMAIN,
            value="app.example.com",
            ip_address="93.184.216.34",
            is_live=True,
            discovery_source="subfinder",
        )
        self.db.add(self.asset)
        self.db.commit()
        self.db.refresh(self.asset)

    def tearDown(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test_teardown")
        self.db.close()

    def test_01_url_normalizer_dedup_gf_and_command_injection_rejection(self):
        # Command injection payloads must be rejected
        self.assertIsNone(normalize_url("https://app.example.com/search?q=1;id"))
        self.assertIsNone(normalize_url("https://app.example.com/search?q=$(whoami)"))
        self.assertIsNone(normalize_url("https://app.example.com/`id`"))
        self.assertFalse(is_valid_hostname("app.example.com;cat /etc/passwd"))

        # Static assets dropped, equivalent parameterized URLs deduplicated
        raw = [
            ("https://app.example.com/static/app.css", "gau"),
            ("https://app.example.com/search?q=hello&page=1", "gau"),
            ("https://app.example.com:443/search?page=2&q=world#frag", "waybackurls"),
            ("https://app.example.com/login?next=https://app.example.com/home", "waymore"),
        ]
        deduped = deduplicate_urls(raw, drop_static=True)
        self.assertEqual(len(deduped), 2)

        search_entry = next(v for v in deduped.values() if v["normalized"].path == "/search")
        self.assertEqual(sorted(search_entry["sources"]), ["gau", "waybackurls"])
        self.assertEqual(search_entry["normalized"].query_params, ["page", "q"])
        self.assertIn("xss", search_entry["normalized"].gf_categories)
        self.assertIn("sqli", search_entry["normalized"].gf_categories)

        cats = classify_gf_categories("/download", ["file", "redirect_uri"])
        self.assertIn("lfi", cats)
        self.assertIn("redirect", cats)

    def test_02_adapter_does_not_reenumerate_subdomains_and_enforces_roe(self):
        adapter = WebCopilotAdapter(db=self.db)
        # Mock historical discovery returning one in-scope URL, one out-of-scope URL, and one excluded subdomain
        adapter._discover_historical_urls_for_host = AsyncMock(
            return_value=[
                ("https://app.example.com/items?id=42&q=test", "gau"),
                ("https://evil-thirdparty.org/admin?id=1", "gau"),
                ("https://excluded.example.com/secret?id=1", "waybackurls"),
            ]
        )

        with patch.object(
            SecurityGovernanceGuard,
            "validate_target_safety",
            side_effect=lambda target, authorized_scope=None, resolve_dns=True: {
                "safe": "example.com" in target and "evil-thirdparty.org" not in target,
                "reason": "scope_check",
            },
        ):
            opts = WebReconOptions(
                enable_historical_discovery=True,
                enable_param_analysis=False,
                enable_nuclei_enrichment=False,
                excluded_domains=["excluded.example.com"],
            )
            res = asyncio.run(
                adapter.run_for_assets(
                    organization_id=self.org.id,
                    assets=[self.asset],
                    authorized_scope=["example.com"],
                    options=opts,
                )
            )

        self.assertEqual(res["endpoints_discovered"], 1)
        eps = self.db.query(DiscoveredEndpoint).filter(DiscoveredEndpoint.organization_id == self.org.id).all()
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0].asset_id, self.asset.id)
        self.assertEqual(eps[0].sources, ["gau"])
        self.assertEqual(eps[0].query_params, ["id", "q"])

    def test_03_anti_fp_deduplication_and_evidence_custody(self):
        adapter = WebCopilotAdapter(db=self.db)
        # 1. KXSS reflection -> PROBABLE (not confirmed)
        r1 = adapter._ingest_normalized_finding(
            organization_id=self.org.id,
            asset=self.asset,
            investigation_id="INV-100",
            title="Reflected XSS on 'q'",
            category="xss",
            severity="MEDIUM",
            source="kxss",
            tool_version="kxss",
            affected_url="https://app.example.com/search",
            affected_parameter="q",
            raw_evidence="URL: https://app.example.com/search?q=1 Param: q Unfiltered: < >",
            detection_method="kxss_reflection",
            confidence=0.65,
            second_check_passed=None,
        )
        self.assertIsNotNone(r1)
        self.assertEqual(r1["afp"]["state"], FindingValidationState.PROBABLE.value)

        # 2. Duplicate finding from another source -> deduplicated, preserves evidence
        r2 = adapter._ingest_normalized_finding(
            organization_id=self.org.id,
            asset=self.asset,
            investigation_id="INV-100",
            title="Reflected XSS on 'q'",
            category="xss",
            severity="MEDIUM",
            source="dalfox",
            tool_version="dalfox-v2",
            affected_url="https://app.example.com/search",
            affected_parameter="q",
            raw_evidence="Dalfox reflected PoC on q=<svg/onload=alert(1)>",
            detection_method="dalfox_active_poc",
            confidence=0.92,
            second_check_passed=True,
        )
        self.assertIsNone(r2)  # Deduplicated!

        # 3. Distinct confirmed finding -> CONFIRMADO + EvidenceRecord + CWE/OWASP
        r3 = adapter._ingest_normalized_finding(
            organization_id=self.org.id,
            asset=self.asset,
            investigation_id="INV-100",
            title="Open Redirect on parameter 'next'",
            category="redirect",
            severity="MEDIUM",
            source="openredirex_safe",
            tool_version="openrecon-3.0",
            affected_url="https://app.example.com/login",
            affected_parameter="next",
            raw_evidence="HTTP 302 Location: https://example.com/openrecon-redirect-canary",
            detection_method="http_redirect_header_check",
            confidence=0.90,
            second_check_passed=True,
        )
        self.assertIsNotNone(r3)
        self.assertEqual(r3["afp"]["state"], FindingValidationState.CONFIRMADO.value)
        self.assertEqual(r3["finding"]["normalized_data"]["cwe_id"], "CWE-601")
        self.assertEqual(r3["finding"]["normalized_data"]["owasp_category"], "A01:2021-Broken Access Control")

        vulns = self.db.query(Vulnerability).filter(Vulnerability.asset_id == self.asset.id).all()
        self.assertEqual(len(vulns), 2)
        ev_records = self.db.query(EvidenceRecord).filter(EvidenceRecord.organization_id == self.org.id).all()
        self.assertEqual(len(ev_records), 2)

    def test_04_safe_by_default_sqlmap_interactsh_and_nuclei_intrusive(self):
        adapter = WebCopilotAdapter(db=self.db)
        policy = adapter._get_org_policy(self.org.id)
        self.assertFalse(policy.sqlmap_enabled)
        self.assertFalse(policy.interactsh_enabled)
        self.assertFalse(policy.nuclei_allow_intrusive)

        # Even if options request sqlmap, org policy blocks it when disabled
        adapter.binaries["sqlmap"] = "/usr/bin/sqlmap"
        adapter._run_subprocess_lines = AsyncMock()
        ep = DiscoveredEndpoint(
            organization_id=self.org.id,
            asset_id=self.asset.id,
            url="https://app.example.com/item?id=1",
            url_hash="h1",
            canonical_key="c1",
            scheme="https",
            host="app.example.com",
            path="/item",
            query_params=["id"],
            has_params=True,
            gf_categories=["sqli"],
            sources=["gau"],
        )
        res = asyncio.run(
            adapter._run_controlled_sqlmap(
                [ep],
                self.asset,
                self.org.id,
                None,
                None,
                policy,
                WebReconOptions(allow_controlled_sqlmap=True),
            )
        )
        self.assertEqual(res, [])
        adapter._run_subprocess_lines.assert_not_called()

        # NucleiEngine safe-by-default excludes intrusive even if requested while SAFE_MODE=True
        ne = NucleiEngine()
        ne.has_nuclei = True
        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            asyncio.run(ne.scan_targets(["https://app.example.com/item?id=1"], allow_intrusive=True))
            called_args = mock_exec.call_args[0]
            etags_idx = list(called_args).index("-etags") + 1
            self.assertIn("intrusive", called_args[etags_idx])

    def test_05_tool_failure_isolation_and_kill_switch(self):
        adapter = WebCopilotAdapter(db=self.db)
        adapter.binaries["gau"] = "/usr/bin/gau"
        adapter.binaries["waybackurls"] = "/usr/bin/waybackurls"

        async def _flaky_exec(cmd, stdin_data=None, timeout=45.0):
            if "gau" in cmd[0]:
                raise RuntimeError("gau crashed")
            return (0, "https://app.example.com/api?user=1\n", "")

        adapter._run_subprocess_lines = _flaky_exec
        urls = asyncio.run(
            adapter._discover_historical_urls_for_host(
                "app.example.com", self.org.id, None, "INV-FAIL", 10.0
            )
        )
        # waybackurls still succeeded despite gau crash
        self.assertEqual(len(urls), 1)
        execs = self.db.query(WebScanExecution).filter(WebScanExecution.organization_id == self.org.id).all()
        statuses = {e.tool_name: e.status for e in execs}
        self.assertEqual(statuses["gau"], "FAILED")
        self.assertEqual(statuses["waybackurls"], "COMPLETED")

        # Kill-Switch halts execution
        SecurityGovernanceGuard.trigger_emergency_kill_switch(reason="Test WebRecon Abort", triggered_by="qa")
        self.assertTrue(adapter._is_killed())

    def test_06_fastapi_web_recon_endpoints_and_kill_switch_lock(self):
        def _override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        orig_token = settings.OPENRECON_API_TOKEN
        settings.OPENRECON_API_TOKEN = "test-secret-token"
        try:
            client = TestClient(app)
            headers = {"X-OpenRecon-Token": "test-secret-token"}

            # Unauthenticated request rejected
            r_unauth = client.get(f"/api/v1/web-recon/summary/{self.org.id}")
            self.assertEqual(r_unauth.status_code, 401)

            # Policy defaults are safe-by-default
            r_pol = client.get(f"/api/v1/web-recon/policy/{self.org.id}", headers=headers)
            self.assertEqual(r_pol.status_code, 200)
            self.assertFalse(r_pol.json()["sqlmap_enabled"])
            self.assertFalse(r_pol.json()["interactsh_enabled"])

            # Update policy (token is never returned in plaintext)
            r_put = client.put(
                f"/api/v1/web-recon/policy/{self.org.id}",
                headers=headers,
                json={"interactsh_enabled": True, "interactsh_token": "super-secret-oast-token"},
            )
            self.assertEqual(r_put.status_code, 200)
            self.assertTrue(r_put.json()["has_interactsh_token"])
            self.assertNotIn("super-secret-oast-token", r_put.text)

            # Summary & endpoints queries work
            r_sum = client.get(f"/api/v1/web-recon/summary/{self.org.id}", headers=headers)
            self.assertEqual(r_sum.status_code, 200)
            self.assertIn("confirmed_vs_potential", r_sum.json())

            r_eps = client.get(f"/api/v1/web-recon/endpoints/{self.org.id}", headers=headers)
            self.assertEqual(r_eps.status_code, 200)

            # Kill-switch blocks new scan with HTTP 423
            SecurityGovernanceGuard.trigger_emergency_kill_switch(reason="API Lock Test", triggered_by="qa")
            r_locked = client.post(
                "/api/v1/web-recon/scan",
                headers=headers,
                json={"organization_id": self.org.id},
            )
            self.assertEqual(r_locked.status_code, 423)
        finally:
            settings.OPENRECON_API_TOKEN = orig_token
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
