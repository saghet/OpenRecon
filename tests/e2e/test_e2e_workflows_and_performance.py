"""
Phase 5 E2E & Performance/Concurrency Tests for OpenRecon 3.0:
- End-to-End API workflow: Org -> Seed -> RoE Validation -> Kill-Switch Lock -> Reset -> Metrics
- Concurrency & High-Volume Anti-False-Positive + HTTP burst test
"""

import concurrent.futures
import os
import sys
import time
import unittest
import uuid

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.core.security_guard import SecurityGovernanceGuard
from app.main import app
from app.services.validation import AntiFalsePositiveEngine, CandidateFinding


class TestE2EWorkflowsAndPerformance(unittest.TestCase):
    def setUp(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="e2e_setup")
        self.client = TestClient(app)

    def tearDown(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="e2e_teardown")

    def test_01_e2e_org_seed_roe_killswitch_and_metrics_flow(self):
        org_name = f"E2E-Org-{uuid.uuid4().hex[:8]}"
        r_org = self.client.post("/api/v1/organizations/", json={"name": org_name, "description": "E2E test"})
        self.assertEqual(r_org.status_code, 201, r_org.text)
        org_id = r_org.json()["id"]

        r_seed = self.client.post(
            f"/api/v1/organizations/{org_id}/seeds",
            json={"seed_type": "DOMAIN", "value": "example.com"},
        )
        self.assertEqual(r_seed.status_code, 201, r_seed.text)

        # Validate target against RoE
        r_val = self.client.post(
            "/api/v1/security/validate-target",
            json={"target": "sub.example.com", "authorized_scope": ["example.com"]},
        )
        self.assertEqual(r_val.status_code, 200)
        self.assertTrue(r_val.json()["safe"])

        # Trigger Kill-Switch -> scan launch must be rejected with 423 Locked
        r_ks = self.client.post(
            "/api/v1/security/kill-switch/trigger",
            json={"reason": "E2E emergency test"},
        )
        self.assertEqual(r_ks.status_code, 200)
        self.assertTrue(r_ks.json()["details"]["active"])

        r_scan_blocked = self.client.post(
            "/api/v1/scans/",
            json={"organization_id": org_id, "scan_type": "EASM_FULL"},
        )
        self.assertEqual(r_scan_blocked.status_code, 423)

        # Reset Kill-Switch
        r_reset = self.client.post("/api/v1/security/kill-switch/reset")
        self.assertEqual(r_reset.status_code, 200)
        self.assertFalse(r_reset.json()["details"]["active"])

        # Verify observability metrics recorded the flow
        r_metrics = self.client.get("/metrics")
        self.assertEqual(r_metrics.status_code, 200)
        self.assertIn("openrecon_http_requests_total", r_metrics.text)

    def test_02_performance_afp_high_volume_and_concurrent_api(self):
        afp = AntiFalsePositiveEngine()
        t0 = time.monotonic()
        for i in range(200):
            cand = CandidateFinding(
                finding_id=f"PERF-{i}",
                organization_id=1,
                asset=f"host-{i}.example.com",
                title="Missing HSTS Header",
                severity="LOW",
                source="WebSecurityAnalyzer",
                raw_evidence=f"HTTP/1.1 200 OK host-{i}.example.com missing Strict-Transport-Security",
                detection_method="HEADER_CHECK",
                confidence=0.85,
            )
            res = afp.process_finding(cand, second_verifier=lambda _c: True, actor="perf_runner")
            self.assertEqual(res["state"], "CONFIRMADO")
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 2.0, f"200 findings took too long: {elapsed:.2f}s")

        # Concurrent API requests
        def _ping(_idx: int) -> int:
            return self.client.get("/api/v1/security/kill-switch").status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            codes = list(pool.map(_ping, range(24)))
        self.assertTrue(all(c == 200 for c in codes))


if __name__ == "__main__":
    unittest.main()
