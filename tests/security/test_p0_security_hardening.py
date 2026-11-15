"""
P0 Security Hardening Test Suite for OpenRecon 3.0.
Verifies:
1. Mandatory TLS verification & MITM/invalid certificate rejection.
2. Centralized evidence sanitization & secret redaction in logs/persistence.
3. RoE enforcement, Anti-SSRF, DNS Rebinding & Redirect protection.
4. Distributed Kill-Switch persistence across workers/restarts.
5. API token authentication & strict CORS configuration.
"""

import logging
import os
import re
import socket
import ssl
import sys
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.core.config import settings
from app.core.evidence_sanitizer import EvidenceSanitizer, SecretRedactingFilter
from app.core.security_guard import SecurityGovernanceGuard
from app.core.tls_config import create_secure_ssl_context, get_httpx_verify, probe_tls_certificate
from app.main import app
from app.services.cti.misp_client import MISPClient
from app.services.cti.opencti_client import OpenCTIClient


class TestP0SecurityHardening(unittest.TestCase):
    def setUp(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test_setup")

    def tearDown(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test_teardown")

    # --- 1. TLS Hardening ---
    def test_01_tls_context_enforces_strict_verification(self):
        ctx = create_secure_ssl_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)

        httpx_ctx = get_httpx_verify()
        self.assertIsInstance(httpx_ctx, ssl.SSLContext)
        self.assertTrue(httpx_ctx.check_hostname)
        self.assertEqual(httpx_ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_02_connectors_forbid_disabling_tls(self):
        with self.assertRaises(ValueError):
            OpenCTIClient(base_url="https://opencti.example.com", verify_ssl=False)
        with self.assertRaises(ValueError):
            MISPClient(base_url="https://misp.example.com", verify_ssl=False)

    def test_03_tls_probe_rejects_untrusted_or_mitm_cert(self):
        with patch("app.core.tls_config.socket.create_connection") as mock_conn:
            mock_sock = mock_conn.return_value.__enter__.return_value
            with patch.object(
                ssl.SSLContext,
                "wrap_socket",
                side_effect=ssl.SSLCertVerificationError(1, "certificate verify failed: self-signed certificate"),
            ):
                res = probe_tls_certificate("mitm.example.com", 443)
                self.assertFalse(res["tls_valid"])
                self.assertIn("verification failed", res["error"].lower())

    def test_04_no_insecure_tls_bypasses_in_codebase(self):
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        scan_dirs = [
            os.path.join(root_dir, "backend", "app"),
            os.path.join(root_dir, "backend", "tools"),
            os.path.join(root_dir, "web_dashboard"),
        ]
        pattern = re.compile(
            r"verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*[,=][>=]?\s*false|CURLOPT_SSL_VERIFYHOST\s*[,=][>=]?\s*(?:false|0)|CERT_NONE|check_hostname\s*=\s*False"
        )
        violations = []
        for sdir in scan_dirs:
            for base, _, files in os.walk(sdir):
                for fname in files:
                    if not fname.endswith((".py", ".php")):
                        continue
                    fpath = os.path.join(base, fname)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, 1):
                            if pattern.search(line):
                                violations.append(f"{fpath}:{lineno}")
        self.assertEqual(violations, [], f"Found insecure TLS bypasses: {violations}")

    # --- 2. Sensitive Info & Secret Redaction ---
    def test_05_evidence_sanitizer_redacts_secrets_and_xss(self):
        dirty = (
            "<script>alert(1)</script>"
            "password=SuperSecret123! "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaa.bbbb "
            "api_key=sk-1234567890abcdef123456 "
            "ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "AKIAIOSFODNN7EXAMPLE"
        )
        cleaned = EvidenceSanitizer.sanitize_raw_content(dirty)
        self.assertNotIn("<script>", cleaned)
        self.assertNotIn("SuperSecret123", cleaned)
        self.assertNotIn("eyJhbGciOi", cleaned)
        self.assertNotIn("sk-1234567890abcdef", cleaned)
        self.assertNotIn("ghp_abcdefgh", cleaned)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)
        self.assertIn("[REDACTED", cleaned)

        payload = {"user": "alice", "password": "plaintext_password", "nested": {"token": "abc"}}
        sanitized_payload = EvidenceSanitizer.sanitize_evidence_payload(payload)
        self.assertEqual(sanitized_payload["password"], "[REDACTED]")
        self.assertEqual(sanitized_payload["nested"]["token"], "[REDACTED]")

    def test_06_log_filter_redacts_secrets(self):
        flt = SecretRedactingFilter()
        rec = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Connecting with api_key=sk-secretkey123456789012345 and password=MyPass99",
            args=(),
            exc_info=None,
        )
        flt.filter(rec)
        self.assertNotIn("sk-secretkey123456789012345", rec.msg)
        self.assertNotIn("MyPass99", rec.msg)

    # --- 3. RoE, Anti-SSRF, DNS Rebinding & Redirects ---
    def test_07_ssrf_and_dns_rebinding_and_redirects_blocked(self):
        for bad in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::ffff:127.0.0.1", "internal.corp"]:
            res = SecurityGovernanceGuard.validate_target_safety(bad)
            self.assertFalse(res["safe"], f"Expected {bad} to be blocked")

        # Simulated DNS rebinding to loopback
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        with patch("app.core.security_guard.socket.getaddrinfo", return_value=fake_addrinfo):
            res = SecurityGovernanceGuard.validate_target_safety("rebind.attacker.com", resolve_dns=True)
            self.assertFalse(res["safe"])
            self.assertIn("DNS Rebinding", res["reason"])

        # Redirect to metadata IP
        redir = SecurityGovernanceGuard.validate_redirect_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(redir["safe"])

        # RoE out of scope
        roe = SecurityGovernanceGuard.validate_target_safety("evil.com", authorized_scope=["example.com"])
        self.assertFalse(roe["safe"])
        self.assertIn("RoE Violation", roe["reason"])

    # --- 4. Distributed Kill-Switch ---
    def test_08_kill_switch_persists_across_worker_restart_and_cancels_tasks(self):
        SecurityGovernanceGuard.register_active_task("TASK-SIM-1", "email_intel", "user@example.com", worker_id="w1")
        SecurityGovernanceGuard.trigger_emergency_kill_switch(reason="P0 Test Abort", triggered_by="secops_lead")

        # Simulate process/worker restart by wiping in-memory class flags
        SecurityGovernanceGuard._EMERGENCY_KILL_SWITCH = False
        SecurityGovernanceGuard._KILL_SWITCH_REASON = None

        state = SecurityGovernanceGuard.is_kill_switch_active()
        self.assertTrue(state["active"])
        self.assertEqual(state["triggered_by"], "secops_lead")
        self.assertEqual(state["reason"], "P0 Test Abort")

        ctrl = SecurityGovernanceGuard.get_task_control_state("TASK-SIM-1")
        self.assertTrue(ctrl["kill_switch"])
        self.assertTrue(ctrl["cancel_requested"])

        SecurityGovernanceGuard.complete_active_task("TASK-SIM-1", "ABORTED_BY_KILL_SWITCH")
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="secops_lead")
        self.assertFalse(SecurityGovernanceGuard.is_kill_switch_active()["active"])

    # --- 5. Auth & CORS ---
    def test_09_api_token_auth_and_strict_cors(self):
        client = TestClient(app)
        with patch.object(settings, "OPENRECON_API_TOKEN", "top-secret-token-xyz"):
            r_unauth = client.post("/api/v1/security/kill-switch/trigger", json={"reason": "test"})
            self.assertEqual(r_unauth.status_code, 401)

            r_bad = client.post(
                "/api/v1/security/kill-switch/trigger",
                json={"reason": "test"},
                headers={"X-OpenRecon-Token": "wrong"},
            )
            self.assertEqual(r_bad.status_code, 401)

            r_ok = client.post(
                "/api/v1/security/kill-switch/trigger",
                json={"reason": "authorized test"},
                headers={"Authorization": "Bearer top-secret-token-xyz"},
            )
            self.assertEqual(r_ok.status_code, 200)
            SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test_cleanup")

        # CORS must not be wildcard with credentials
        for m in app.user_middleware:
            if m.cls.__name__ == "CORSMiddleware":
                self.assertNotEqual(m.kwargs.get("allow_origins"), ["*"])
                self.assertFalse(m.kwargs.get("allow_credentials", True))


if __name__ == "__main__":
    unittest.main()
