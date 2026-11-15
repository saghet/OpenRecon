"""
Phase 3 Intelligence Tests:
- Email Intelligence confidence classification (syntax, MX, confirmed vs inconclusive, breach)
- GitHub Secret Intelligence (pattern detection, REVOKED vs POTENTIAL, secret redaction, zero active usage)
- Web Security Intelligence (HSTS, CSP, X-Frame-Options, Cookies, TLS posture, SSRF blocking)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.services.email_intel.confidence_classifier import (
    EmailVerificationClassifier,
    EmailVerificationTier,
)
from app.services.github_intel import GitHubIntelConnector, SecretLifecycleState
from app.services.web_security import WebSecurityAnalyzer


class TestPhase3Intelligence(unittest.TestCase):
    def test_01_email_verification_classifier_distinguishes_ambiguous_from_confirmed(self):
        # Ambiguous (429/403) must NEVER confirm account existence
        res_ambig = EmailVerificationClassifier.classify(
            email="alice@example.com",
            domain_intel={"mx_records": ["mx1.example.com"]},
            accounts=[{"platform": "Instagram", "status": "INCONCLUSIVE", "confidence_level": "LOW"}],
            leaks=[],
        )
        self.assertTrue(res_ambig["syntax_valid"])
        self.assertTrue(res_ambig["has_mail_infra"])
        self.assertFalse(res_ambig["account_existence_confirmed"])
        self.assertIn(EmailVerificationTier.AMBIGUOUS_OR_INCONCLUSIVE.value, res_ambig["tiers"])
        self.assertNotIn(EmailVerificationTier.REGISTERED_ACCOUNT_CONFIRMED.value, res_ambig["tiers"])

        # Confirmed account + breach
        res_conf = EmailVerificationClassifier.classify(
            email="bob@example.com",
            domain_intel={"mx_records": ["mx1.example.com"]},
            accounts=[{"platform": "GitHub", "status": "CONFIRMED", "confidence_level": "HIGH"}],
            leaks=[{"source": "XposedOrNot"}],
        )
        self.assertTrue(res_conf["account_existence_confirmed"])
        self.assertIn(EmailVerificationTier.REGISTERED_ACCOUNT_CONFIRMED.value, res_conf["tiers"])
        self.assertIn(EmailVerificationTier.BREACH_ASSOCIATED.value, res_conf["tiers"])

        # Invalid syntax
        res_bad = EmailVerificationClassifier.classify("not-an-email", {}, [], [])
        self.assertFalse(res_bad["syntax_valid"])

    def test_02_github_intel_secret_detection_redacts_and_never_uses_credentials(self):
        conn = GitHubIntelConnector()
        fake_pat = "ghp_1234567890abcdefghijklmnopqrstuv"
        hits_potential = conn.scan_text_for_secret_indicators(
            f"config: token={fake_pat}",
            repo="org/repo",
            ref="abc123",
        )
        self.assertEqual(len(hits_potential), 1)
        self.assertEqual(hits_potential[0]["lifecycle_state"], SecretLifecycleState.POTENTIAL.value)
        self.assertFalse(hits_potential[0]["active_usage_attempted"])
        self.assertNotIn(fake_pat, hits_potential[0]["redacted_preview"])
        self.assertEqual(len(hits_potential[0]["secret_sha256"]), 64)

        hits_revoked = conn.scan_text_for_secret_indicators(
            f"revoked old key {fake_pat}",
            repo="org/repo",
            ref="def456",
        )
        self.assertEqual(hits_revoked[0]["lifecycle_state"], SecretLifecycleState.REVOKED.value)

    def test_03_web_security_analyzer_headers_cookies_and_ssrf_guard(self):
        header_findings = WebSecurityAnalyzer.analyze_headers(
            headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"},
            is_https=True,
        )
        controls = {f["control"] for f in header_findings}
        self.assertIn("HSTS", controls)
        self.assertIn("CSP", controls)
        self.assertIn("X-Frame-Options", controls)
        self.assertIn("X-Content-Type-Options", controls)

        cookie_findings = WebSecurityAnalyzer.analyze_cookies(
            ["sessionid=xyz123; Path=/"], is_https=True
        )
        self.assertEqual(len(cookie_findings), 1)
        self.assertEqual(cookie_findings[0]["severity"], "MEDIUM")
        self.assertIn("Secure", cookie_findings[0]["evidence"])
        self.assertIn("HttpOnly", cookie_findings[0]["evidence"])

        with self.assertRaises(ValueError):
            WebSecurityAnalyzer.inspect_url_posture("http://127.0.0.1:8080/", {}, [])


if __name__ == "__main__":
    unittest.main()
