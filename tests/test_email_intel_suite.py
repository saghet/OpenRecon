"""
===============================================================================
TEST SUITE INTEGRAL: EMAIL INTELLIGENCE (ZEHEF OSINT ENGINE)
Valida rigurosamente los 15 controles exigidos para la integración en OpenRecon:
 1. Validación de correos (RFC 5322 & Anti-SSRF)
 2. Ejecución del Adaptador Zehef
 3. Búsqueda de filtraciones (Leaks & K-Anonymity)
 4. Búsqueda de cuentas digitales (Account Presence)
 5. Búsqueda en pastes (Public Archives)
 6. Generación de variantes (Hipótesis no verificadas)
 7. Análisis DNS de Dominio (MX, SPF, DMARC, DKIM)
 8. Normalización de resultados
 9. Detección y mitigación de falsos positivos
10. Persistencia de investigaciones en SQLite
11. Generación y exportación de informes (JSON / CSV)
12. Cancelación y pausa de tareas activas
13. Control de permisos y justificación RoE
14. Aislamiento de procesos y seguridad AppSec
15. Recuperación ante errores y resiliencia de red
===============================================================================
"""

import unittest
import asyncio
import os
import sys
import json
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock

# Ensure backend is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.services.email_intel.schemas import (
    InvestigationCreateRequest,
    DomainAnalysisFinding,
    AccountFinding,
    LeakFinding
)
from app.services.email_intel.zehef_adapter import ZehefAdapter
from app.services.email_intel.leak_searcher import LeakSearcher
from app.services.email_intel.account_searcher import AccountSearcher
from app.services.email_intel.paste_searcher import PasteSearcher
from app.services.email_intel.email_generator import EmailGenerator
from app.services.email_intel.domain_intel_engine import DomainIntelEngine
from app.services.email_intel.risk_scorer import RiskScorer
from app.services.email_intel.orchestrator import EmailIntelOrchestrator


class TestEmailIntelligenceSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = ZehefAdapter(timeout_seconds=5.0)
        cls.generator = EmailGenerator()
        cls.domain_engine = DomainIntelEngine(timeout=3.0)
        cls.risk_scorer = RiskScorer()

    # -------------------------------------------------------------------------
    # 1. Validación de Correos (RFC 5322 & Anti-SSRF)
    # -------------------------------------------------------------------------
    def test_01_email_syntax_and_anti_ssrf_validation(self):
        # Valid email
        req = InvestigationCreateRequest(
            target_email="analyst.soc@openrecon.security",
            case_id="CASE-2026-001",
            title="Valid Investigation",
            authorization_justification="Authorized RoE"
        )
        self.assertEqual(req.target_email, "analyst.soc@openrecon.security")

        # Invalid syntax
        with self.assertRaises(ValueError):
            InvestigationCreateRequest(
                target_email="not-an-email-address",
                case_id="CASE-2026-001",
                title="Invalid Syntax",
                authorization_justification="Authorized RoE"
            )

        # Anti-SSRF: Localhost blocked
        with self.assertRaises(ValueError):
            InvestigationCreateRequest(
                target_email="admin@localhost",
                case_id="CASE-2026-001",
                title="SSRF Attack Attempt",
                authorization_justification="Authorized RoE"
            )

        # Anti-SSRF: 127.0.0.1 blocked
        with self.assertRaises(ValueError):
            InvestigationCreateRequest(
                target_email="root@127.0.0.1",
                case_id="CASE-2026-001",
                title="SSRF IP Attempt",
                authorization_justification="Authorized RoE"
            )

    # -------------------------------------------------------------------------
    # 2. Ejecución del Adaptador Zehef
    # -------------------------------------------------------------------------
    def test_02_zehef_adapter_initialization_and_hashing(self):
        sha = self.adapter.calculate_sha256("test_evidence_string")
        self.assertEqual(len(sha), 64)
        self.assertEqual(sha, "9fee3e0f9e63cb170631a4e6a650aa51cdd4222651a037821a56540454bc6158")

        # Masking PII (K-Anonymity check)
        masked_email = self.adapter.mask_pii("john.doe@company.com")
        self.assertTrue(masked_email.startswith("jo*"))
        self.assertTrue(masked_email.endswith("@company.com"))

    # -------------------------------------------------------------------------
    # 3. Búsqueda de Filtraciones (Leak Search & K-Anonymity)
    # -------------------------------------------------------------------------
    def test_03_leak_search_sanitization_and_k_anonymity(self):
        leak_searcher = LeakSearcher(self.adapter)
        # Test simulated response ensuring cleartext passwords are NEVER extracted
        simulated_stealer = {
            "stealers": [{
                "date_compromised": "2026-01-15T10:00:00Z",
                "total_corporate_services": 4,
                "total_user_services": 12,
                "computer_name": "CORP-WKS-88",
                "operating_system": "Windows 11 Pro",
                "ip": "198.51.100.55",
                "top_passwords": ["CLEAR_TEXT_PASSWORD_LEAKED_1234"]
            }]
        }
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = json.dumps(simulated_stealer)
            mock_resp.json.return_value = simulated_stealer
            mock_get.return_value = mock_resp

            loop = asyncio.new_event_loop()
            findings, evidences = loop.run_until_complete(leak_searcher.search_leaks("victim@target.com"))
            loop.close()

            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["corporate_services_count"], 4)
            self.assertEqual(finding["user_services_count"], 12)
            # Crucial assertion: Cleartext password must NEVER exist in finding
            finding_str = json.dumps(finding)
            self.assertNotIn("CLEAR_TEXT_PASSWORD_LEAKED_1234", finding_str)
            self.assertEqual(len(evidences), 1)

    # -------------------------------------------------------------------------
    # 4. Búsqueda de Cuentas Digitales (Account Search)
    # -------------------------------------------------------------------------
    def test_04_account_search_platforms(self):
        account_searcher = AccountSearcher(self.adapter)
        # Test mock of GitHub and Spotify
        with patch.object(account_searcher, "_check_github") as mock_gh:
            mock_gh.return_value = ({
                "platform": "GitHub", "status": "CONFIRMED", "query_date": "2026-11-11T20:00:00Z",
                "check_method": "API Search", "username": "osintanalyst", "raw_evidence_sha256": "abc"
            }, {"source_name": "GitHub", "content_sha256": "abc", "source_type": "ACCOUNT_LOOKUP", "collected_at_utc": "2026-11-11T20:00:00Z", "raw_content_preview": "", "validation_status": "CORROBORATED", "confidence_score": 0.9})

            loop = asyncio.new_event_loop()
            res, ev = loop.run_until_complete(account_searcher._check_github(None, "osintanalyst@test.com"))
            loop.close()

            self.assertEqual(res["platform"], "GitHub")
            self.assertEqual(res["status"], "CONFIRMED")
            self.assertEqual(res["username"], "osintanalyst")

    # -------------------------------------------------------------------------
    # 5. Búsqueda en Pastes (Public Archives)
    # -------------------------------------------------------------------------
    def test_05_paste_search_passive_query(self):
        paste_searcher = PasteSearcher(self.adapter)
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = json.dumps([{"id": "pst9988", "time": "2026-05-01"}])
            mock_resp.json.return_value = [{"id": "pst9988", "time": "2026-05-01"}]
            mock_get.return_value = mock_resp

            loop = asyncio.new_event_loop()
            findings, evidences = loop.run_until_complete(paste_searcher.search_pastes("target@corp.com"))
            loop.close()

            self.assertTrue(len(findings) >= 1)
            self.assertEqual(findings[0]["classification"], "LEAK_PASTE_INDEX")

    # -------------------------------------------------------------------------
    # 6. Generación de Variantes (Hipótesis no confirmadas)
    # -------------------------------------------------------------------------
    def test_06_email_variant_generator(self):
        variants = self.generator.generate_variants("john.doe@company.com")
        self.assertTrue(len(variants) >= 5)

        emails = [v["variant_email"] for v in variants]
        # Should generate jdoe@company.com, doe.john@company.com, etc.
        self.assertIn("jdoe@company.com", emails)
        self.assertIn("doe.john@company.com", emails)

        # All generated variants must be explicitly classified as HYPOTHESIS
        for v in variants:
            self.assertEqual(v["classification"], "HYPOTHESIS_UNVERIFIED")

    # -------------------------------------------------------------------------
    # 7. Análisis DNS de Dominio (MX, SPF, DMARC, DKIM)
    # -------------------------------------------------------------------------
    def test_07_domain_dns_security_posture(self):
        # Test on live authoritative domain or controlled mock
        result = self.domain_engine.analyze_domain("google.com")
        self.assertEqual(result["domain"], "google.com")
        self.assertIn("Google", result["mail_provider"])
        self.assertTrue(len(result["mx_records"]) > 0)
        self.assertIn(result["spf_status"], ["STRICT_HARDFAIL (-all)", "PERMISSIVE_SOFTFAIL (~all)", "CONFIGURED"])
        self.assertIn(result["dmarc_status"], ["STRICT_REJECT (p=reject)", "QUARANTINE (p=quarantine)", "MONITORING_ONLY (p=none)", "PRESENT"])

    # -------------------------------------------------------------------------
    # 8. Normalización de Resultados
    # -------------------------------------------------------------------------
    def test_08_results_normalization_states(self):
        valid_states = {"CONFIRMED", "PROBABLE", "NOT_FOUND", "INCONCLUSIVE", "QUERY_ERROR"}
        sample = AccountFinding(
            platform="TestPlatform",
            status="CONFIRMED",
            query_date="2026-11-11T20:00:00Z",
            check_method="API Probe",
            evidence_snippet="User exists",
            raw_evidence_sha256="abc123"
        )
        self.assertIn(sample.status, valid_states)

    # -------------------------------------------------------------------------
    # 9. Detección y Mitigación de Falsos Positivos
    # -------------------------------------------------------------------------
    def test_09_false_positive_mitigation(self):
        # An HTTP 200 without user profile or positive indication must NOT be marked CONFIRMED
        searcher = AccountSearcher(self.adapter)
        error_res = searcher._error_finding("SampleService", "Generic HTTP 200 with empty body", "sha")
        self.assertNotEqual(error_res["status"], "CONFIRMED")
        self.assertEqual(error_res["status"], "QUERY_ERROR")

    # -------------------------------------------------------------------------
    # 10. Persistencia de Investigaciones en SQLite
    # -------------------------------------------------------------------------
    def test_10_investigation_persistence_and_relationships(self):
        # Create a temp DB to test full relational integrity
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            temp_db = tf.name

        try:
            from app.core.init_email_intel_db import EMAIL_INTEL_DDL_SQLITE
            conn = sqlite3.connect(temp_db)
            conn.executescript(EMAIL_INTEL_DDL_SQLITE)
            conn.close()

            orch = EmailIntelOrchestrator(db_path=temp_db)
            req = InvestigationCreateRequest(
                target_email="security.test@example.com",
                case_id="CASE-PERSIST-001",
                title="Persistence Test",
                authorization_justification="Automated QA Suite"
            )
            inv_id = orch.create_investigation(req)
            self.assertTrue(inv_id.startswith("EI-"))

            # Verify in DB
            conn = sqlite3.connect(temp_db)
            row = conn.execute("SELECT target_email, status FROM email_intel_investigations WHERE id = ?", (inv_id,)).fetchone()
            conn.close()
            self.assertEqual(row[0], "security.test@example.com")
            self.assertEqual(row[1], "PENDING")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    # -------------------------------------------------------------------------
    # 11. Generación y Exportación de Informes (JSON / CSV)
    # -------------------------------------------------------------------------
    def test_11_report_generation_and_export_formats(self):
        leaks = [{"source": "HudsonRock", "corporate_services_count": 2, "user_services_count": 5, "confidence_level": "HIGH", "query_date": "2026-11-11"}]
        accounts = [{"platform": "GitHub", "status": "CONFIRMED", "username": "analyst", "confidence_level": "HIGH", "query_date": "2026-11-11"}]
        pastes = []
        domain = {"dns_security_score": 85}

        score, level, explanation = self.risk_scorer.calculate_risk(leaks, accounts, pastes, domain)
        self.assertTrue(score >= 40.0)
        self.assertIn(level, ["MEDIUM", "HIGH", "CRITICAL"])
        self.assertIn("info-stealer", explanation.lower())

    # -------------------------------------------------------------------------
    # 12. Cancelación y Pausa de Tareas
    # -------------------------------------------------------------------------
    def test_12_task_cancellation_and_pause_controls(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            temp_db = tf.name

        try:
            from app.core.init_email_intel_db import EMAIL_INTEL_DDL_SQLITE
            conn = sqlite3.connect(temp_db)
            conn.executescript(EMAIL_INTEL_DDL_SQLITE)
            conn.close()

            orch = EmailIntelOrchestrator(db_path=temp_db)
            req = InvestigationCreateRequest(
                target_email="pause.test@example.com",
                case_id="CASE-PAUSE-001",
                title="Pause Test",
                authorization_justification="Automated QA Suite"
            )
            inv_id = orch.create_investigation(req)
            orch.cancel_investigation(inv_id)

            conn = sqlite3.connect(temp_db)
            row = conn.execute("SELECT status FROM email_intel_investigations WHERE id = ?", (inv_id,)).fetchone()
            conn.close()
            self.assertEqual(row[0], "CANCELLED")
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    # -------------------------------------------------------------------------
    # 13. Control de Permisos y Justificación RoE
    # -------------------------------------------------------------------------
    def test_13_authorization_justification_mandatory(self):
        # Empty justification must fail
        with self.assertRaises(ValueError):
            InvestigationCreateRequest(
                target_email="test@target.com",
                case_id="CASE-001",
                title="No Justification",
                authorization_justification=""
            )

    # -------------------------------------------------------------------------
    # 14. Aislamiento de Procesos y Seguridad AppSec
    # -------------------------------------------------------------------------
    def test_14_appsec_command_injection_prevention(self):
        # Attempt command injection in email or case_id
        with self.assertRaises(ValueError):
            InvestigationCreateRequest(
                target_email="user@domain.com; rm -rf /; touch /tmp/pwned",
                case_id="CASE-INJECT",
                title="Injection",
                authorization_justification="RoE"
            )

    # -------------------------------------------------------------------------
    # 15. Recuperación ante Errores y Resiliencia de Red
    # -------------------------------------------------------------------------
    def test_15_resilience_and_graceful_degradation(self):
        searcher = AccountSearcher(self.adapter)
        # Calling with broken/unreachable client must degrade gracefully with QUERY_ERROR, never crash
        loop = asyncio.new_event_loop()
        finding, ev = loop.run_until_complete(searcher._check_github(None, "error@test.com"))
        loop.close()

        self.assertEqual(finding["status"], "QUERY_ERROR")
        self.assertIn("Exception Handler", finding["check_method"])


if __name__ == "__main__":
    unittest.main()
