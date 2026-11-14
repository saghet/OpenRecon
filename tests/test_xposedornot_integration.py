import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.email_intel.leak_searcher import LeakSearcher
from app.services.email_intel.risk_scorer import RiskScorer
from app.services.email_intel.xposedornot_connector import (
    XposedOrNotConnector,
    classify_exposed_categories,
    validate_email_syntax,
)
from app.services.email_intel.zehef_adapter import ZehefAdapter


class TestXposedOrNotIntegration(unittest.TestCase):
    def test_01_live_official_api_test_example_com(self):
        """Prueba REAL contra la API oficial de XposedOrNot usando correo público de prueba (test@example.com)."""
        conn = XposedOrNotConnector()
        res = asyncio.run(conn.search_email("test@example.com"))
        # Acepta COMPLETED (si test@example.com tiene brechas) o RATE_LIMITED si la IP pública está limitada, nunca INVALID_INPUT
        self.assertIn(res["status"], ("COMPLETED", "NO_MATCHES", "RATE_LIMITED"))
        self.assertEqual(res["evidence"]["source_name"], "XposedOrNot")
        if res["status"] == "COMPLETED":
            self.assertGreater(res["matches_count"], 0)
            first = res["findings"][0]
            self.assertTrue(first["source"].startswith("XposedOrNot"))
            self.assertIsInstance(first["exposed_data_types"], list)

    def test_02_live_official_api_no_matches(self):
        """Prueba REAL contra XposedOrNot con correo inexistente sin filtraciones."""
        conn = XposedOrNotConnector()
        res = asyncio.run(conn.search_email("openrecon-nonexistent-99887766@example.invalid"))
        self.assertIn(res["status"], ("NO_MATCHES", "RATE_LIMITED"))
        self.assertEqual(res["findings"], [])

    def test_03_invalid_email_format_rejected(self):
        conn = XposedOrNotConnector()
        for bad in ("", "no-at-symbol", "user@", "bad email@example.com", "a" * 260 + "@b.com"):
            res = asyncio.run(conn.search_email(bad))
            self.assertEqual(res["status"], "INVALID_INPUT")
            self.assertEqual(res["evidence"]["validation_status"], "ERROR")

    def test_04_simulated_multi_breach_deduplication_and_categories(self):
        """Prueba controlada (mock HTTP) de múltiples filtraciones, deduplicación y clasificación de categorías."""
        sample_payload = {
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "AcmeCorp2024",
                        "domain": "acme.example",
                        "industry": "Technology",
                        "xposed_date": "2024",
                        "xposed_records": 50000,
                        "xposed_data": "Email addresses;Passwords;Phone numbers;IP addresses",
                        "password_risk": "plaintext",
                        "verified": True,
                        "details": "Exposed user table",
                        "references": "https://xposedornot.com/xposed#AcmeCorp2024",
                    },
                    {
                        "breach": "AcmeCorp2024",
                        "domain": "acme.example",
                        "industry": "Technology",
                        "xposed_date": "2024",
                        "xposed_data": "Email addresses;Passwords",
                    },
                    {
                        "breach": "ForumLeak2022",
                        "domain": "forum.example",
                        "industry": "Social",
                        "xposed_date": "2022",
                        "xposed_data": "Email addresses;Names;Credit cards",
                        "verified": False,
                    },
                ]
            }
        }
        mock_resp = httpx.Response(200, json=sample_payload)
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.services.email_intel.xposedornot_connector.httpx.AsyncClient", return_value=mock_client):
            res = asyncio.run(XposedOrNotConnector().search_email("analyst@acme.example"))

        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["matches_count"], 2)  # Deduplicó AcmeCorp2024
        cats_first = res["findings"][0]["exposed_data_types"]
        self.assertIn("PASSWORDS", cats_first)
        self.assertIn("PHONE_NUMBERS", cats_first)
        self.assertIn("IP_ADDRESSES", cats_first)
        self.assertIn("FINANCIAL_DATA", res["findings"][1]["exposed_data_types"])

    def test_05_simulated_error_states_never_reported_as_clean(self):
        """Prueba controlada (mock HTTP) de 429, 500, Timeout, ConnectError y JSON malformado."""
        conn = XposedOrNotConnector()
        cases = [
            (httpx.Response(429, text="Too Many Requests"), "RATE_LIMITED"),
            (httpx.Response(500, text="Internal Server Error"), "TEMPORARILY_UNAVAILABLE"),
            (httpx.Response(200, content=b"{invalid-json"), "MALFORMED_RESPONSE"),
            (httpx.Response(200, json={"unexpected": 123}), "MALFORMED_RESPONSE"),
            (httpx.TimeoutException("timeout"), "TIMEOUT"),
            (httpx.ConnectError("unreachable"), "CONNECTION_ERROR"),
        ]
        for outcome, expected_status in cases:
            with self.subTest(expected_status=expected_status):
                mock_client = MagicMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                if isinstance(outcome, Exception):
                    mock_client.get = AsyncMock(side_effect=outcome)
                else:
                    mock_client.get = AsyncMock(return_value=outcome)

                with patch("app.services.email_intel.xposedornot_connector.httpx.AsyncClient", return_value=mock_client):
                    res = asyncio.run(conn.search_email("user@example.com"))
                self.assertEqual(res["status"], expected_status)
                self.assertEqual(res["evidence"]["validation_status"], expected_status)

    def test_06_leak_searcher_consolidation_and_risk_scorer(self):
        """Verifica consolidación HudsonRock + XposedOrNot y cálculo explicable de riesgo."""
        adapter = ZehefAdapter()
        searcher = LeakSearcher(adapter)

        fake_xon = {
            "status": "COMPLETED",
            "findings": [{
                "source": "XposedOrNot · TestBreach",
                "leak_date": "2024",
                "query_date": "2026-11-14T00:00:00Z",
                "exposed_data_types": ["EMAIL_ADDRESSES", "PASSWORDS"],
                "confidence_level": "HIGH",
                "verifiable_reference": "https://xposedornot.com/xposed#TestBreach",
                "corporate_services_count": 0,
                "user_services_count": 0,
            }],
            "evidence": {
                "source_type": "BREACH_XPOSEDORNOT",
                "source_name": "XposedOrNot",
                "collected_at_utc": "2026-11-14T00:00:00Z",
                "raw_content_preview": "{}",
                "content_sha256": "abc",
                "validation_status": "CORROBORATED",
                "confidence_score": 0.9,
            },
        }
        with patch.object(searcher.xon_connector, "search_email", new=AsyncMock(return_value=fake_xon)):
            leaks, evidences = asyncio.run(searcher.search_leaks("openrecon-nonexistent-99887766@example.invalid"))

        self.assertTrue(any(e["source_name"] == "XposedOrNot" for e in evidences))
        self.assertTrue(any(e["source_name"] == "HudsonRock Cavalier" for e in evidences))
        self.assertTrue(any(l["source"] == "XposedOrNot · TestBreach" for l in leaks))

        score, level, exp = RiskScorer.calculate_risk(leaks, [], [], {"dns_security_score": 100})
        self.assertGreaterEqual(score, 40.0)
        self.assertIn("XposedOrNot", exp)
        self.assertIn("vigente", exp)

    def test_07_ttl_cache_hit_and_error_non_caching(self):
        XposedOrNotConnector.clear_cache()
        connector = XposedOrNotConnector(cache_ttl_seconds=60)

        mock_404 = MagicMock(status_code=404, text='{"Error":"Not found"}')
        with patch("httpx.AsyncClient") as client_cls:
            inst = client_cls.return_value.__aenter__.return_value
            inst.get = AsyncMock(return_value=mock_404)
            first = asyncio.run(connector.search_email("cache-test@example.com"))
            second = asyncio.run(connector.search_email("cache-test@example.com"))

        self.assertEqual(first["status"], "NO_MATCHES")
        self.assertFalse(first.get("from_cache", False))
        self.assertEqual(second["status"], "NO_MATCHES")
        self.assertTrue(second.get("from_cache", False))
        self.assertEqual(inst.get.await_count, 1)

        # Errors must never be cached
        mock_429 = MagicMock(status_code=429, text="rate limit")
        with patch("httpx.AsyncClient") as client_cls:
            inst = client_cls.return_value.__aenter__.return_value
            inst.get = AsyncMock(return_value=mock_429)
            err1 = asyncio.run(connector.search_email("err-test@example.com"))
            err2 = asyncio.run(connector.search_email("err-test@example.com"))

        self.assertEqual(err1["status"], "RATE_LIMITED")
        self.assertEqual(err2["status"], "RATE_LIMITED")
        self.assertEqual(inst.get.await_count, 2)

    def test_08_query_domain_breaches_states(self):
        connector = XposedOrNotConnector()
        with patch.dict(os.environ, {}, clear=True):
            res_missing = asyncio.run(connector.query_domain_breaches())
        self.assertEqual(res_missing["status"], "KEY_NOT_CONFIGURED")

        mock_401 = MagicMock(status_code=401, text='{"error":"Unauthorized"}')
        with patch("httpx.AsyncClient") as client_cls:
            client_cls.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_401)
            res_401 = asyncio.run(connector.query_domain_breaches(api_key="bad-key"))
        self.assertEqual(res_401["status"], "INVALID_KEY")

        mock_200 = MagicMock(
            status_code=200,
            json=lambda: {"status": "success", "metrics": {"Breach_Summary": {"Total": 2}}},
        )
        with patch("httpx.AsyncClient") as client_cls:
            post_mock = AsyncMock(return_value=mock_200)
            client_cls.return_value.__aenter__.return_value.post = post_mock
            res_200 = asyncio.run(connector.query_domain_breaches(api_key="valid-key"))
        self.assertEqual(res_200["status"], "COMPLETED")
        self.assertEqual(res_200["data"]["metrics"]["Breach_Summary"]["Total"], 2)
        sent_headers = post_mock.call_args.kwargs["headers"]
        self.assertEqual(sent_headers["x-api-key"], "valid-key")
        self.assertEqual(sent_headers["Content-Length"], "0")

    def test_09_compare_investigations_endpoint(self):
        import sqlite3
        import tempfile
        from app.api.v1.endpoints import email_intel as ei_ep

        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.close()
        try:
            conn = sqlite3.connect(tmp.name)
            conn.row_factory = sqlite3.Row
            conn.executescript(
                """
                CREATE TABLE email_intel_investigations (
                    id TEXT PRIMARY KEY,
                    target_email TEXT,
                    created_at TEXT
                );
                CREATE TABLE email_intel_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT,
                    source TEXT,
                    leak_date TEXT,
                    exposed_data_types TEXT,
                    verifiable_reference TEXT
                );
                INSERT INTO email_intel_investigations VALUES ('inv-1', 'user@corp.com', '2026-11-01T00:00:00Z');
                INSERT INTO email_intel_investigations VALUES ('inv-2', 'user@corp.com', '2026-11-14T00:00:00Z');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date, exposed_data_types, verifiable_reference)
                VALUES ('inv-1', 'XposedOrNot · OldBreach', '2020-01-01', '["Email addresses"]', 'https://xposedornot.com/xposed#OldBreach');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date, exposed_data_types, verifiable_reference)
                VALUES ('inv-2', 'XposedOrNot · OldBreach', '2020-01-01', '["Email addresses"]', 'https://xposedornot.com/xposed#OldBreach');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date, exposed_data_types, verifiable_reference)
                VALUES ('inv-2', 'XposedOrNot · NewBreach2026', '2026-05-01', '["Email addresses", "Passwords"]', 'https://xposedornot.com/xposed#NewBreach2026');
                """
            )
            conn.commit()
            conn.close()

            def _get_test_db():
                c = sqlite3.connect(tmp.name)
                c.row_factory = sqlite3.Row
                return c

            with patch.object(ei_ep, "get_db", side_effect=_get_test_db):
                diff = ei_ep.compare_investigations("inv-1", "inv-2")

            self.assertEqual(diff["unchanged_count"], 1)
            self.assertEqual(len(diff["new_leaks"]), 1)
            self.assertEqual(diff["new_leaks"][0]["source"], "XposedOrNot · NewBreach2026")
            self.assertEqual(diff["removed_leaks"], [])
        finally:
            os.unlink(tmp.name)

    def test_10_orchestrator_consecutive_investigations_diff(self):
        import sqlite3
        import tempfile
        from app.services.email_intel.orchestrator import EmailIntelOrchestrator

        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.close()
        try:
            conn = sqlite3.connect(tmp.name)
            conn.executescript(
                """
                CREATE TABLE email_intel_investigations (
                    id TEXT PRIMARY KEY,
                    target_email TEXT,
                    status TEXT,
                    progress INTEGER,
                    exposure_score REAL,
                    risk_level TEXT,
                    risk_explanation TEXT,
                    total_findings INTEGER,
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE TABLE email_intel_leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT,
                    source TEXT,
                    leak_date TEXT
                );
                INSERT INTO email_intel_investigations VALUES
                    ('EI-PREV-1', 'repeat@corp.com', 'COMPLETED', 100, 30.0, 'ELEVATED', 'Prev', 1, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z'),
                    ('EI-CURR-2', 'repeat@corp.com', 'RUNNING', 90, 0.0, 'INFORMATIVE', '', 0, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date)
                VALUES ('EI-PREV-1', 'XposedOrNot · OldBreach', '2020-01-01');
                INSERT INTO email_intel_leaks (investigation_id, source, leak_date)
                VALUES ('EI-CURR-2', 'XposedOrNot · OldBreach', '2020-01-01'),
                       ('EI-CURR-2', 'XposedOrNot · FreshBreach2026', '2026-06-01');
                """
            )
            conn.commit()
            conn.close()

            orch = EmailIntelOrchestrator()
            orch.db_path = tmp.name
            orch._finalize_investigation("EI-CURR-2", 65.0, "ELEVATED", "Base explanation.", 2)

            verify_conn = sqlite3.connect(tmp.name)
            verify_conn.row_factory = sqlite3.Row
            row = verify_conn.execute(
                "SELECT status, risk_explanation FROM email_intel_investigations WHERE id = 'EI-CURR-2'"
            ).fetchone()
            verify_conn.close()

            self.assertEqual(row["status"], "COMPLETED")
            self.assertIn("Detectadas 1 filtración(es) nueva(s)", row["risk_explanation"])
            self.assertIn("FreshBreach2026", row["risk_explanation"])
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
