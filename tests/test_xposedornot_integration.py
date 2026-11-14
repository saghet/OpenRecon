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


if __name__ == "__main__":
    unittest.main()
