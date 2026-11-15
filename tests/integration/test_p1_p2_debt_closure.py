"""
P1/P2 Technical Debt Closure Verification Suite.
Covers:
- Bloque 1: Unified Kill-Switch propagation to EmailIntelOrchestrator
- Bloque 2: HTTPEngine (httpx JSONL + SSRF), PortEngine (naabu JSON + local lab TCP),
            MISPGalaxyService + CorrelationGraphEngine, Gitleaks sandboxed endpoint
- Bloque 3: BaseConnector retry/backoff/circuit-breaker + DomainIntelligenceService isolation
- Bloque 4: Dockerfile pinned binaries, non-root user, and healthcheck validation
"""

import json
import os
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from fastapi.testclient import TestClient

from app.core.security_guard import SecurityGovernanceGuard
from app.main import app
from app.models.domain_intel import ProviderQueryStatus
from app.services.connectors.base import BaseConnector, CircuitState, ConnectorConfig
from app.services.correlation.graph_engine import CorrelationGraphEngine
from app.services.cti.misp_galaxy import MISPGalaxyService
from app.services.domain_intel.base import ProviderResponse
from app.services.domain_intel.service import DomainIntelligenceService
from app.services.email_intel.orchestrator import ACTIVE_TASKS, EmailIntelOrchestrator
from app.services.engines.http_engine import HTTPEngine
from app.services.engines.port_engine import PortEngine
from app.services.github_intel.scanner import GitHubIntelConnector


class _FlakyConnector(BaseConnector):
    def __init__(self, fail_times: int = 10):
        super().__init__(
            ConnectorConfig(
                connector_id="flaky-test-v1",
                name="Flaky Test",
                version="1.0",
                source="unit-test",
                timeout=1.0,
                rate_limit_rps=100.0,
                max_retries=1,
                backoff_base_seconds=0.01,
                failure_threshold=2,
                recovery_timeout_seconds=60.0,
                cache_ttl_seconds=30,
            )
        )
        self.fail_times = fail_times
        self.calls = 0

    async def _fetch_raw(self, target: str, **kwargs):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("upstream unavailable")
        return {"ok": True, "target": target}

    def normalize(self, raw_data, target: str):
        return [raw_data]


class TestP1P2DebtClosure(unittest.IsolatedAsyncioTestCase):
    def tearDown(self):
        SecurityGovernanceGuard.reset_emergency_kill_switch(reset_by="test-cleanup")
        DomainIntelligenceService._circuit_failures.clear()
        DomainIntelligenceService._circuit_open_until.clear()

    def test_01_kill_switch_cancels_email_intel_orchestrator_task(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
            db_path = tf.name
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE email_intel_investigations (id TEXT PRIMARY KEY, status TEXT, progress INTEGER, updated_at TEXT, risk_explanation TEXT)"
            )
            conn.execute("INSERT INTO email_intel_investigations (id, status, progress) VALUES ('EI-TEST-1', 'RUNNING', 10)")
            conn.commit()
            conn.close()

            orch = EmailIntelOrchestrator(db_path=db_path)
            ACTIVE_TASKS["EI-TEST-1"] = {"status": "RUNNING", "cancel_requested": False, "pause_requested": False}
            SecurityGovernanceGuard.register_active_task("EI-TEST-1", "email_intel", "user@example.com")
            SecurityGovernanceGuard.trigger_emergency_kill_switch("Test unified kill-switch", triggered_by="qa")

            self.assertTrue(orch._check_cancelled("EI-TEST-1"))
        finally:
            ACTIVE_TASKS.pop("EI-TEST-1", None)
            if os.path.exists(db_path):
                os.remove(db_path)

    async def test_02_http_engine_jsonl_and_ssrf_guard(self):
        raw_jsonl = json.dumps({
            "status_code": 200,
            "title": "Portal Corporativo",
            "webserver": "nginx",
            "tech": ["Nginx", "React"],
            "tls": {"issuer_org": "Let's Encrypt", "not_after": "2027-01-01", "expired": False},
        })
        parsed = HTTPEngine.parse_httpx_jsonl(raw_jsonl)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["web_title"], "Portal Corporativo")
        self.assertIn("React", parsed["tech_stack"])

        eng = HTTPEngine()
        blocked = await eng.probe("169.254.169.254", 80)
        self.assertIn("Anti-SSRF", blocked["tls_error"] or "")

    async def test_03_port_engine_naabu_parse_and_local_lab_probe(self):
        naabu_out = json.dumps({"ip": "93.184.216.34", "port": 443, "protocol": "tcp"}) + "\n"
        parsed = PortEngine.parse_naabu_json(naabu_out)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["service_name"], "https")

        # Real local lab TCP socket test (authorized localhost)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            pe = PortEngine(timeout=1.0)
            # Without allow_local_lab, 127.0.0.1 must be blocked by Anti-SSRF
            blocked = await pe.scan_host("127.0.0.1", ports=[(port, "lab-svc")], allow_local_lab=False)
            self.assertEqual(blocked, [])
            # With allow_local_lab=True, it detects the real listening port
            open_ports = await pe.scan_host("127.0.0.1", ports=[(port, "lab-svc")], allow_local_lab=True)
            self.assertEqual(len(open_ports), 1)
            self.assertEqual(open_ports[0]["port"], port)
        finally:
            srv.close()

    def test_04_misp_galaxy_loader_and_graph_enrichment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            galaxy = MISPGalaxyService(cache_dir=tmpdir)
            payload = {
                "uuid": "galaxy-cluster-1",
                "version": 2,
                "values": [
                    {
                        "uuid": "actor-uuid-123",
                        "value": "LockBit",
                        "description": "Ransomware-as-a-Service group",
                        "meta": {"synonyms": ["LockBit 3.0"], "country": "RU"},
                    }
                ],
            }
            meta = galaxy.ingest_cluster_payload("ransomware", payload)
            self.assertEqual(meta["count"], 1)
            self.assertIsNotNone(galaxy.lookup("LockBit 3.0"))

            graph = CorrelationGraphEngine()
            graph.add_node("cve:CVE-2024-0001", "CVE-2024-0001", "CVE")
            added = galaxy.enrich_correlation_graph(graph, ["LockBit 3.0", "UnknownFakeActor"], target_node_id="cve:CVE-2024-0001")
            self.assertEqual(added, 1)
            self.assertEqual(len(graph.edges), 1)
            self.assertEqual(graph.edges[0]["source"], "MISP-Galaxy")
            self.assertFalse(graph.edges[0]["is_inferred"])

    def test_05_gitleaks_path_traversal_blocked_and_endpoint_secured(self):
        with self.assertRaises(ValueError):
            GitHubIntelConnector.run_gitleaks_cli("../../etc")

        client = TestClient(app)
        resp = client.post(
            "/api/v1/exposures/secrets/scan",
            json={"mode": "local_sandbox", "repo_dir": "../../etc"},
        )
        self.assertEqual(resp.status_code, 400)

    async def test_06_base_connector_retry_backoff_and_circuit_breaker(self):
        conn = _FlakyConnector(fail_times=10)
        r1 = await conn.execute("example.com")
        self.assertFalse(r1.success)
        self.assertEqual(conn._circuit_state, CircuitState.CLOSED)

        r2 = await conn.execute("example.com")
        self.assertFalse(r2.success)
        self.assertEqual(conn._circuit_state, CircuitState.OPEN)

        # Third call must short-circuit immediately without calling _fetch_raw
        calls_before = conn.calls
        r3 = await conn.execute("example.com")
        self.assertFalse(r3.success)
        self.assertIn("Circuit breaker OPEN", r3.error or "")
        self.assertEqual(conn.calls, calls_before)

    async def test_07_domain_intel_circuit_breaker_isolates_failing_provider(self):
        svc = DomainIntelligenceService.__new__(DomainIntelligenceService)

        async def _fail_coro():
            return ProviderResponse(provider_name="whois_xml", status=ProviderQueryStatus.CONNECTION_ERROR, error_message="503")

        for _ in range(3):
            await svc._run_limited("whois_xml", _fail_coro())

        # Circuit for whois_xml must now be OPEN
        res_open = await svc._run_limited("whois_xml", _fail_coro())
        self.assertIn("Circuit breaker OPEN", res_open.error_message or "")

        # Other providers must remain unaffected
        async def _ok_coro():
            return ProviderResponse(provider_name="rdap_whois", status=ProviderQueryStatus.SUCCESS, data={"ok": True})

        res_ok = await svc._run_limited("rdap_whois", _ok_coro())
        self.assertEqual(res_ok.status, ProviderQueryStatus.SUCCESS)

    def test_08_dockerfile_hardening_and_pinned_binaries(self):
        df_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend", "Dockerfile"))
        with open(df_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("USER openrecon", content)
        self.assertIn("HEALTHCHECK", content)
        self.assertIn("dnsx:v1.2.1", content)
        self.assertIn("gitleaks", content)
        self.assertIn("dnstwist==20240116", content)
        self.assertNotIn(":latest", content)

    def test_09_stop_scan_and_kill_switch_cancel_active_tasks_and_processes(self):
        from unittest.mock import MagicMock
        from app.api.v1.endpoints.scans import (
            _ACTIVE_SCAN_TASKS,
            _ACTIVE_SCAN_PROCESSES,
            register_scan_process,
            stop_scan_execution,
            cancel_all_active_scans,
        )

        mock_task = MagicMock()
        mock_task.done.return_value = False
        mock_proc = MagicMock()
        mock_proc.returncode = None

        _ACTIVE_SCAN_TASKS[9991] = mock_task
        register_scan_process(9991, mock_proc)
        res = stop_scan_execution(9991)
        self.assertEqual(res["cancelled_tasks"], 1)
        self.assertEqual(res["terminated_processes"], 1)
        mock_task.cancel.assert_called_once()
        mock_proc.terminate.assert_called_once()
        _ACTIVE_SCAN_TASKS.pop(9991, None)

        mock_task2 = MagicMock()
        mock_task2.done.return_value = False
        _ACTIVE_SCAN_TASKS[9992] = mock_task2
        res_all = cancel_all_active_scans()
        self.assertGreaterEqual(res_all["stopped_scan_ids"], 1)
        mock_task2.cancel.assert_called_once()
        _ACTIVE_SCAN_TASKS.pop(9992, None)


if __name__ == "__main__":
    unittest.main()
