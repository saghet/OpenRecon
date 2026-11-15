"""
Phase 2 Architecture Consolidation Integration Tests:
- Standardized Connector Architecture & Registry
- Central EvidenceManager with Tenant Isolation & Audit History
- Observability (Correlation ID, JSON logging, Prometheus /metrics)
- Alembic versioned migration presence
"""

import asyncio
import json
import logging
import os
import sys
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from app.core.database import Base, enforce_org_isolation
from app.core.observability import JsonLogFormatter, correlation_id_ctx
from app.main import app
from app.models.evidence import EvidenceAuditLog, EvidenceRecord, FindingValidationState
from app.models.organization import Organization
from app.services.connectors import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorStatus,
)
from app.services.evidence import EvidenceManager


class _DummyConnector(BaseConnector):
    async def _fetch_raw(self, target: str, **kwargs):
        if kwargs.get("slow"):
            await asyncio.sleep(0.5)
        if kwargs.get("fail"):
            raise RuntimeError("upstream 503")
        return {"hit": target}

    def normalize(self, raw_data, target: str):
        return [{"asset": target, "hit": raw_data["hit"]}]


class TestPhase2Architecture(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

        @event.listens_for(self.engine, "connect")
        def _fk_on(dbapi_conn, _rec):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_01_connector_registry_timeout_and_normalization(self):
        reg = ConnectorRegistry()
        conn = _DummyConnector(
            ConnectorConfig(
                connector_id="dummy-osint-v1",
                name="Dummy OSINT",
                version="1.0.0",
                source="DummySource",
                timeout=0.1,
                rate_limit_rps=50.0,
            )
        )
        reg.register(conn)
        self.assertEqual(len(reg.list_all()), 1)
        self.assertIsNotNone(reg.get("dummy-osint-v1"))

        res_ok = asyncio.run(conn.execute("example.com"))
        self.assertTrue(res_ok.success)
        self.assertEqual(res_ok.status, ConnectorStatus.READY)
        self.assertEqual(res_ok.records[0]["asset"], "example.com")

        res_timeout = asyncio.run(conn.execute("example.com", slow=True))
        self.assertFalse(res_timeout.success)
        self.assertEqual(res_timeout.status, ConnectorStatus.DEGRADED)

        res_err = asyncio.run(conn.execute("example.com", fail=True))
        self.assertFalse(res_err.success)
        self.assertEqual(res_err.status, ConnectorStatus.ERROR)

    def test_02_evidence_manager_sanitization_and_tenant_isolation(self):
        db = self.Session()
        try:
            org1 = Organization(name="Org One")
            org2 = Organization(name="Org Two")
            db.add_all([org1, org2])
            db.commit()
            db.refresh(org1)
            db.refresh(org2)

            mgr = EvidenceManager(db)
            ev = mgr.record_finding(
                organization_id=org1.id,
                related_asset="api.org1.com",
                source="DummySource",
                technical_evidence="<script>xss</script> leak token=sk-1234567890abcdef123456",
                detection_method="PASSIVE_OSINT",
                confidence_level=0.75,
                actor="analyst_1",
            )
            self.assertEqual(ev.validation_status, FindingValidationState.NUEVO.value)
            self.assertFalse(ev.is_confirmed_vulnerability)
            self.assertNotIn("<script>", ev.technical_evidence)
            self.assertNotIn("sk-1234567890abcdef", ev.technical_evidence)
            self.assertEqual(len(ev.change_history), 1)

            # Tenant isolation: org2 cannot access or transition org1's evidence
            with self.assertRaises(LookupError):
                mgr.transition_status(
                    ev.id,
                    organization_id=org2.id,
                    new_status=FindingValidationState.FALSO_POSITIVO,
                    actor="attacker",
                    reason="cross-tenant attempt",
                )
            self.assertEqual(len(mgr.list_by_organization(org2.id)), 0)
            self.assertEqual(len(mgr.list_by_organization(org1.id)), 1)

            # Valid transition
            updated = mgr.transition_status(
                ev.id,
                organization_id=org1.id,
                new_status=FindingValidationState.CONFIRMADO,
                actor="soc_lead",
                reason="Verified manually",
                is_confirmed_vulnerability=True,
            )
            self.assertEqual(updated.validation_status, FindingValidationState.CONFIRMADO.value)
            self.assertTrue(updated.is_confirmed_vulnerability)
            self.assertEqual(len(updated.change_history), 2)
            logs = db.query(EvidenceAuditLog).filter(EvidenceAuditLog.evidence_id == ev.id).all()
            self.assertEqual(len(logs), 2)

            with self.assertRaises(ValueError):
                enforce_org_isolation(db.query(EvidenceRecord), EvidenceRecord, 0)
        finally:
            db.close()

    def test_03_observability_correlation_id_json_logs_and_metrics(self):
        client = TestClient(app)
        resp = client.get("/", headers={"X-Correlation-ID": "corr-test-123"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Correlation-ID"), "corr-test-123")

        metrics_resp = client.get("/metrics")
        self.assertEqual(metrics_resp.status_code, 200)
        self.assertIn("openrecon_http_requests_total", metrics_resp.text)

        tok = correlation_id_ctx.set("corr-json-999")
        try:
            fmt = JsonLogFormatter()
            rec = logging.LogRecord("test", logging.INFO, __file__, 1, "hello", (), None)
            parsed = json.loads(fmt.format(rec))
            self.assertEqual(parsed["correlation_id"], "corr-json-999")
            self.assertEqual(parsed["message"], "hello")
        finally:
            correlation_id_ctx.reset(tok)

    def test_04_alembic_initial_migration_present(self):
        versions_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "backend", "alembic", "versions")
        )
        self.assertTrue(os.path.isdir(versions_dir))
        py_files = [f for f in os.listdir(versions_dir) if f.endswith(".py") and not f.startswith("__")]
        self.assertGreaterEqual(len(py_files), 1, "Expected at least one Alembic migration file.")


if __name__ == "__main__":
    unittest.main()
