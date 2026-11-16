"""
Integration tests for the Centralized Settings Hub (/api/v1/settings/overview & /runtime).
"""

import os
import sys
import tempfile
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.core.config import settings
from app.core.database import Base, get_db
from app.main import app


class TestSettingsHub(unittest.TestCase):
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

    def test_01_settings_overview_and_runtime_update_no_secret_leak(self):
        def _override_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_db
        orig_token = settings.OPENRECON_API_TOKEN
        orig_rate = settings.RATE_LIMIT_RPS
        settings.OPENRECON_API_TOKEN = "hub-test-token"
        try:
            client = TestClient(app)
            self.assertEqual(client.get("/api/v1/settings/overview").status_code, 401)

            headers = {"X-OpenRecon-Token": "hub-test-token"}
            r = client.get("/api/v1/settings/overview?organization_id=1", headers=headers)
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn("internal", data)
            self.assertIn("web_policy", data)
            self.assertIn("external_apis", data)
            self.assertIn("platforms", data)
            self.assertNotIn("hub-test-token", r.text)
            self.assertNotIn("DATABASE_URL", r.text)

            provider_names = {p["provider_name"] for p in data["external_apis"]}
            self.assertIn("virustotal", provider_names)
            self.assertIn("otx", provider_names)

            r_put = client.put(
                "/api/v1/settings/runtime",
                headers=headers,
                json={"rate_limit_rps": 25},
            )
            self.assertEqual(r_put.status_code, 200)
            self.assertEqual(r_put.json()["rate_limit_rps"], 25)
        finally:
            settings.RATE_LIMIT_RPS = orig_rate
            settings.OPENRECON_API_TOKEN = orig_token
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
