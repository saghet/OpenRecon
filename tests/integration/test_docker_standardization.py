"""
Verification tests for OpenRecon 3.0 Docker Standardization, Worker Isolation,
PHP/Docker API parameterization, and SQLite->PostgreSQL migrator.
"""

import os
import sqlite3
import sys
import tempfile
import unittest

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKEND_DIR = os.path.join(REPO_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


class TestDockerStandardization(unittest.TestCase):
    def test_01_docker_compose_hardening_and_topology(self):
        compose_path = os.path.join(REPO_ROOT, "docker-compose.yml")
        with open(compose_path, "r", encoding="utf-8") as f:
            raw = f.read()
        data = yaml.safe_load(raw)

        services = data.get("services", {})
        for expected in ("postgres", "redis", "tor-proxy", "api", "recon-worker", "web"):
            self.assertIn(expected, services)

        self.assertNotIn("privileged: true", raw)
        self.assertNotIn("docker.sock", raw)
        self.assertNotIn(":latest", raw)

        # Internal data network must be marked internal: true
        self.assertTrue(data["networks"]["internal-data-net"].get("internal"))

        # Recon worker must drop all capabilities and enforce no-new-privileges
        worker = services["recon-worker"]
        self.assertIn("ALL", worker.get("cap_drop", []))
        self.assertIn("no-new-privileges:true", worker.get("security_opt", []))
        self.assertIn("resources", worker.get("deploy", {}))

    def test_02_worker_and_web_dockerfiles_hardened(self):
        worker_df = os.path.join(REPO_ROOT, "docker", "worker", "Dockerfile")
        with open(worker_df, "r", encoding="utf-8") as f:
            w_content = f.read()
        self.assertIn("AS go-builder", w_content)
        self.assertIn("USER openrecon", w_content)
        self.assertIn("sha256sum -c", w_content)
        self.assertIn("HEALTHCHECK", w_content)
        self.assertNotIn(":latest", w_content)

        web_df = os.path.join(REPO_ROOT, "docker", "web", "Dockerfile")
        with open(web_df, "r", encoding="utf-8") as f:
            web_content = f.read()
        self.assertIn("php:8.2.26-apache-bookworm", web_content)
        self.assertIn("pdo_sqlite", web_content)
        self.assertIn("pdo_pgsql", web_content)
        self.assertIn("HEALTHCHECK", web_content)

    def test_03_php_dashboard_supports_docker_api_url(self):
        autostart_path = os.path.join(REPO_ROOT, "web_dashboard", "backend_autostart.php")
        with open(autostart_path, "r", encoding="utf-8") as f:
            as_content = f.read()
        self.assertIn("OPENRECON_API_URL", as_content)
        self.assertIn("OPENRECON_DOCKER_MODE", as_content)

        api_path = os.path.join(REPO_ROOT, "web_dashboard", "api.php")
        with open(api_path, "r", encoding="utf-8") as f:
            api_content = f.read()
        self.assertIn("getenv('OPENRECON_API_URL')", api_content)

    def test_04_sqlite_to_postgres_migrator_dry_run(self):
        from scripts.migrate_sqlite_to_postgres import migrate

        tmp_src = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp_dst = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_src.close()
        tmp_dst.close()
        try:
            conn = sqlite3.connect(tmp_src.name)
            conn.execute("CREATE TABLE organizations (id INTEGER PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO organizations (id, name) VALUES (1, 'Acme')")
            conn.commit()
            conn.close()

            dst_conn = sqlite3.connect(tmp_dst.name)
            dst_conn.execute("CREATE TABLE organizations (id INTEGER PRIMARY KEY, name TEXT)")
            dst_conn.commit()
            dst_conn.close()

            report = migrate(tmp_src.name, f"sqlite:///{tmp_dst.name}", dry_run=True)
            self.assertEqual(report.get("organizations"), 1)
        finally:
            os.unlink(tmp_src.name)
            os.unlink(tmp_dst.name)


if __name__ == "__main__":
    unittest.main()
