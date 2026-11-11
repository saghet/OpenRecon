import unittest
import sqlite3
import subprocess
import json
import os

PHP_BIN = r'C:\xampp\php\php.exe'
PYTHON_VENV = os.path.join(os.path.dirname(__file__), '..', 'backend', 'venv', 'Scripts', 'python.exe')
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'openrecon.sqlite')
ARCH_DOC = os.path.join(os.path.dirname(__file__), '..', 'docs', 'ARCHITECTURE_ENTERPRISE.md')
SBOM_DOC = os.path.join(os.path.dirname(__file__), '..', 'docs', 'SBOM.md')

class TestStage4Consolidation(unittest.TestCase):
    
    def setUp(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.close()

    def test_01_sqlite_performance_indexes(self):
        """Verifica que los 11 índices de rendimiento de SQLite existan en la base de datos."""
        indexes = [r[0] for r in self.cur.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()]
        expected_indexes = [
            'idx_assets_seed',
            'idx_assets_subdomain',
            'idx_open_ports_sub',
            'idx_vulns_sub',
            'idx_vulns_cve',
            'idx_vulns_state',
            'idx_drp_seed',
            'idx_cloud_seed',
            'idx_scope_pattern',
            'idx_audit_logs_action',
            'idx_scheduled_monitors_seed'
        ]
        for idx in expected_indexes:
            self.assertIn(idx, indexes, f"Falta el índice de rendimiento {idx} en SQLite.")

    def test_02_fastapi_schema_and_app_import(self):
        """Verifica que el microservicio FastAPI se importe correctamente y exponga 12 rutas OpenAPI."""
        py_code = """
import sys
sys.path.insert(0, 'backend')
from app.main import app
schema = app.openapi()
print(len(schema['paths']))
"""
        res = subprocess.run([PYTHON_VENV, '-c', py_code], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Fallo al importar FastAPI: {res.stderr}")
        paths_count = int(res.stdout.strip())
        self.assertGreaterEqual(paths_count, 12, "FastAPI debe exponer al menos 12 endpoints.")

    def test_03_fastapi_testclient_execution(self):
        """Verifica la ejecución de endpoints de FastAPI con TestClient."""
        py_code = """
import sys
sys.path.insert(0, 'backend')
from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)
resp = client.get('/')
assert resp.status_code == 200
data = resp.json()
assert data['platform'] == 'OpenRecon'
print('OK')
"""
        res = subprocess.run([PYTHON_VENV, '-c', py_code], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"TestClient falló: {res.stderr}")
        self.assertIn('OK', res.stdout)

    def test_04_sbom_and_architecture_documentation(self):
        """Verifica la existencia y contenido de los documentos de arquitectura y SBOM."""
        self.assertTrue(os.path.exists(ARCH_DOC), "Falta docs/ARCHITECTURE_ENTERPRISE.md")
        self.assertTrue(os.path.exists(SBOM_DOC), "Falta docs/SBOM.md")

        with open(ARCH_DOC, 'r', encoding='utf-8') as f:
            arch_content = f.read()
        self.assertIn("Diagrama de Arquitectura de la Plataforma", arch_content)
        self.assertIn("MÓDULO 1: External Attack Surface Management", arch_content)

        with open(SBOM_DOC, 'r', encoding='utf-8') as f:
            sbom_content = f.read()
        self.assertIn("Software Bill of Materials", sbom_content)
        self.assertIn("FastAPI", sbom_content)
        self.assertIn("CISA KEV Catalog", sbom_content)

    def test_05_launcher_scripts_present(self):
        """Verifica la existencia del script lanzador del microservicio FastAPI."""
        runner_py = os.path.join(os.path.dirname(__file__), '..', 'backend', 'run_server.py')
        runner_bat = os.path.join(os.path.dirname(__file__), '..', 'run_backend.bat')
        self.assertTrue(os.path.exists(runner_py), "Falta backend/run_server.py")
        self.assertTrue(os.path.exists(runner_bat), "Falta run_backend.bat")

if __name__ == '__main__':
    unittest.main()
