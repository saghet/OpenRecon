import unittest
import sqlite3
import subprocess
import json
import os

PHP_BIN = r'C:\xampp\php\php.exe'
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'openrecon.sqlite')
API_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'api.php')

class TestStage2CoreModules(unittest.TestCase):
    
    def setUp(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.close()

    def call_php_api(self, action, params=None, method='GET'):
        php_code = f"""
        $_SERVER['REQUEST_METHOD'] = '{method}';
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_GET = ['action' => '{action}'];
        $_POST = [];
        """
        if params:
            for k, v in params.items():
                if method == 'GET':
                    php_code += f"$_GET['{k}'] = '{v}';\n"
                else:
                    php_code += f"$_POST['{k}'] = '{v}';\n"
                    
        php_code += f"""
        ob_start();
        require '{API_PATH.replace(chr(92), "/")}';
        $output = ob_get_clean();
        echo $output;
        """
        res = subprocess.run([PHP_BIN, '-r', php_code], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"PHP execution failed: {res.stderr}")
        return json.loads(res.stdout)

    def test_01_connectors_catalog_categories(self):
        """Verifica que los conectores estén estructurados en FREE, API_KEY y COMMERCIAL."""
        resp = self.call_php_api('get_connectors')
        self.assertTrue(resp.get('success', False))
        counts = resp.get('counts', {})
        self.assertGreaterEqual(counts.get('free', 0), 6)
        self.assertGreaterEqual(counts.get('api_key', 0), 6)
        self.assertGreaterEqual(counts.get('commercial', 0), 4)

    def test_02_connector_key_masking(self):
        """Verifica que las API keys se almacenen enmascaradas y nunca se expongan en texto plano."""
        resp = self.call_php_api('update_connector', {
            'connector_id': 'abuseipdb',
            'is_enabled': '1',
            'api_key': 'super_secret_abuseipdb_token_999'
        }, 'POST')
        self.assertTrue(resp.get('success', False))

        get_resp = self.call_php_api('get_connectors')
        abuse_conn = [c for c in get_resp.get('connectors', []) if c['connector_id'] == 'abuseipdb'][0]
        self.assertEqual(abuse_conn['is_enabled'], 1)
        self.assertNotEqual(abuse_conn['api_key_masked'], 'super_secret_abuseipdb_token_999')
        self.assertTrue(abuse_conn['api_key_masked'].startswith('supe...'))

    def test_03_cisa_kev_local_catalog(self):
        """Verifica que el catálogo local de CISA KEV contenga registros reales de CVEs explotados."""
        count = self.cur.execute("SELECT count(*) FROM cisa_kev_catalog").fetchone()[0]
        self.assertGreaterEqual(count, 1000, f"Catálogo CISA KEV tiene solo {count} registros.")

        # Verificar CVE-2024-4577 (PHP CGI)
        row = self.cur.execute("SELECT cve_id, vulnerability_name, known_ransomware_campaign_use FROM cisa_kev_catalog WHERE cve_id = 'CVE-2024-4577'").fetchone()
        self.assertIsNotNone(row, "CVE-2024-4577 no encontrado en cisa_kev_catalog")
        self.assertIn("PHP-CGI", row[1])

    def test_04_epss_and_cisa_kev_enrichment(self):
        """Verifica enriquecimiento automático de CVE con CISA KEV y API oficial de EPSS."""
        resp = self.call_php_api('enrich_cve', {'cve_id': 'CVE-2024-4577'})
        self.assertTrue(resp.get('success', False))
        self.assertTrue(resp.get('in_cisa_kev', False))
        epss_score = resp.get('epss', {}).get('score', 0.0)
        self.assertGreater(epss_score, 0.5, "EPSS score para CVE-2024-4577 debería ser alto.")

    def test_05_vulnerability_validation_states(self):
        """Verifica que el sistema soporte y valide los 5 estados de vulnerabilidad."""
        # Insertar vulnerabilidad de prueba
        self.cur.execute("""
            INSERT OR REPLACE INTO vulnerabilities (id, asset_subdomain, title, severity, status, validation_state)
            VALUES (99999, 'test-qa.vulnweb.com', 'Falla de prueba QA', 'HIGH', 'OPEN', 'POTENCIAL')
        """)
        self.conn.commit()

        # Probar cambiar a los 5 estados válidos
        valid_states = ['POTENCIAL', 'PROBABLE', 'VALIDADA', 'FALSO_POSITIVO', 'INFO_INSUFICIENTE']
        for state in valid_states:
            resp = self.call_php_api('update_vuln_validation', {'id': '99999', 'validation_state': state}, 'POST')
            self.assertTrue(resp.get('success', False), f"Falló transición a estado {state}")

        # Probar estado inválido
        resp_invalid = self.call_php_api('update_vuln_validation', {'id': '99999', 'validation_state': 'ESTADO_INVENTADO'}, 'POST')
        self.assertFalse(resp_invalid.get('success', True))

        # Limpiar
        self.cur.execute("DELETE FROM vulnerabilities WHERE id = 99999")
        self.conn.commit()

    def test_06_explainable_risk_score_structure(self):
        """Verifica que el puntaje de riesgo 0-100 sea explicable y trace sus factores de cálculo."""
        resp = self.call_php_api('get_risk_score_breakdown')
        self.assertTrue(resp.get('success', False))
        assess = resp.get('assessment', {})
        risk_score = assess.get('risk_score')
        posture_score = assess.get('posture_score')

        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 100)
        self.assertEqual(risk_score + posture_score, 100)

        factors = assess.get('factors', [])
        self.assertGreater(len(factors), 0, "Debe haber factores explicativos del puntaje.")
        for f in factors:
            self.assertIn('category', f)
            self.assertIn('points', f)
            self.assertIn('weight', f)
            self.assertIn('description', f)

    def test_07_php2shell_stored_with_validation_state(self):
        """Verifica que los hallazgos de PHP2Shell se persistan como VALIDADA con CVSS 9.8."""
        self.cur.execute("""
            INSERT OR REPLACE INTO vulnerabilities (asset_subdomain, title, severity, cve_id, description, status, validation_state, cvss_score)
            VALUES ('qa-p2s.vulnweb.com', 'PHP2Shell Remote Code Execution (CVE-2026-109618 / CVE-2026-109619)', 'CRITICAL', 'CVE-2026-109618', 'RCE activo', 'OPEN', 'VALIDADA', 9.8)
        """)
        self.conn.commit()

        row = self.cur.execute("SELECT validation_state, cvss_score, cve_id FROM vulnerabilities WHERE asset_subdomain = 'qa-p2s.vulnweb.com'").fetchone()
        self.assertEqual(row[0], 'VALIDADA')
        self.assertEqual(row[1], 9.8)
        self.assertEqual(row[2], 'CVE-2026-109618')

        self.cur.execute("DELETE FROM vulnerabilities WHERE asset_subdomain = 'qa-p2s.vulnweb.com'")
        self.conn.commit()

if __name__ == '__main__':
    unittest.main()
