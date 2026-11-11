import unittest
import sqlite3
import subprocess
import json
import os

PHP_BIN = r'C:\xampp\php\php.exe'
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'openrecon.sqlite')
API_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'api.php')

class TestStage1SecurityAndPurity(unittest.TestCase):
    
    def setUp(self):
        self.assertTrue(os.path.exists(DB_PATH), f"Database not found at {DB_PATH}")
        self.assertTrue(os.path.exists(API_PATH), f"api.php not found at {API_PATH}")
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

    def test_01_no_fabricated_credential_leaks(self):
        """Verifica que no existan credenciales mock o colecciones inventadas en la base de datos."""
        count = self.cur.execute("""
            SELECT count(*) FROM credential_leaks 
            WHERE source_breach LIKE '%Collection #1%' OR source_breach LIKE '%Exploit.in%'
        """).fetchone()[0]
        self.assertEqual(count, 0, f"Se encontraron {count} credenciales fabricadas en la base de datos.")

    def test_02_no_fabricated_ransomware_leaks(self):
        """Verifica que no existan las 12 víctimas inventadas o URLs .onion falsas."""
        count = self.cur.execute("""
            SELECT count(*) FROM ransomware_leaks 
            WHERE is_simulation = 1 OR claim_url LIKE '%...onion%' OR victim_name LIKE '%Testing Labs%'
        """).fetchone()[0]
        self.assertEqual(count, 0, f"Se encontraron {count} registros simulados de ransomware.")

    def test_03_no_fabricated_drp_testnet_threats(self):
        """Verifica que no existan dominios clones con IPs de laboratorios RFC 5737."""
        count = self.cur.execute("""
            SELECT count(*) FROM drp_threats 
            WHERE ip_address IN ('198.51.100.42', '203.0.113.15', '192.0.2.88', '198.51.100.77', '203.0.113.91')
        """).fetchone()[0]
        self.assertEqual(count, 0, f"Se encontraron {count} amenazas DRP falsas con IPs reservadas de testnet.")

    def test_04_no_arbitrary_threat_ioc_modulo_attribution(self):
        """Verifica que los IoCs de IPsum no tengan familias arbitrarias asignadas por rotación."""
        count = self.cur.execute("""
            SELECT count(*) FROM threat_iocs 
            WHERE malware_family IN ('Infostealer Drop C2', 'Ransomware Loader', 'AsyncRAT Controller', 'QakBot Node', 'RedLine Stealer Gate')
        """).fetchone()[0]
        self.assertEqual(count, 0, f"Se encontraron {count} IoCs con atribución arbitraria de familias.")

    def test_05_schema_integrity_and_cve_column(self):
        """Verifica la existencia de authorized_scope, users, audit_logs y cve_id en vulnerabilities."""
        tables = [t[0] for t in self.cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        self.assertIn('authorized_scope', tables)
        self.assertIn('users', tables)
        self.assertIn('audit_logs', tables)
        self.assertIn('vulnerabilities', tables)

        vuln_cols = [c[1] for c in self.cur.execute("PRAGMA table_info(vulnerabilities)").fetchall()]
        self.assertIn('cve_id', vuln_cols, "Falta la columna 'cve_id' en la tabla 'vulnerabilities' (Bug C7).")

    def test_06_cve_persistence_functional_test(self):
        """Prueba de inserción y lectura de un hallazgo CVE en vulnerabilities."""
        test_host = 'qa-cve-test.vulnweb.com'
        self.cur.execute("""
            INSERT OR REPLACE INTO vulnerabilities (asset_subdomain, title, severity, cve_id, description, status)
            VALUES (?, 'PHP2Shell CVE Test', 'CRITICAL', 'CVE-2026-109618', 'Verificación de persistencia C7', 'OPEN')
        """, (test_host,))
        self.conn.commit()

        row = self.cur.execute("SELECT cve_id, status FROM vulnerabilities WHERE asset_subdomain = ?", (test_host,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'CVE-2026-109618')
        self.assertEqual(row[1], 'OPEN')

        # Limpiar
        self.cur.execute("DELETE FROM vulnerabilities WHERE asset_subdomain = ?", (test_host,))
        self.conn.commit()

    def test_07_scope_and_ssrf_enforcement_out_of_scope(self):
        """Verifica que objetivos fuera del alcance autorizado sean bloqueados."""
        resp = self.call_php_api('php2shell_scan', {'target': 'unauthorized-target-domain-999.com'}, 'POST')
        self.assertFalse(resp.get('success', True))
        self.assertIn('Control de Alcance', resp.get('error', ''))

    def test_08_scope_and_ssrf_enforcement_private_ip(self):
        """Verifica que direcciones IP privadas/reservadas (ej. metadata AWS 169.254.169.254) sean bloqueadas."""
        resp = self.call_php_api('php2shell_scan', {'target': '169.254.169.254'}, 'POST')
        self.assertFalse(resp.get('success', True))
        self.assertTrue('Control de Alcance' in resp.get('error', '') or 'Protección Anti-SSRF' in resp.get('error', ''))

    def test_09_csirt_advisory_no_fabricated_phone_or_pgp(self):
        """Verifica que el generador de avisos CSIRT no emita teléfonos o huellas PGP inventadas."""
        resp = self.call_php_api('generate_cti_advisory', {'victim_name': 'Acme Corporation'}, 'POST')
        self.assertTrue(resp.get('success', False))
        payload_str = json.dumps(resp)
        self.assertNotIn('+57 (601) 800-FORTI', payload_str, "El aviso CSIRT aún contiene el teléfono simulado.")
        self.assertNotIn('0x9F41E7A23C89B01F', payload_str, "El aviso CSIRT aún contiene la huella PGP simulada.")

    def test_10_cors_hardening(self):
        """Verifica que api.php no tenga CORS abierto con comodín universal '*'."""
        with open(API_PATH, 'r', encoding='utf-8') as f:
            code = f.read()
        self.assertNotIn("header('Access-Control-Allow-Origin: *');", code, "api.php todavía tiene CORS abierto con comodín (*).")

if __name__ == '__main__':
    unittest.main()
