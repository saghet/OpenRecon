import unittest
import sqlite3
import subprocess
import json
import os

PHP_BIN = r'C:\xampp\php\php.exe'
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'openrecon.sqlite')
API_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'api.php')
INDEX_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'index.php')
REPORT_PATH = os.path.join(os.path.dirname(__file__), '..', 'web_dashboard', 'report.php')

class TestStage3EnterpriseModules(unittest.TestCase):
    
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

    def test_01_cloud_exposure_backend(self):
        """Verifica tabla de exposición cloud y respuesta del endpoint get_cloud_exposure."""
        resp = self.call_php_api('get_cloud_exposure')
        self.assertTrue(resp.get('success', False))
        self.assertIn('exposures', resp)

    def test_02_scheduled_monitors_backend(self):
        """Verifica monitoreo programado de dominios y tabla de diffs de infraestructura."""
        resp = self.call_php_api('get_monitors')
        self.assertTrue(resp.get('success', False))
        monitors = resp.get('monitors', [])
        self.assertGreater(len(monitors), 0)
        self.assertIn('frequency_hours', monitors[0])

    def test_03_ai_correlation_report_grounding(self):
        """Verifica que el informe de correlación con IA se genere con citas a evidencias y MITRE ATT&CK."""
        resp = self.call_php_api('ai_correlate_evidence', {'seed': 'vulnweb.com'})
        self.assertTrue(resp.get('success', False))
        report_md = resp.get('report_markdown', '')
        self.assertIn('INFORME DE CORRELACIÓN CTI', report_md)
        self.assertIn('MITRE ATT&CK', report_md)
        self.assertIn('vulnweb.com', report_md)

    def test_04_ui_elements_in_dashboard(self):
        """Verifica que index.php contenga las pestañas y modales de la Fase 3."""
        with open(INDEX_PATH, 'r', encoding='utf-8') as f:
            html = f.read()

        self.assertIn('tab-btn-connectors', html)
        self.assertIn('tab-content-connectors', html)
        self.assertIn('tab-btn-scope', html)
        self.assertIn('tab-content-scope', html)
        self.assertIn('tab-btn-cloud', html)
        self.assertIn('tab-content-cloud', html)
        self.assertIn('tab-btn-ai', html)
        self.assertIn('tab-content-ai', html)
        self.assertIn('risk-breakdown-modal', html)
        self.assertIn('connector-config-modal', html)

    def test_05_report_php_renders_with_cti_columns(self):
        """Verifica que report.php compile sin errores y renderice las columnas de validación y CTI."""
        res = subprocess.run([PHP_BIN, '-l', REPORT_PATH], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn('No syntax errors detected', res.stdout)

        with open(REPORT_PATH, 'r', encoding='utf-8') as f:
            code = f.read()
        self.assertIn('Validación & CTI', code)

if __name__ == '__main__':
    unittest.main()
