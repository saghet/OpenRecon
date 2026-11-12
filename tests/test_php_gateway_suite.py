"""
Automated Test Runner for PHP API Gateway: Email Intelligence
Invokes each action in an isolated PHP subprocess to test routing, headers, JSON serialization, and database access.
"""

import unittest
import subprocess
import json
import os

PHP_EXE = r"C:\xampp\php\php.exe"
API_PATH = os.path.abspath("web_dashboard/api.php")


class TestPhpApiGatewayEmailIntel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PHP_EXE):
            raise unittest.SkipTest("PHP executable not found at C:\\xampp\\php\\php.exe")

    def _call_api(self, get_params=None, post_params=None):
        get_params = get_params or {}
        post_params = post_params or {}

        setup_code = ""
        for k, v in get_params.items():
            setup_code += f"$_GET['{k}'] = '{v}';\n"
        for k, v in post_params.items():
            setup_code += f"$_POST['{k}'] = '{v}';\n"
        setup_code += f"ob_start();\nrequire '{API_PATH.replace(chr(92), '/')}';\n$out = ob_get_clean();\necho $out;\n"

        proc = subprocess.run(
            [PHP_EXE, "-r", setup_code],
            capture_output=True,
            text=True
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    def test_01_email_intel_list(self):
        code, stdout, stderr = self._call_api(get_params={"action": "email_intel_list"})
        self.assertEqual(code, 0, f"PHP error: {stderr}")
        data = json.loads(stdout)
        self.assertEqual(data.get("status"), "ok")
        self.assertIn("investigations", data)
        self.assertTrue(len(data["investigations"]) > 0)

    def test_02_email_intel_get_existing(self):
        # Fetch list first to get an ID
        _, stdout, _ = self._call_api(get_params={"action": "email_intel_list"})
        data = json.loads(stdout)
        inv_id = data["investigations"][0]["id"]

        code, stdout, stderr = self._call_api(get_params={"action": "email_intel_get", "id": inv_id})
        self.assertEqual(code, 0, f"PHP error: {stderr}")
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "ok")
        self.assertIn("investigation", res)
        inv = res["investigation"]
        self.assertEqual(inv["id"], inv_id)
        self.assertIn("leaks", inv)
        self.assertIn("accounts", inv)

    def test_03_email_intel_graph(self):
        _, stdout, _ = self._call_api(get_params={"action": "email_intel_list"})
        data = json.loads(stdout)
        inv_id = data["investigations"][0]["id"]

        code, stdout, stderr = self._call_api(get_params={"action": "email_intel_graph", "id": inv_id})
        self.assertEqual(code, 0, f"PHP error: {stderr}")
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "ok")
        self.assertIn("nodes", res)
        self.assertIn("edges", res)
        self.assertTrue(len(res["nodes"]) > 0)

    def test_04_email_intel_correlate_ioc(self):
        _, stdout, _ = self._call_api(get_params={"action": "email_intel_list"})
        data = json.loads(stdout)
        inv_id = data["investigations"][0]["id"]

        code, stdout, stderr = self._call_api(get_params={"action": "email_intel_correlate_ioc"}, post_params={"id": inv_id})
        self.assertEqual(code, 0, f"PHP error: {stderr}")
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "ok")
        self.assertIn("correlacionado como IoC", res.get("message", ""))

    def test_05_email_intel_validation_rejection(self):
        code, stdout, stderr = self._call_api(
            get_params={"action": "email_intel_start"},
            post_params={"target_email": "invalid-syntax", "case_id": "CASE-1", "title": "Test", "authorization_justification": "RoE"}
        )
        self.assertEqual(code, 0)
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "error")
        self.assertIn("inválida según RFC 5322", res.get("message", ""))

    def test_06_email_intel_anti_ssrf_rejection(self):
        code, stdout, stderr = self._call_api(
            get_params={"action": "email_intel_start"},
            post_params={"target_email": "security@corp.local", "case_id": "CASE-1", "title": "Test", "authorization_justification": "RoE"}
        )
        self.assertEqual(code, 0)
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "error")
        self.assertIn("anti-SSRF", res.get("message", ""))

    def test_07_email_intel_evidence_vault_listing(self):
        """Verify that email_intel_get returns evidence vault records with proper forensic aliasing."""
        code, stdout, stderr = self._call_api(
            get_params={"action": "email_intel_get", "id": "EI-20261112-2ABB2B"}
        )
        self.assertEqual(code, 0)
        res = json.loads(stdout)
        self.assertEqual(res.get("status"), "ok")
        inv = res.get("investigation", {})
        self.assertIn("evidences", inv)
        evidences = inv["evidences"]
        self.assertIsInstance(evidences, list)
        if len(evidences) > 0:
            ev = evidences[0]
            self.assertIn("raw_sha256", ev)
            self.assertIn("source", ev)
            self.assertIn("evidence_type", ev)


if __name__ == "__main__":
    unittest.main()
