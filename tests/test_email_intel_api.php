<?php
/**
 * PHP API Gateway Test Suite Wrapper for Email Intelligence
 */
$pythonCmd = 'backend\\venv\\Scripts\\python.exe -m unittest tests/test_php_gateway_suite.py';
if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
    $pythonCmd = 'python3 -m unittest tests/test_php_gateway_suite.py';
}

echo "Executing PHP API Gateway Automated Suite via Isolated Subprocesses...\n";
passthru($pythonCmd, $returnCode);
exit($returnCode);
