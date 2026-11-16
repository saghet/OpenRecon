<?php
/**
 * Auto-start helper for the FortiRecon / OpenRecon FastAPI backend (127.0.0.1:8000).
 * Ensures the Python engine starts transparently whenever XAMPP / the dashboard is used,
 * without requiring manual terminal commands.
 */
if (!function_exists('ensure_fastapi_backend_running')) {
    function ensure_fastapi_backend_running(bool $waitForReady = false, int $maxWaitMs = 6000): bool
    {
        $apiUrl = getenv('OPENRECON_API_URL') ?: 'http://127.0.0.1:8000';
        $parts = parse_url($apiUrl);
        $apiHost = $parts['host'] ?? '127.0.0.1';
        $apiPort = (int)($parts['port'] ?? 8000);

        $checkPort = static function () use ($apiHost, $apiPort): bool {
            $fp = @fsockopen($apiHost, $apiPort, $errno, $errstr, 0.15);
            if ($fp !== false) {
                @fclose($fp);
                return true;
            }
            return false;
        };

        if ($checkPort()) {
            return true;
        }

        if (getenv('OPENRECON_DOCKER_MODE') === 'true' || strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
            return false;
        }

        $vbsPath = 'C:\\Users\\saghe\\Documents\\FortiRecon\\backend\\start_backend_hidden.vbs';
        if (!file_exists($vbsPath)) {
            $vbsPath = realpath(__DIR__ . '/../backend/start_backend_hidden.vbs') ?: '';
        }
        if ($vbsPath === '' || !file_exists($vbsPath)) {
            return false;
        }

        $lockFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'openrecon_fastapi_boot.lock';
        $shouldLaunch = true;
        if (file_exists($lockFile) && (time() - (int)@filemtime($lockFile)) < 8) {
            $shouldLaunch = false;
        }

        if ($shouldLaunch) {
            @file_put_contents($lockFile, (string)time());
            if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
                $cmd = 'start "" /B wscript.exe //B //Nologo "' . $vbsPath . '"';
                $proc = @popen($cmd, 'r');
                if (is_resource($proc)) {
                    @pclose($proc);
                }
            }
        }

        if (!$waitForReady) {
            return false;
        }

        $deadline = microtime(true) + ($maxWaitMs / 1000.0);
        while (microtime(true) < $deadline) {
            usleep(250000);
            if ($checkPort()) {
                return true;
            }
        }
        return false;
    }
}
