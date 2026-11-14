$ErrorActionPreference = "SilentlyContinue"
$backendDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = Join-Path $backendDir "venv\Scripts\pythonw.exe"
$python = Join-Path $backendDir "venv\Scripts\python.exe"
$runner = Join-Path $backendDir "run_server.py"
$logDir = Join-Path $backendDir "logs"

# 1. Fast check if port 8000 is already listening (idempotent)
$tcp = New-Object System.Net.Sockets.TcpClient
try {
    $iar = $tcp.BeginConnect("127.0.0.1", 8000, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(150, $false)
    if ($ok -and $tcp.Connected) {
        $tcp.EndConnect($iar)
        $tcp.Close()
        exit 0
    }
} catch {
} finally {
    $tcp.Close()
}

# 2. Avoid duplicate launch if run_server.py process already exists
$existing = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -like "*run_server.py*"
}
if ($existing) {
    exit 0
}

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$exe = if (Test-Path $pythonw) { $pythonw } else { $python }
Start-Process -FilePath $exe -ArgumentList "`"$runner`"" -WorkingDirectory $backendDir -WindowStyle Hidden
exit 0
