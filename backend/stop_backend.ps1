$ErrorActionPreference = "SilentlyContinue"
$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -like "*run_server.py*"
}
foreach ($p in $procs) {
    Stop-Process -Id $p.ProcessId -Force
}
exit 0
