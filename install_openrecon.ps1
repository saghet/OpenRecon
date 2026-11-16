<#
.SYNOPSIS
    Instalador integral de OpenRecon 3.0 para Windows (incluye último XAMPP 8.2, Python venv,
    dependencias del backend, migraciones Alembic y herramientas opcionales de reconocimiento).
.DESCRIPTION
    Automatiza la puesta en marcha de OpenRecon 3.0 sin requerir ejecución como root/SYSTEM en runtime:
      1. Verifica / instala XAMPP 8.2 (ApacheFriends.Xampp.8.2) vía winget.
      2. Verifica / instala Python 3.12 vía winget, crea backend\venv e instala requirements.txt.
      3. Configura .env desde .env.example y ejecuta migraciones Alembic.
      4. Enlaza web_dashboard en C:\xampp\htdocs\openrecon (Junction) para acceso inmediato vía Apache.
      5. (Opcional -WithSecurityTools) Instala Go y binarios fijados de ProjectDiscovery / WebCopilotAdapter
         (subfinder, dnsx, httpx, naabu, nuclei, gau, waybackurls, kxss, dalfox).
      6. Ejecuta verificación de seguridad (tests/security).
#>
[CmdletBinding()]
param(
    [switch]$WithSecurityTools,
    [switch]$SkipXampp,
    [switch]$SkipTests,
    [string]$XamppPath = "C:\xampp"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RepoRoot "backend"
$VenvDir = Join-Path $BackendDir "venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OpenRecon 3.0 - Instalador Integral (Windows + XAMPP 8.2) " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

function Test-CommandExists($cmd) {
    return $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

# 1. XAMPP 8.2 (última versión disponible en winget: ApacheFriends.Xampp.8.2)
if (-not $SkipXampp) {
    if (Test-Path (Join-Path $XamppPath "apache\bin\httpd.exe")) {
        Write-Host "[OK] XAMPP detectado en $XamppPath" -ForegroundColor Green
    } else {
        if (-not (Test-CommandExists "winget")) {
            Write-Warning "winget no está disponible. Descarga XAMPP 8.2 manualmente desde https://www.apachefriends.org/download.html"
        } else {
            Write-Host "[*] Instalando último XAMPP 8.2 (ApacheFriends.Xampp.8.2) vía winget..." -ForegroundColor Yellow
            winget install --id ApacheFriends.Xampp.8.2 --exact --accept-source-agreements --accept-package-agreements
        }
    }

    # Enlazar web_dashboard en htdocs\openrecon si existe C:\xampp\htdocs
    $HtdocsDir = Join-Path $XamppPath "htdocs"
    $TargetWebLink = Join-Path $HtdocsDir "openrecon"
    $SourceWebDir = Join-Path $RepoRoot "web_dashboard"
    if (Test-Path $HtdocsDir) {
        if (-not (Test-Path $TargetWebLink)) {
            Write-Host "[*] Creando enlace Junction: $TargetWebLink -> $SourceWebDir" -ForegroundColor Yellow
            New-Item -ItemType Junction -Path $TargetWebLink -Target $SourceWebDir | Out-Null
            Write-Host "[OK] Dashboard accesible en http://localhost/openrecon/ (cuando Apache esté iniciado)" -ForegroundColor Green
        } else {
            Write-Host "[OK] Enlace $TargetWebLink ya existe." -ForegroundColor Green
        }
    }
}

# 2. Python 3.11+ y entorno virtual
$PythonCmd = $null
if (Test-CommandExists "python") {
    $PythonCmd = "python"
} elseif (Test-CommandExists "py") {
    $PythonCmd = "py"
}

if (-not $PythonCmd) {
    if (Test-CommandExists "winget") {
        Write-Host "[*] Instalando Python 3.12 vía winget..." -ForegroundColor Yellow
        winget install --id Python.Python.3.12 --exact --accept-source-agreements --accept-package-agreements
        $PythonCmd = "python"
    } else {
        throw "Python 3.11+ es requerido y no se encontró winget."
    }
}

if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Creando entorno virtual en $VenvDir..." -ForegroundColor Yellow
    & $PythonCmd -m venv $VenvDir
} else {
    Write-Host "[OK] Entorno virtual existente en $VenvDir" -ForegroundColor Green
}

Write-Host "[*] Actualizando pip e instalando dependencias de backend\requirements.txt..." -ForegroundColor Yellow
& $VenvPython -m pip install --upgrade pip
& $VenvPip install -r (Join-Path $BackendDir "requirements.txt")
& $VenvPip install "dnstwist==20240116"

# 3. Configuración .env y Migraciones Alembic
$EnvFile = Join-Path $RepoRoot ".env"
$EnvExample = Join-Path $RepoRoot ".env.example"
if (-not (Test-Path $EnvFile) -and (Test-Path $EnvExample)) {
    Copy-Item $EnvExample $EnvFile
    Write-Host "[OK] Archivo .env creado desde .env.example" -ForegroundColor Green
}

$BackendEnv = Join-Path $BackendDir ".env"
if (-not (Test-Path $BackendEnv) -and (Test-Path $EnvFile)) {
    Copy-Item $EnvFile $BackendEnv
}

Write-Host "[*] Ejecutando migraciones Alembic..." -ForegroundColor Yellow
Push-Location $BackendDir
try {
    & $VenvPython -m alembic upgrade head
    Write-Host "[OK] Esquema de base de datos actualizado (Alembic)." -ForegroundColor Green
} finally {
    Pop-Location
}

# 4. Herramientas opcionales de reconocimiento (Go + ProjectDiscovery + WebCopilotAdapter)
if ($WithSecurityTools) {
    if (-not (Test-CommandExists "go") -and (Test-CommandExists "winget")) {
        Write-Host "[*] Instalando Go (GoLang.Go) para herramientas de reconocimiento..." -ForegroundColor Yellow
        winget install --id GoLang.Go --exact --accept-source-agreements --accept-package-agreements
    }
    if (Test-CommandExists "go") {
        $GoTools = @(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1",
            "github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0",
            "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1",
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.4",
            "github.com/lc/gau/v2/cmd/gau@v2.2.3",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/Emoe/kxss@latest",
            "github.com/hahwul/dalfox/v2@v2.9.2"
        )
        foreach ($pkg in $GoTools) {
            Write-Host "[*] go install $pkg" -ForegroundColor Cyan
            go install -v $pkg
        }
    } else {
        Write-Warning "Go no detectado en PATH; se omite instalación de binarios Go. OpenRecon funcionará con fallbacks Python nativos."
    }
}

# 5. Verificación de seguridad post-instalación
if (-not $SkipTests) {
    Write-Host "[*] Ejecutando suite de verificación de seguridad..." -ForegroundColor Yellow
    Push-Location $RepoRoot
    try {
        & $VenvPython -m unittest discover -s tests/security -v
        Write-Host "[OK] Verificación de seguridad superada." -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "Instalación completada." -ForegroundColor Green
Write-Host "  1) Inicia Apache desde XAMPP Control Panel ($XamppPath\xampp-control.exe)." -ForegroundColor White
Write-Host "  2) Inicia el backend FastAPI con: .\run_backend.bat  (o python run_dev.py)" -ForegroundColor White
Write-Host "  3) Abre el Dashboard SOC en: http://localhost/openrecon/  y Swagger en http://127.0.0.1:8000/docs" -ForegroundColor White
