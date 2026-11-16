@echo off
setlocal
echo ============================================================
echo   OpenRecon 3.0 - Lanzador de Instalacion (Windows + XAMPP)
echo ============================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_openrecon.ps1" %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] La instalacion finalizo con codigo %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)
echo.
pause
