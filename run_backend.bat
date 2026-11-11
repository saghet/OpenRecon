@echo off
title FortiRecon / OpenRecon Enterprise Backend (FastAPI Engine)
echo ==================================================================
echo   Iniciando Motor Asincrono FastAPI de FortiRecon / OpenRecon
echo ==================================================================
if exist backend\venv\Scripts\python.exe (
    backend\venv\Scripts\python.exe backend\run_server.py
) else (
    python backend\run_server.py
)
pause
