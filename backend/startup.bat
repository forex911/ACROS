@echo off
title Aegis - Backend
cd /d "%~dp0"

echo Starting Aegis Backend (FastAPI on :8000)...
if exist "venv\Scripts\python.exe" (
    venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
) else (
    python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
)
pause