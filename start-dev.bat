@echo off
title ACROS-AI Dev Launcher

echo.
echo  =========================================
echo    ACROS-AI - Starting Dev Environment
echo  =========================================
echo.

:: Change to the script's directory (works when double-clicked)
cd /d "%~dp0"

:: Start Backend in a new window
echo [1/2] Starting Backend (FastAPI on :8000)...
start "ACROS - Backend" cmd /k "cd /d "%~dp0backend" && (if exist "venv\Scripts\python.exe" (venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000) else (python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000))"

:: Small delay
timeout /t 2 /nobreak >nul

:: Start Frontend in a new window
echo [2/2] Starting Frontend (Vite on :5173)...
start "ACROS - Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo  =========================================
echo   Both servers are starting up!
echo  -----------------------------------------
echo   Backend  ^>  http://localhost:8000
echo   API Docs ^>  http://localhost:8000/docs
echo   Frontend ^>  http://localhost:5173
echo  =========================================
echo.
pause
