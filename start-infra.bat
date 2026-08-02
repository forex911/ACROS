@echo off
title Aegis - Infrastructure Launcher
cd /d "%~dp0"

echo.
echo =========================================
echo   Aegis - Starting Local Infrastructure
echo =========================================
echo.

docker compose up -d mongodb redis neo4j minio
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to start Docker services. Make sure Docker Desktop is running.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [+] Waiting 5 seconds for services to initialize...
timeout /t 5 /nobreak >nul

echo.
echo =========================================
echo   Infrastructure is running:
echo -----------------------------------------
echo   MongoDB  ^> localhost:27017
echo   Redis    ^> localhost:6379
echo   Neo4j    ^> localhost:7474 (bolt: 7687)
echo   MinIO    ^> localhost:9001 (api: 9000)
echo =========================================
echo.
pause
