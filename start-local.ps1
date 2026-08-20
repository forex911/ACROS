Write-Host "[+] Starting ACROS Local Infrastructure..." -ForegroundColor Cyan
docker compose up -d mongodb redis neo4j minio

Write-Host "[+] Waiting for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host "--------------------------------------------------------"
Write-Host "✅ Infrastructure is running." -ForegroundColor Green
Write-Host "MongoDB:  localhost:27017"
Write-Host "Redis:    localhost:6379"
Write-Host "Neo4j:    localhost:7474 (bolt: 7687)"
Write-Host "MinIO:    localhost:9001 (api: 9000)"
Write-Host "--------------------------------------------------------"
Write-Host ""
Write-Host "To start the backend:"
Write-Host "  cd backend"
Write-Host "  python -m uvicorn app.main:app --port 8000 --reload"
Write-Host ""
Write-Host "To start the frontend:"
Write-Host "  cd frontend"
Write-Host "  npm run dev"
