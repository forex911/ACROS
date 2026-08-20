#!/usr/bin/env bash
set -e

echo "[+] Starting ACROS Local Infrastructure..."
docker compose up -d mongodb redis neo4j minio

echo "[+] Waiting for services to initialize..."
sleep 10

echo "--------------------------------------------------------"
echo "✅ Infrastructure is running."
echo "MongoDB:  localhost:27017"
echo "Redis:    localhost:6379"
echo "Neo4j:    localhost:7474 (bolt: 7687)"
echo "MinIO:    localhost:9001 (api: 9000)"
echo "--------------------------------------------------------"
echo ""
echo "To start the backend:"
echo "  cd backend"
echo "  python -m uvicorn app.main:app --port 8000 --reload"
echo ""
echo "To start the frontend:"
echo "  cd frontend"
echo "  npm run dev"
