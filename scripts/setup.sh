#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ACROS — First-Time Setup Script
# Installs Python/Node dependencies, creates .env, and initializes services
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "═══════════════════════════════════════════════════════════════"
echo "  ACROS — First-Time Setup"
echo "═══════════════════════════════════════════════════════════════"

# ── Check prerequisites ─────────────────────────────────────────────────────
echo ""
echo "──── Checking prerequisites ────"

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo "  ✓ $1 found: $(command -v "$1")"
        return 0
    else
        echo "  ✗ $1 not found"
        return 1
    fi
}

check_cmd python3 || check_cmd python || { echo "ERROR: Python 3 is required"; exit 1; }
check_cmd pip3 || check_cmd pip || echo "  ⚠ pip not found (will try with python -m pip)"
check_cmd node || echo "  ⚠ Node.js not found (frontend will not build)"
check_cmd npm || echo "  ⚠ npm not found (frontend will not build)"
check_cmd docker || echo "  ⚠ Docker not found (containers will not build)"
check_cmd git || echo "  ⚠ Git not found"

# ── Python backend setup ────────────────────────────────────────────────────
echo ""
echo "──── Setting up Python backend ────"

cd "${REPO_ROOT}/backend"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv venv || python -m venv venv
fi

# Activate venv and install dependencies
echo "  Installing Python dependencies..."
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi

pip install --no-cache-dir -r requirements.txt 2>/dev/null || \
    python -m pip install --no-cache-dir -r requirements.txt

echo "  ✓ Python dependencies installed"

# ── Frontend setup ──────────────────────────────────────────────────────────
echo ""
echo "──── Setting up frontend ────"

cd "${REPO_ROOT}/frontend"

if command -v npm &>/dev/null && [ -f "package.json" ]; then
    echo "  Installing Node.js dependencies..."
    npm install
    echo "  ✓ Frontend dependencies installed"
else
    echo "  ⚠ Skipping frontend setup (npm or package.json not found)"
fi

# ── Create .env file ────────────────────────────────────────────────────────
echo ""
echo "──── Creating environment file ────"

cd "${REPO_ROOT}"

if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# ─────────────────────────────────────────────────────────────────
# ACROS — Environment Configuration
# ─────────────────────────────────────────────────────────────────

# Backend
MONGO_URI=mongodb://localhost:27017
DATABASE_NAME=sentinel_ai
REDIS_URL=redis://localhost:6379
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=test1234

# Object Storage (MinIO)
S3_ENDPOINT=http://localhost:9000
S3_ACCESS_KEY=minioadmin
S3_SECRET_KEY=minioadmin
S3_BUCKET=uploads
S3_USE_SSL=false

# Security
SECRET_KEY=acros-dev-secret-key-change-in-production-32chars
ENVIRONMENT=development

# Sandbox
SANDBOX_MODE=mock
EOF
    echo "  ✓ .env file created"
else
    echo "  .env file already exists, skipping"
fi

# ── Start infrastructure services ──────────────────────────────────────────
echo ""
echo "──── Infrastructure services ────"

if command -v docker &>/dev/null; then
    echo "  Starting Docker infrastructure (MongoDB, Redis, Neo4j, MinIO)..."
    cd "${REPO_ROOT}"
    docker compose up -d mongodb redis neo4j minio 2>/dev/null || \
        docker-compose up -d mongodb redis neo4j minio 2>/dev/null || \
        echo "  ⚠ Could not start Docker services (run 'docker compose up -d' manually)"
    echo "  ✓ Infrastructure services started"
else
    echo "  ⚠ Docker not available — start infrastructure services manually"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Setup complete!"
echo ""
echo "  To start the backend:    cd backend && uvicorn app.main:app --reload"
echo "  To start the frontend:   cd frontend && npm run dev"
echo "  To start everything:     docker compose up -d"
echo "═══════════════════════════════════════════════════════════════"
