#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ACROS AI — Clean Script
# Removes Docker volumes, dangling images, temp files, and caches
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "═══════════════════════════════════════════════════════════════"
echo "  ACROS AI — Cleanup"
echo "═══════════════════════════════════════════════════════════════"

# ── Python caches ───────────────────────────────────────────────────────────
echo "Cleaning Python caches..."
find "${REPO_ROOT}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${REPO_ROOT}" -name "*.pyc" -delete 2>/dev/null || true
find "${REPO_ROOT}" -name "*.pyo" -delete 2>/dev/null || true
find "${REPO_ROOT}" -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
echo "  ✓ Python caches cleaned"

# ── Node.js caches ──────────────────────────────────────────────────────────
echo "Cleaning Node.js caches..."
if [ -d "${REPO_ROOT}/frontend/node_modules/.cache" ]; then
    rm -rf "${REPO_ROOT}/frontend/node_modules/.cache"
fi
if [ -d "${REPO_ROOT}/frontend/.vite" ]; then
    rm -rf "${REPO_ROOT}/frontend/.vite"
fi
echo "  ✓ Node.js caches cleaned"

# ── Temp files ──────────────────────────────────────────────────────────────
echo "Cleaning temp files..."
find "${REPO_ROOT}" -name "*.log" -not -path "*/node_modules/*" -delete 2>/dev/null || true
find "${REPO_ROOT}" -name ".DS_Store" -delete 2>/dev/null || true
find "${REPO_ROOT}" -name "Thumbs.db" -delete 2>/dev/null || true
echo "  ✓ Temp files cleaned"

# ── Docker cleanup (optional, only if docker is available) ──────────────────
if command -v docker &>/dev/null; then
    echo "Cleaning Docker resources..."

    # Remove dangling images
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null || true)
    if [ -n "${dangling}" ]; then
        echo "  Removing dangling images..."
        docker rmi ${dangling} 2>/dev/null || true
    fi

    # Remove ACROS-specific stopped containers
    stopped=$(docker ps -a -f "name=acros-" -f "status=exited" -q 2>/dev/null || true)
    if [ -n "${stopped}" ]; then
        echo "  Removing stopped ACROS containers..."
        docker rm ${stopped} 2>/dev/null || true
    fi

    echo "  ✓ Docker resources cleaned"
else
    echo "  ⚠ Docker not found, skipping Docker cleanup"
fi

# ── Sandbox temp dirs ───────────────────────────────────────────────────────
echo "Cleaning sandbox temp directories..."
rm -rf /tmp/aegis_sandbox_* 2>/dev/null || true
rm -rf /tmp/aegis_uploads/* 2>/dev/null || true
rm -rf /tmp/aegis_reports/* 2>/dev/null || true
echo "  ✓ Sandbox temp dirs cleaned"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Cleanup complete"
echo "═══════════════════════════════════════════════════════════════"
