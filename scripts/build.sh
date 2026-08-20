#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ACROS — Build Script
# Builds all Docker images and tags with latest + git commit SHA
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="${DOCKER_REGISTRY:-forex911}"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo 'dev')"
TAG="${BUILD_TAG:-latest}"

echo "═══════════════════════════════════════════════════════════════"
echo "  ACROS — Docker Build"
echo "  Registry: ${REGISTRY}"
echo "  Tag:      ${TAG} + ${GIT_SHA}"
echo "═══════════════════════════════════════════════════════════════"

build_image() {
    local name="$1"
    local context="$2"
    local dockerfile="$3"

    echo ""
    echo "──── Building ${name} ────"
    docker build \
        -t "${REGISTRY}/${name}:${TAG}" \
        -t "${REGISTRY}/${name}:${GIT_SHA}" \
        -f "${dockerfile}" \
        "${context}"
    echo "✓ ${name} built successfully"
}

cd "${REPO_ROOT}"

# ── Backend ─────────────────────────────────────────────────────────────────
build_image "acros-backend" "." "./backend/Dockerfile"

# ── Frontend ────────────────────────────────────────────────────────────────
if [ -f "./frontend/Dockerfile" ]; then
    build_image "acros-frontend" "./frontend" "./frontend/Dockerfile"
fi

# ── Sandbox Runner ──────────────────────────────────────────────────────────
build_image "acros-sandbox-runner" "." "./sandbox/docker/Dockerfile.runner"

# ── Sandbox Python ──────────────────────────────────────────────────────────
build_image "acros-sandbox-python" "." "./sandbox/docker/Dockerfile.python"

# ── Sandbox Node ────────────────────────────────────────────────────────────
if [ -f "./sandbox/docker/Dockerfile.node" ]; then
    build_image "acros-sandbox-node" "." "./sandbox/docker/Dockerfile.node"
fi

# ── Sandbox APK ─────────────────────────────────────────────────────────────
build_image "acros-sandbox-apk" "." "./sandbox/docker/Dockerfile.apk"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ All images built successfully"
echo "  Images tagged: ${TAG}, ${GIT_SHA}"
echo "═══════════════════════════════════════════════════════════════"

# List built images
docker images --filter "reference=${REGISTRY}/acros-*" --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
