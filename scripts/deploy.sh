#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ACROS — Deploy Script
# Pushes Docker images to Docker Hub and optionally applies K8s manifests
# Usage: ./deploy.sh [--env staging|production] [--skip-push] [--skip-k8s]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REGISTRY="${DOCKER_REGISTRY:-forex911}"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo 'dev')"
ENVIRONMENT="staging"
SKIP_PUSH=false
SKIP_K8S=false

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --skip-push)
            SKIP_PUSH=true
            shift
            ;;
        --skip-k8s)
            SKIP_K8S=true
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: ./deploy.sh [--env staging|production] [--skip-push] [--skip-k8s]"
            exit 1
            ;;
    esac
done

echo "═══════════════════════════════════════════════════════════════"
echo "  ACROS — Deploy"
echo "  Environment: ${ENVIRONMENT}"
echo "  Registry:    ${REGISTRY}"
echo "  Git SHA:     ${GIT_SHA}"
echo "═══════════════════════════════════════════════════════════════"

# ── Validate environment ────────────────────────────────────────────────────
if [[ "${ENVIRONMENT}" != "staging" && "${ENVIRONMENT}" != "production" ]]; then
    echo "ERROR: Invalid environment '${ENVIRONMENT}'. Must be 'staging' or 'production'."
    exit 1
fi

# ── Build images first ──────────────────────────────────────────────────────
echo ""
echo "──── Building images ────"
bash "${REPO_ROOT}/scripts/build.sh"

# ── Push to Docker Hub ──────────────────────────────────────────────────────
if [ "${SKIP_PUSH}" = false ]; then
    echo ""
    echo "──── Pushing images to Docker Hub ────"

    IMAGES=(
        "acros-backend"
        "acros-frontend"
        "acros-sandbox-runner"
        "acros-sandbox-python"
        "acros-sandbox-node"
        "acros-sandbox-apk"
    )

    for image in "${IMAGES[@]}"; do
        full_name="${REGISTRY}/${image}"

        # Check if image exists locally
        if docker image inspect "${full_name}:latest" &>/dev/null; then
            echo "  Pushing ${full_name}:latest..."
            docker push "${full_name}:latest"

            echo "  Pushing ${full_name}:${GIT_SHA}..."
            docker push "${full_name}:${GIT_SHA}"

            echo "  ✓ ${image} pushed"
        else
            echo "  ⚠ ${image} not found locally, skipping"
        fi
    done

    echo "  ✓ All images pushed"
else
    echo "  ⚠ Skipping Docker push (--skip-push)"
fi

# ── Apply Kubernetes manifests ──────────────────────────────────────────────
if [ "${SKIP_K8S}" = false ]; then
    echo ""
    echo "──── Applying Kubernetes manifests ────"

    K8S_DIR="${REPO_ROOT}/deployment/k8s"
    NAMESPACE="acros-${ENVIRONMENT}"

    if [ -d "${K8S_DIR}" ] && command -v kubectl &>/dev/null; then
        # Create namespace if it doesn't exist
        kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

        # Apply manifests
        if [ -d "${K8S_DIR}/base" ]; then
            echo "  Applying base manifests..."
            kubectl apply -f "${K8S_DIR}/base/" -n "${NAMESPACE}" || true
        fi

        if [ -d "${K8S_DIR}/${ENVIRONMENT}" ]; then
            echo "  Applying ${ENVIRONMENT} overlays..."
            kubectl apply -f "${K8S_DIR}/${ENVIRONMENT}/" -n "${NAMESPACE}" || true
        fi

        # Update image tags
        echo "  Updating deployment images to ${GIT_SHA}..."
        kubectl set image deployment/acros-backend \
            acros-backend="${REGISTRY}/acros-backend:${GIT_SHA}" \
            -n "${NAMESPACE}" 2>/dev/null || true

        echo "  ✓ Kubernetes manifests applied"
    else
        echo "  ⚠ K8s manifests or kubectl not found, skipping"
    fi
else
    echo "  ⚠ Skipping Kubernetes deployment (--skip-k8s)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Deploy complete"
echo "  Environment: ${ENVIRONMENT}"
echo "  Git SHA:     ${GIT_SHA}"
echo "═══════════════════════════════════════════════════════════════"
