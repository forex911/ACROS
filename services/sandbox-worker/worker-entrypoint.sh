#!/bin/sh
set -e

# Simple entrypoint to start Celery worker. Configure via environment variables:
# - CELERY_BROKER_URL (e.g. redis://redis:6379/0)
# - CELERY_LOG_LEVEL

: ${CELERY_BROKER_URL:=redis://localhost:6379/0}
: ${CELERY_LOG_LEVEL:=INFO}

echo "Starting Celery worker (broker=${CELERY_BROKER_URL})"
exec celery -A worker.celery_app worker --loglevel=${CELERY_LOG_LEVEL} --concurrency=1
