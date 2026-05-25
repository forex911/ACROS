"""
Celery client — enqueue sandbox tasks by name.

The API server uses ``send_task`` to dispatch jobs without importing the
worker module.  Workers expose the task ``worker.run_sandbox_job`` which
expects a presigned URL to download the artifact from MinIO/S3.
"""

import os
import logging
from celery import Celery

logger = logging.getLogger("celery_client")

BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')

celery_app = Celery(
    'sentinel',
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
)

# Production-grade Celery configuration
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    result_expires=3600,            # expire results after 1 hour
    task_acks_late=True,            # ack after execution for crash safety
    worker_prefetch_multiplier=1,   # prevent task starvation
    task_reject_on_worker_lost=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)


def enqueue_sandbox_job(
    job_id: str,
    presigned_url: str,
    image: str = 'ghcr.io/sentinel-ai/sandbox-runner:latest',
    timeout: int = 120,
) -> object:
    """
    Enqueue a sandbox job.  The worker downloads the artifact from the
    presigned URL — no local filesystem path assumptions.

    Returns the Celery AsyncResult.
    """
    task_name = 'worker.run_sandbox_job'

    result = celery_app.send_task(
        task_name,
        args=[job_id, presigned_url, image, timeout],
        # Propagate OpenTelemetry trace context for distributed tracing
        headers={
            'sentinel_job_id': job_id,
        },
    )

    logger.info("Enqueued task %s for job %s", result.id, job_id)
    return result
