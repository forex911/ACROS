"""
Sandbox service — orchestrates malware execution via Kubernetes Jobs.

This module is the single entry point for sandbox lifecycle management.
It delegates container execution to the Kubernetes Job Manager, which
creates isolated, gVisor-hardened pods in the ``sentinel-sandbox`` namespace.

NO Docker socket access is used.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.services.kubernetes_job_manager import (
    create_sandbox_job,
    get_job_status,
    get_pod_logs,
    delete_sandbox_job,
)

logger = logging.getLogger("sandbox_service")


def enqueue_sandbox(
    file_record: dict,
    presigned_url: str,
    image: str = "ghcr.io/sentinel-ai/sandbox-runner:latest",
    timeout: int = 120,
) -> Dict[str, Any]:
    """
    Submit a malware sample for sandboxed analysis.

    The worker downloads the artifact from the ``presigned_url`` inside
    a memory-backed init container — the API server never passes local
    filesystem paths to distributed workers.

    Returns the Kubernetes Job metadata (job_name, namespace, uid).
    """
    job_id = file_record["file_id"]

    logger.info(
        "Submitting sandbox job %s (image=%s, timeout=%ds)",
        job_id, image, timeout,
    )

    job_meta = create_sandbox_job(
        job_id=job_id,
        artifact_presigned_url=presigned_url,
        image=image,
        timeout=timeout,
    )

    logger.info("Sandbox Job %s created → K8s Job %s", job_id, job_meta["job_name"])
    return job_meta


def poll_sandbox_status(job_name: str) -> Dict[str, Any]:
    """Query the completion state of a running sandbox Job."""
    return get_job_status(job_name)


def retrieve_sandbox_logs(job_name: str) -> str:
    """Retrieve stdout/stderr from the sandbox execution container."""
    return get_pod_logs(job_name)


def cleanup_sandbox(job_name: str) -> None:
    """Force-delete a sandbox Job and all associated pods."""
    delete_sandbox_job(job_name)
    logger.info("Cleaned up sandbox Job %s", job_name)