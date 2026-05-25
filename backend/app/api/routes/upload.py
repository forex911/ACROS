"""
Artifact upload endpoint — fully async, non-blocking.

Upload flow:
  1. Stream file to disk via aiofiles (non-blocking)
  2. Compute SHA-256 in thread pool (non-blocking)
  3. Upload artifact to MinIO/S3 (sync boto3 offloaded to thread)
  4. Generate presigned URL for worker download
  5. Enqueue Celery task with presigned URL (NOT local path)
  6. Clean up local temporary file
"""

import asyncio
import os
import logging

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from starlette.status import HTTP_202_ACCEPTED

from app.utils.file_utils import save_uploaded_file
from app.utils.hash_utils import calculate_sha256
from app.utils.celery_client import enqueue_sandbox_job
from app.models.job_model import create_job
from app.utils.object_store import upload_file, generate_presigned_url
from app.core.config import S3_BUCKET, S3_PRESIGNED_EXPIRATION
from app.api.dependencies.auth import get_current_user

logger = logging.getLogger("upload")

router = APIRouter()


@router.post("/upload", status_code=HTTP_202_ACCEPTED)
async def upload_artifact(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """
    Accept a malware sample for sandbox analysis.

    The entire pipeline is non-blocking:
      - File I/O uses aiofiles
      - SHA-256 hashing runs in a thread pool
      - S3 upload runs in a thread pool
    """

    # ── 1. Stream-write artifact to temp storage (async) ──────────────────
    try:
        saved_file = await save_uploaded_file(file)
    except Exception as exc:
        logger.error("Failed to save uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail="failed_saving_file") from exc

    local_path = saved_file["path"]

    try:
        # ── 2. Hash in thread pool (non-blocking) ────────────────────────
        sha256 = await calculate_sha256(local_path)

        # ── 3. Upload to MinIO/S3 in thread pool (non-blocking) ──────────
        object_key = f"{saved_file['file_id']}/{saved_file['filename']}"
        upload_meta = await asyncio.to_thread(
            upload_file, local_path, S3_BUCKET, object_key
        )

        # ── 4. Generate presigned URL for distributed workers ────────────
        presigned = await asyncio.to_thread(
            generate_presigned_url,
            upload_meta['bucket'],
            upload_meta['key'],
            S3_PRESIGNED_EXPIRATION,
        )

        # ── 5. Persist job record in MongoDB ─────────────────────────────
        extra = {
            "artifact_bucket": upload_meta['bucket'],
            "artifact_key": upload_meta['key'],
            "artifact_size": upload_meta['size'],
            "artifact_sha256": sha256,
            "submitted_by": user['username'],
        }
        await create_job(
            job_id=saved_file["file_id"],
            filename=saved_file["filename"],
            path=None,  # no local path — workers use presigned URL
            sha256=sha256,
            extra=extra,
        )

        # ── 6. Enqueue Celery task with PRESIGNED URL (not local path) ───
        task = enqueue_sandbox_job(
            job_id=saved_file["file_id"],
            presigned_url=presigned,
        )

    finally:
        # ── 7. Clean up local temp file (always) ─────────────────────────
        try:
            os.remove(local_path)
        except OSError:
            pass

    return {
        "file_id": saved_file["file_id"],
        "filename": saved_file["filename"],
        "sha256": sha256,
        "task_id": str(task.id) if hasattr(task, 'id') else None,
        "status": "accepted",
    }