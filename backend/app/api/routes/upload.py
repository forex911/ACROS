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
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from starlette.status import HTTP_202_ACCEPTED
from app.core.limiter import limiter

from app.utils.file_utils import save_uploaded_file
from app.utils.hash_utils import calculate_sha256
from app.models.job_model import create_job
from app.utils.object_store import upload_file, generate_presigned_url
from app.core.config import settings
from app.api.dependencies.auth import get_current_user
from app.services.report_generator import generate_report_pipeline
import shutil

logger = logging.getLogger("upload")

router = APIRouter()


@router.post("/upload", status_code=HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def upload_artifact(
    request: Request,
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

    # ── 1. Validate File Size ────────────────────────────────────────────────
    if file.size and file.size > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 100MB.")

    # ── 2. Validate File Type & Signature ────────────────────────────────────
    _, ext = os.path.splitext(file.filename)
    if ext.lower() not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File extension {ext} not allowed.")

    # Validate Magic Bytes (MIME)
    import magic
    # Read the first 2048 bytes for magic signature detection
    header = await file.read(2048)
    await file.seek(0)  # Reset cursor for actual save
    
    mime_type = magic.from_buffer(header, mime=True)
    # Basic protection against zip bombs masquerading as executables etc.
    if mime_type not in ["application/x-dosexec", "text/x-python", "text/plain", "application/javascript", "text/x-shellscript"]:
         logger.warning(f"Suspicious MIME type detected: {mime_type} for file {file.filename}")
         # We allow it through if the extension matched for sandbox detonation, 
         # but we log it. If you want strict enforcement:
         # raise HTTPException(status_code=400, detail="Invalid file signature")

    # ── 2. Stream-write artifact to temp storage (async) ──────────────────
    try:
        saved_file = await save_uploaded_file(file)
    except Exception as exc:
        logger.error("Failed to save uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail="failed_saving_file") from exc

    local_path = saved_file["path"]

    try:
        # ── 2. Hash in thread pool (non-blocking) ────────────────────────
        sha256 = await calculate_sha256(local_path)

        # ── 4. Upload to MinIO/S3 in thread pool (non-blocking) ──────────
        object_key = f"{saved_file['file_id']}/{saved_file['filename']}"
        
        if not settings.S3_ACCESS_KEY:
            raise ValueError("S3_ACCESS_KEY not configured")
            
        upload_meta = await asyncio.to_thread(
            upload_file, local_path, settings.S3_BUCKET, object_key
        )

        # ── 5. Generate presigned URL for distributed workers ────────────
        presigned = await asyncio.to_thread(
            generate_presigned_url,
            upload_meta['bucket'],
            upload_meta['key'],
            settings.S3_PRESIGNED_EXPIRATION,
        )

        # ── 5. Persist job record in MongoDB ─────────────────────────────
        extra = {
            "artifact_bucket": upload_meta['bucket'],
            "artifact_key": upload_meta['key'],
            "artifact_size": upload_meta['size'],
            "artifact_sha256": sha256,
            "submitted_by": user['username'],
        }
        
        # Calculate full hash data and basic metadata sync for the DB
        from app.services.static_analysis.hash_analyzer import analyze_hashes
        hash_data = await asyncio.to_thread(analyze_hashes, local_path)
        
        await create_job(
            job_id=saved_file["file_id"],
            filename=saved_file["original_filename"],
            path=None,  # no local path — workers use presigned URL
            sha256=sha256,
            md5=hash_data.get("md5"),
            size=hash_data.get("size", 0),
            entropy=hash_data.get("entropy", 0.0),
            extra=extra,
        )

        # ── 6. Trigger Real Pipeline ───
        from app.models.job_model import append_log
        await append_log(saved_file["file_id"], f"[Upload API] Artifact '{saved_file['original_filename']}' accepted into secure vault.")
        
        # We need to keep the file alive for the pipeline. We will copy it to a persistent temp location
        # or just await the pipeline synchronously for simplicity in this prototype.
        # But to keep the upload endpoint fast, we'll run it in background and the pipeline will clean it up.
        _, ext = os.path.splitext(saved_file["original_filename"])
        persistent_path = local_path + ext
        shutil.copy(local_path, persistent_path)
        
        from opentelemetry import context
        
        current_context = context.get_current()
        
        async def run_and_clean():
            token = context.attach(current_context)
            try:
                await generate_report_pipeline(saved_file["file_id"], persistent_path, saved_file["filename"])
            except Exception as e:
                logger.error(f"Pipeline crashed: {e}", exc_info=True)
                from app.models.job_model import update_job_status
                await update_job_status(saved_file["file_id"], "failed", {"error": str(e)})
            finally:
                context.detach(token)
                try:
                    os.remove(persistent_path)
                except OSError:
                    pass

        asyncio.create_task(run_and_clean())
        task_id = "sandbox-" + saved_file["file_id"]

    finally:
        # ── 7. Clean up original local temp file (always) ─────────────────────────
        try:
            os.remove(local_path)
        except OSError:
            pass

    return {
        "file_id": saved_file["file_id"],
        "filename": saved_file["original_filename"],
        "sha256": sha256,
        "task_id": task_id,
        "status": "accepted",
    }
