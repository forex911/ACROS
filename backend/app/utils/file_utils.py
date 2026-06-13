"""
Async-safe file utilities for artifact persistence.

Uses ``aiofiles`` for non-blocking disk I/O so that large malware binaries
never stall the FastAPI asyncio event loop.
"""

import os
import uuid

import aiofiles

from app.core.config import UPLOAD_DIR


async def save_uploaded_file(file) -> dict:
    """
    Stream an uploaded file to disk asynchronously using chunked writes.

    Returns a dict with ``file_id``, ``filename``, and ``path``.
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    file_id = str(uuid.uuid4())
    # Extract only the base name of the original file (prevent path traversal logic on the client side)
    original_basename = os.path.basename(file.filename.replace('\\', '/'))
    
    # Store the file strictly as UUID.sample to prevent path traversal and command injection vulnerabilities
    filename = f"{file_id}.sample"
    file_path = os.path.join(UPLOAD_DIR, filename)

    # Stream in 64 KiB chunks — never loads the full binary into memory
    async with aiofiles.open(file_path, "wb") as out:
        while True:
            chunk = await file.read(65_536)
            if not chunk:
                break
            await out.write(chunk)

    return {
        "file_id": file_id,
        "filename": filename,
        "original_filename": original_basename,
        "path": file_path,
    }