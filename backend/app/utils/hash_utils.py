"""
Async-safe hashing utilities.

CPU-intensive hashing is executed inside a thread pool via
``asyncio.to_thread`` so it never blocks the FastAPI event loop.
"""

import asyncio
import hashlib


def _sha256_sync(file_path: str) -> str:
    """Compute SHA-256 of a file synchronously (called from thread pool)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65_536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


async def calculate_sha256(file_path: str) -> str:
    """
    Non-blocking SHA-256 computation.

    Delegates to a thread-pool worker so the asyncio event loop
    remains responsive even for large (100 MB+) malware artifacts.
    """
    return await asyncio.to_thread(_sha256_sync, file_path)