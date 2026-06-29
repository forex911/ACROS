"""
Graph Resilience — Neo4j Connection Guard
==========================================
Wraps all Neo4j operations with graceful degradation. When Neo4j is
unavailable, operations return safe defaults instead of crashing the
pipeline. The guard caches availability status to avoid repeated
connection attempts during a known outage.

Usage::

    from app.services.graph_resilience import neo4j_resilient, is_neo4j_available

    @neo4j_resilient(default_return=[])
    async def my_graph_query():
        async with get_neo4j_async_session() as session:
            ...

    if await is_neo4j_available():
        # proceed with graph ops
"""

import asyncio
import logging
import functools
import time
from typing import Any, Callable, TypeVar
from app.database.neo4j import get_neo4j_async_session

logger = logging.getLogger("graph_resilience")

T = TypeVar("T")

# Cache availability check for 30 seconds to avoid hammering a dead Neo4j
_availability_cache: dict = {"available": None, "checked_at": 0.0}
_CACHE_TTL = 30.0


async def is_neo4j_available() -> bool:
    """
    Check if Neo4j is reachable. Result is cached for 30 seconds.
    Returns False if connection fails — the pipeline continues without graph features.
    """
    now = time.monotonic()
    if (
        _availability_cache["available"] is not None
        and (now - _availability_cache["checked_at"]) < _CACHE_TTL
    ):
        return _availability_cache["available"]

    try:
        async with get_neo4j_async_session() as session:
            result = await session.run("RETURN 1 AS ping")
            await result.consume()
        _availability_cache["available"] = True
        _availability_cache["checked_at"] = now
        return True
    except Exception as e:
        logger.warning(f"[GraphResilience] Neo4j unavailable: {e}")
        _availability_cache["available"] = False
        _availability_cache["checked_at"] = now
        return False


def invalidate_cache():
    """Force a re-check on next call (e.g., after a reconnect attempt)."""
    _availability_cache["available"] = None
    _availability_cache["checked_at"] = 0.0


def neo4j_resilient(default_return: Any = None):
    """
    Decorator for async functions that depend on Neo4j.
    If Neo4j is unavailable, returns `default_return` without raising.

    Example::

        @neo4j_resilient(default_return=(0, 0, False, []))
        async def score_graph_correlation(job_id: str):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if not await is_neo4j_available():
                logger.info(
                    f"[GraphResilience] Skipping {func.__name__} — Neo4j unavailable"
                )
                return default_return
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(
                    f"[GraphResilience] {func.__name__} failed: {e}",
                    exc_info=True,
                )
                # Mark unavailable to skip further attempts this cycle
                _availability_cache["available"] = False
                _availability_cache["checked_at"] = time.monotonic()
                return default_return
        return wrapper
    return decorator
