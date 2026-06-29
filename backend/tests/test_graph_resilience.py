"""
Graph Resilience — Test Suite
==============================
Tests the Neo4j availability check and @neo4j_resilient decorator.
"""

import pytest
from unittest.mock import patch, AsyncMock
from app.services.graph_resilience import (
    is_neo4j_available,
    neo4j_resilient,
    invalidate_cache,
    _availability_cache,
)


class TestNeo4jAvailability:

    def setup_method(self):
        """Reset the cache before each test."""
        invalidate_cache()

    @pytest.mark.asyncio
    async def test_unavailable_when_connection_refused(self):
        """When Neo4j is down, is_neo4j_available returns False."""
        with patch("app.services.graph_resilience.get_neo4j_async_session") as mock:
            mock.side_effect = ConnectionRefusedError("Connection refused")
            result = await is_neo4j_available()
            assert result is False

    @pytest.mark.asyncio
    async def test_availability_is_cached(self):
        """Subsequent calls within TTL should return cached result."""
        with patch("app.services.graph_resilience.get_neo4j_async_session") as mock:
            mock.side_effect = ConnectionRefusedError("Connection refused")
            result1 = await is_neo4j_available()
            assert result1 is False

            # Should not call again (cached)
            result2 = await is_neo4j_available()
            assert result2 is False
            assert mock.call_count == 1  # Only called once

    @pytest.mark.asyncio
    async def test_invalidate_cache_forces_recheck(self):
        """invalidate_cache() should force a fresh check."""
        with patch("app.services.graph_resilience.get_neo4j_async_session") as mock:
            mock.side_effect = ConnectionRefusedError("Connection refused")
            await is_neo4j_available()
            assert mock.call_count == 1

            invalidate_cache()
            await is_neo4j_available()
            assert mock.call_count == 2


class TestNeo4jResilientDecorator:

    def setup_method(self):
        invalidate_cache()

    @pytest.mark.asyncio
    async def test_returns_default_when_unavailable(self):
        """When Neo4j is unavailable, decorated function returns default."""
        with patch("app.services.graph_resilience.get_neo4j_async_session") as mock:
            mock.side_effect = ConnectionRefusedError("Connection refused")

            @neo4j_resilient(default_return=(0, 0, False, []))
            async def my_query():
                return (99, 99, True, ["should not reach"])

            result = await my_query()
            assert result == (0, 0, False, [])

    @pytest.mark.asyncio
    async def test_returns_default_on_runtime_error(self):
        """If the function itself raises, return default instead of crashing."""
        # First make Neo4j appear available
        invalidate_cache()
        _availability_cache["available"] = True
        _availability_cache["checked_at"] = __import__("time").monotonic()

        @neo4j_resilient(default_return="fallback")
        async def broken_query():
            raise RuntimeError("Query exploded")

        result = await broken_query()
        assert result == "fallback"
