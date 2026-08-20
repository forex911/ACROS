"""
ACROS Structured Logging
============================
Standardized JSON-structured logging using structlog.
Every log entry includes:
  - level, timestamp, logger name
  - job_id (when bound via `get_logger`)

Usage::

    from app.core.logger import get_logger

    logger = get_logger("my_module")
    logger.info("something happened", job_id="abc-123", extra_key="value")

All modules should use ``get_logger()`` instead of ``logging.getLogger()``.
"""

import logging
import sys

import structlog


def setup_structlog():
    """Configure structlog for JSON output and stdlib integration."""

    # Route stdlib logging through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str, **initial_binds) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger bound with the given name and optional initial context.

    Common usage::

        logger = get_logger("pipeline", job_id=context.job_id)
        logger.info("stage started", stage="Static Analysis")

    All key-value pairs passed here are included in every subsequent log message.
    """
    return structlog.get_logger(name, **initial_binds)