from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.metrics import sandbox_errors_total
import logging

logger = logging.getLogger("acros.exceptions")

class AegisException(Exception):
    """Base exception for all ACROS-AI errors."""
    def __init__(self, message: str, status_code: int = 400, context: dict = None):
        self.message = message
        self.status_code = status_code
        self.context = context or {}
        super().__init__(self.message)

# Backward-compatibility alias
SentinelException = AegisException


class SandboxExecutionError(AegisException):
    """Raised when sandbox execution fails unexpectedly."""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, status_code=502, context=context)


class AnalysisTimeoutError(AegisException):
    """Raised when static or dynamic analysis exceeds configured timeouts."""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message, status_code=504, context=context)


async def aegis_exception_handler(request: Request, exc: AegisException):
    """
    Global exception handler for AegisException.
    Ensures safe JSON responses without leaking internal stack traces to the client.
    """
    logger.error(f"AegisException ({exc.status_code}): {exc.message}", extra={"context": exc.context})
    
    if isinstance(exc, SandboxExecutionError) or isinstance(exc, AnalysisTimeoutError):
        sandbox_errors_total.inc()
        
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status": "error", "type": exc.__class__.__name__}
    )

# Backward-compatibility alias
sentinel_exception_handler = aegis_exception_handler

async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions to prevent stack trace leakage.
    """
    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    sandbox_errors_total.inc()
    return JSONResponse(
        status_code=500,
        content={"error": "An internal system error occurred.", "status": "error"}
    )
