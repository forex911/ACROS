"""
Pipeline Stage — Abstract Base Class
=====================================
All analysis stages implement this interface, allowing the pipeline
to be composed, extended, and tested independently.
"""

from abc import ABC, abstractmethod
from app.services.pipeline.context import PipelineContext


class PipelineStage(ABC):
    """Common interface for all analysis pipeline stages."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable stage name for logging and tracing."""
        ...

    async def execute(self, context: PipelineContext) -> PipelineContext:
        """
        Execute this stage. Reads from and writes to the shared context.
        Must be idempotent and must not raise on non-fatal failures.

        Override ``_run`` for your stage logic. This method wraps it
        with logging and error handling.
        """
        context.log(f"[Pipeline] Executing stage: {self.name}")
        try:
            context = await self._run(context)
        except Exception as e:
            context.log(f"[Pipeline] Stage '{self.name}' failed (non-fatal): {e}")
            import logging
            logging.getLogger("pipeline").error(
                f"Stage '{self.name}' failed: {e}", exc_info=True
            )
        return context

    @abstractmethod
    async def _run(self, context: PipelineContext) -> PipelineContext:
        """Stage-specific logic. Subclasses must implement this."""
        ...
