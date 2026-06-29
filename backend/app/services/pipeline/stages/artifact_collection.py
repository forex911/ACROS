"""Artifact Collection Stage — Recursive artifact analysis."""

import os
import asyncio
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class ArtifactCollectionStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Artifact Collection"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.analysis.artifact_engine import ArtifactEngine

        artifact_engine = ArtifactEngine()
        context.artifact_report = await asyncio.to_thread(
            artifact_engine.process,
            context.telemetry_events,
            os.path.dirname(context.local_path),
        )

        context.log(
            f"[Artifacts] Collected {context.artifact_report.get('artifact_count', 0)} artifacts, "
            f"detected {context.artifact_report.get('download_count', 0)} downloads."
        )

        # Stash engine for graph edges later
        context._artifact_engine = artifact_engine
        return context
