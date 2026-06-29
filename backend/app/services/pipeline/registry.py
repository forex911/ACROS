"""
Analysis Pipeline — Composable Pipeline Runner
================================================
Executes an ordered list of PipelineStage instances against a shared
PipelineContext. The pipeline is extensible: stages can be added,
removed, or reordered without changing the runner.
"""

import logging
from typing import List
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext

logger = logging.getLogger("pipeline")


class AnalysisPipeline:
    """Runs an ordered sequence of pipeline stages."""

    def __init__(self, stages: List[PipelineStage]):
        self._stages = stages

    async def run(self, context: PipelineContext) -> PipelineContext:
        """Execute all stages sequentially."""
        logger.info(f"[Pipeline] Starting pipeline with {len(self._stages)} stages for job {context.job_id}")
        for i, stage in enumerate(self._stages, 1):
            logger.info(f"[Pipeline] Stage {i}/{len(self._stages)}: {stage.name}")
            context = await stage.execute(context)
        logger.info(f"[Pipeline] Pipeline completed for job {context.job_id}")
        return context

    @property
    def stage_names(self) -> List[str]:
        return [s.name for s in self._stages]
