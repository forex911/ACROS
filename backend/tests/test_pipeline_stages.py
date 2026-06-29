"""
Pipeline Stage — Test Suite
============================
Tests the pipeline framework (PipelineStage, PipelineContext, AnalysisPipeline)
using mock stages to verify composition, error handling, and context propagation.
"""

import pytest
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext
from app.services.pipeline.registry import AnalysisPipeline


# ── Mock Stages ──

class SuccessStage(PipelineStage):
    @property
    def name(self) -> str:
        return "Success Stage"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        context.static_results["success"] = True
        return context


class FailingStage(PipelineStage):
    @property
    def name(self) -> str:
        return "Failing Stage"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        raise RuntimeError("Intentional test failure")


class CounterStage(PipelineStage):
    """Tracks how many times it was executed."""
    call_count = 0

    @property
    def name(self) -> str:
        return "Counter Stage"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        CounterStage.call_count += 1
        context.static_results["counter"] = CounterStage.call_count
        return context


# ── Tests ──

class TestPipelineContext:
    def test_context_defaults(self):
        ctx = PipelineContext(job_id="test-001", local_path="/tmp/x", filename="x.exe")
        assert ctx.job_id == "test-001"
        assert ctx.static_results == {}
        assert ctx.telemetry_events == []
        assert ctx.logs == []

    def test_context_log(self):
        ctx = PipelineContext()
        ctx.log("hello")
        ctx.log("world")
        assert len(ctx.logs) == 2
        assert ctx.logs[0] == "hello"


class TestAnalysisPipeline:
    @pytest.mark.asyncio
    async def test_empty_pipeline(self):
        pipeline = AnalysisPipeline(stages=[])
        ctx = PipelineContext(job_id="empty")
        result = await pipeline.run(ctx)
        assert result.job_id == "empty"

    @pytest.mark.asyncio
    async def test_single_stage(self):
        pipeline = AnalysisPipeline(stages=[SuccessStage()])
        ctx = PipelineContext(job_id="single")
        result = await pipeline.run(ctx)
        assert result.static_results.get("success") is True

    @pytest.mark.asyncio
    async def test_multiple_stages_execute_in_order(self):
        CounterStage.call_count = 0
        pipeline = AnalysisPipeline(stages=[
            SuccessStage(),
            CounterStage(),
        ])
        ctx = PipelineContext(job_id="multi")
        result = await pipeline.run(ctx)
        assert result.static_results.get("success") is True
        assert result.static_results.get("counter") == 1

    @pytest.mark.asyncio
    async def test_failing_stage_does_not_crash_pipeline(self):
        """A failing stage should log the error but not crash the pipeline."""
        pipeline = AnalysisPipeline(stages=[
            SuccessStage(),
            FailingStage(),
            CounterStage(),
        ])
        CounterStage.call_count = 0
        ctx = PipelineContext(job_id="fail")
        result = await pipeline.run(ctx)
        # SuccessStage ran
        assert result.static_results.get("success") is True
        # CounterStage ran AFTER the failure
        assert result.static_results.get("counter") == 1

    def test_stage_names(self):
        pipeline = AnalysisPipeline(stages=[SuccessStage(), FailingStage()])
        assert pipeline.stage_names == ["Success Stage", "Failing Stage"]


class TestPipelineFactory:
    def test_create_default(self):
        from app.services.pipeline.factory import PipelineFactory
        pipeline = PipelineFactory.create_default()
        assert len(pipeline.stage_names) == 8
        assert pipeline.stage_names[0] == "Static Analysis"
        assert pipeline.stage_names[-1] == "Report Finalization"

    def test_create_static_only(self):
        from app.services.pipeline.factory import PipelineFactory
        pipeline = PipelineFactory.create_static_only()
        assert len(pipeline.stage_names) == 4
        assert "Sandbox Execution" not in pipeline.stage_names

    def test_create_custom(self):
        from app.services.pipeline.factory import PipelineFactory
        pipeline = PipelineFactory.create_custom([SuccessStage()])
        assert pipeline.stage_names == ["Success Stage"]
