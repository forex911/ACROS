"""Sandbox Execution Stage — Orchestrate sandbox run, validate and normalize telemetry."""

from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class SandboxExecutionStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Sandbox Execution"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.services.sandbox.orchestrator import orchestrate_sandbox
        from app.services.telemetry.normalizer import normalize_telemetry
        from app.services.telemetry.stats import compute_telemetry_stats

        # 1. Run sandbox and collect raw telemetry
        raw_events = await orchestrate_sandbox(context.job_id, context.local_path)

        # 2. Normalize, validate, and deduplicate
        context.telemetry_events = normalize_telemetry(raw_events, job_id=context.job_id)

        # 3. Compute stats for observability
        stats = compute_telemetry_stats(context.telemetry_events)
        context.static_results["telemetry_stats"] = stats

        context.log(
            f"[Sandbox] Raw: {len(raw_events)} events → "
            f"Validated: {len(context.telemetry_events)} events | "
            f"PIDs: {stats['unique_pids']}, IPs: {stats['unique_ips']}, "
            f"Domains: {stats['unique_domains']}"
        )
        return context
