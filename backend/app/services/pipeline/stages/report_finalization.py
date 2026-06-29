"""Report Finalization Stage — Compile final report, save to MongoDB, broadcast completion."""

from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class ReportFinalizationStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Report Finalization"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.analysis.analyst_report import AnalystReportGenerator
        from app.models.job_model import set_report, append_log
        from app.services.sandbox.orchestrator import publish_state
        from app.core.metrics import jobs_processed_total, malware_detected_total

        # Generate analyst report
        context.analyst_report = AnalystReportGenerator.generate(
            context.capabilities,
            context.behavior_chains,
            context.threat,
            list({m.get("tactic", m.get("name", "Unknown")) for m in context.mitre_mappings}),
            context.impact,
            context.risk_assessment,
        )

        # Compile final report dict
        context.report = {
            "metadata": context.static_results.get("hash", {}),
            "yara_matches": context.yara_match_names,
            "mitre_tactics": context.mitre_mappings,
            "risk_score": context.risk_assessment.score,
            "risk_factors": context.risk_assessment.reasoning,
            "risk_calculation": context.risk_assessment.model_dump(),
            "analyst_report": context.analyst_report.model_dump(),
            "ai_summary": context.analyst_report.executive_summary,
            "iocs": context.iocs,
            "artifacts": context.artifact_report,
            "deobfuscation": context.deobfuscation_report,
            "attack_timeline": context.attack_timeline,
            "telemetry_count": len(context.telemetry_events),
            "telemetry_events": context.telemetry_events,
        }

        # Add V3-specific fields if available
        if hasattr(context.risk_assessment, "evidence_tree"):
            context.report["evidence_tree"] = context.risk_assessment.evidence_tree
            context.report["behaviour_tree"] = context.risk_assessment.behaviour_tree
            context.report["threat_distribution"] = context.risk_assessment.threat_distribution
            context.report["confidence_trace"] = context.risk_assessment.confidence_trace
            context.report["complexity_metrics"] = context.risk_assessment.complexity_metrics

        # Persist
        await set_report(context.job_id, context.report)

        # Flush pipeline logs to MongoDB
        for log_msg in context.logs:
            await append_log(context.job_id, log_msg)

        # Metrics
        jobs_processed_total.inc()
        if context.risk_assessment.score > 60:
            malware_detected_total.inc()

        # Signal completion
        await publish_state(context.job_id, "COMPLETED")
        context.log("[Pipeline] Pipeline completed successfully.")

        return context
