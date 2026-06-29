"""Risk Scoring Stage — Build EvidenceEnvelope and run RiskEngineV2."""

from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class RiskScoringStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Risk Scoring"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.analysis.evidence_envelope import EvidenceEnvelope
        from app.analysis.risk_engine_v2 import RiskEngineV2

        # Build unified evidence envelope
        context.envelope = EvidenceEnvelope.build(
            job_id=context.job_id,
            static_results=context.static_results,
            telemetry_events=context.telemetry_events,
            iocs=context.iocs,
            mitre_mappings=context.mitre_mappings,
            yara_matches=context.yara_matches,
            capabilities=context.capabilities,
            behavior_chains=context.behavior_chains,
            threat=context.threat,
            filename=context.filename,
        )

        # Calculate risk
        context.risk_assessment = RiskEngineV2.calculate_risk(context.envelope)

        # Propagate risk from child artifacts
        max_child_risk = context.artifact_report.get("max_child_risk", 0)
        context.risk_assessment = RiskEngineV2.propagate_artifact_risk(
            context.risk_assessment, max_child_risk
        )

        context.log(
            f"[Risk] Score: {context.risk_assessment.score}/100 "
            f"({context.risk_assessment.severity}) — "
            f"{len(context.risk_assessment.contributors)} contributors"
        )
        return context
