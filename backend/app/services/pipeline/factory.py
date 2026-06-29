"""
Pipeline Factory — Dependency Injection for the Analysis Pipeline
=================================================================
Constructs a fully-wired AnalysisPipeline with all stages configured.
This is the single point where dependencies are assembled, enabling
testing with mocked stages and flexible reconfiguration.

Usage::

    from app.services.pipeline.factory import PipelineFactory
    from app.services.pipeline.context import PipelineContext

    pipeline = PipelineFactory.create_default()
    context = PipelineContext(job_id="abc", local_path="/tmp/sample.exe", filename="sample.exe")
    result = await pipeline.run(context)
"""

from app.services.pipeline.registry import AnalysisPipeline
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.stages.static_analysis import StaticAnalysisStage
from app.services.pipeline.stages.sandbox_execution import SandboxExecutionStage
from app.services.pipeline.stages.deobfuscation import DeobfuscationStage
from app.services.pipeline.stages.artifact_collection import ArtifactCollectionStage
from app.services.pipeline.stages.correlation import CorrelationStage
from app.services.pipeline.stages.risk_scoring import RiskScoringStage
from app.services.pipeline.stages.graph_ingestion import GraphIngestionStage
from app.services.pipeline.stages.report_finalization import ReportFinalizationStage


class PipelineFactory:
    """Factory for constructing fully-wired analysis pipelines."""

    @staticmethod
    def create_default() -> AnalysisPipeline:
        """
        Create the standard production analysis pipeline.

        Stage order:
            1. Static Analysis   — Hash, PE, Python, Strings
            2. Sandbox Execution — Run in sandbox, collect telemetry
            3. Deobfuscation     — Decode obfuscated strings and commands
            4. Artifact Collection — Extract and classify dropped files
            5. Correlation       — IOC, MITRE, YARA, Capabilities, Behavior, Threat
            6. Risk Scoring      — Build EvidenceEnvelope, run RiskEngineV2
            7. Graph Ingestion   — Neo4j ingestion + graph-assisted re-scoring
            8. Report Finalization — Compile report, persist, signal completion
        """
        return AnalysisPipeline(stages=[
            StaticAnalysisStage(),
            SandboxExecutionStage(),
            DeobfuscationStage(),
            ArtifactCollectionStage(),
            CorrelationStage(),
            RiskScoringStage(),
            GraphIngestionStage(),
            ReportFinalizationStage(),
        ])

    @staticmethod
    def create_static_only() -> AnalysisPipeline:
        """
        Create a lightweight pipeline for static-only analysis.
        No sandbox execution, no graph ingestion.
        """
        return AnalysisPipeline(stages=[
            StaticAnalysisStage(),
            CorrelationStage(),
            RiskScoringStage(),
            ReportFinalizationStage(),
        ])

    @staticmethod
    def create_custom(stages: list[PipelineStage]) -> AnalysisPipeline:
        """Create a pipeline from a custom list of stages."""
        return AnalysisPipeline(stages=stages)
