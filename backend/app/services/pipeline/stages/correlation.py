"""Correlation Stage — IOC extraction, MITRE mapping, YARA scan, capabilities, behavior, threat classification."""

from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class CorrelationStage(PipelineStage):
    """Combines IOC, MITRE, YARA, Capability, Behavior, and Threat analysis."""

    @property
    def name(self) -> str:
        return "Correlation Analysis"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.services.ioc_pipeline import extract_and_store_iocs
        from app.services.mitre_mapper import map_to_mitre
        from app.analysis.capability_engine import CapabilityEngine
        from app.analysis.behavior_engine import BehaviorEngine
        from app.analysis.threat_classifier import ThreatClassifier
        from app.analysis.impact_engine import ImpactEngine
        from app.services.yara_service import YaraService

        # IOC extraction
        context.iocs = extract_and_store_iocs(context.static_results, context.telemetry_events)

        # MITRE ATT&CK mapping
        context.mitre_mappings = map_to_mitre(context.static_results, context.telemetry_events)

        # Capability & Behavior analysis
        context.capabilities = CapabilityEngine.extract_capabilities(
            context.static_results, context.telemetry_events
        )
        context.behavior_chains = BehaviorEngine.detect_chains(context.capabilities)
        context.threat = ThreatClassifier.classify(context.capabilities, context.behavior_chains)
        context.impact = ImpactEngine.calculate_impact(context.capabilities, context.behavior_chains)

        # YARA scan
        yara_svc = YaraService()
        yara_scan_results = yara_svc.scan_file(context.local_path)
        context.yara_matches = yara_scan_results if yara_scan_results else []
        context.yara_match_names = [m["rule"] for m in context.yara_matches] if context.yara_matches else []

        context.log(
            f"[Correlation] {len(context.iocs)} IOCs, "
            f"{len(context.mitre_mappings)} MITRE techniques, "
            f"{len(context.capabilities)} capabilities, "
            f"{len(context.behavior_chains)} behavior chains, "
            f"{len(context.yara_matches)} YARA matches"
        )
        return context
