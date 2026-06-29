"""Graph Ingestion Stage — Ingest into Neo4j and run graph-assisted scoring."""

import logging
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext

logger = logging.getLogger("graph_stage")


class GraphIngestionStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Graph Ingestion & Scoring"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.services.graph_ingester import GraphIngester
        from app.services.threat_correlation import build_attack_timeline, ingest_timeline_to_graph
        from app.analysis.graph_scorer import score_graph_correlation
        from app.analysis.evidence_envelope import GraphEvidence
        from app.analysis.risk_engine_v2 import RiskEngineV2

        sha256 = context.static_results.get("hash", {}).get("sha256", "unknown")

        # 1. Ingest job execution
        await GraphIngester.ingest_job_execution(context.job_id, sha256, context.filename)

        # 2. Ingest telemetry events
        for event in context.telemetry_events:
            evt_type = event.get("type")
            data = event.get("data", {})

            if evt_type == "PROCESS_CREATE":
                await GraphIngester.ingest_process_event(
                    context.job_id,
                    pid=data.get("pid", 0), ppid=data.get("ppid", 0),
                    executable=data.get("executable", data.get("name", "")),
                    command=data.get("cmdline", ""),
                )
            if evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                await GraphIngester.ingest_network_event(
                    context.job_id,
                    pid=data.get("pid", 0), ip_address=data.get("dest_ip", ""),
                    port=data.get("dest_port", 0), protocol=data.get("protocol", "TCP"),
                )
            elif evt_type == "DNS_QUERY":
                await GraphIngester.ingest_dns_event(
                    context.job_id, pid=data.get("pid", 0), domain=data.get("query", ""),
                )
            elif evt_type in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
                await GraphIngester.ingest_registry_event(
                    context.job_id, pid=data.get("pid", 0),
                    key=data.get("key", ""), operation=data.get("operation", "MODIFY"),
                )
            elif evt_type == "PERSISTENCE_EVENT":
                await GraphIngester.ingest_persistence_event(
                    context.job_id, pid=data.get("pid", 0),
                    mechanism=data.get("mechanism", ""), target=data.get("target", ""),
                )
            elif evt_type == "MEMORY_INJECTION":
                await GraphIngester.ingest_memory_injection_event(
                    context.job_id, source_pid=data.get("source_pid", 0),
                    target_pid=data.get("target_pid", 0), api_call=data.get("api_call", ""),
                )

        # 3. Ingest IOCs
        await GraphIngester.ingest_iocs_batch(context.job_id, context.iocs)

        # 4. Ingest MITRE ATT&CK
        for mapping in context.mitre_mappings:
            await GraphIngester.ingest_attack_technique(
                context.job_id,
                technique_id=mapping.get("id", ""),
                technique_name=mapping.get("name", ""),
                tactic=mapping.get("evidence", ""),
            )

        # 5. Ingest YARA
        for rule_name in context.yara_match_names:
            await GraphIngester.ingest_yara_match(sha256, rule_name, category="yara_detection")

        # 6. Ingest artifact tree
        try:
            artifact_engine = getattr(context, "_artifact_engine", None)
            if artifact_engine:
                edges = artifact_engine.get_artifact_graph_edges()
                await GraphIngester.ingest_artifact_tree(context.job_id, edges)
        except Exception as e:
            logger.error(f"Artifact graph ingestion failed (non-fatal): {e}")

        # 7. Build attack timeline
        context.attack_timeline = build_attack_timeline(context.telemetry_events)
        try:
            await ingest_timeline_to_graph(context.job_id, context.attack_timeline)
        except Exception as e:
            logger.error(f"Timeline graph ingestion failed (non-fatal): {e}")

        # 8. Graph-assisted correlation scoring (Graph → Evidence Provider)
        try:
            chain_length, graph_bonus, has_c2_persist, graph_reasons = await score_graph_correlation(context.job_id)
            if graph_bonus > 0 and context.envelope:
                context.envelope.graph = GraphEvidence(
                    chain_length=chain_length,
                    has_c2_persistence=has_c2_persist,
                    reasoning=graph_reasons,
                )
                # Re-score with graph evidence
                context.risk_assessment = RiskEngineV2.calculate_risk(context.envelope)
                # Re-propagate child risk
                max_child_risk = context.artifact_report.get("max_child_risk", 0)
                context.risk_assessment = RiskEngineV2.propagate_artifact_risk(
                    context.risk_assessment, max_child_risk
                )
                context.log(f"[Graph] Correlation: chain={chain_length}, bonus=+{graph_bonus}")
        except Exception as e:
            logger.error(f"Graph correlation scoring failed (non-fatal): {e}")

        context.log("[Graph] Neo4j ingestion completed")
        return context
