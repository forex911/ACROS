from app.models.job_model import update_job_status
from app.services.static_analysis.hash_analyzer import analyze_hashes
from app.services.static_analysis.python_analyzer import analyze_python_file
from app.services.static_analysis.pe_analyzer import analyze_pe_file
from app.services.static_analysis.string_extractor import extract_strings
from app.services.sandbox.orchestrator import orchestrate_sandbox, publish_state
from app.services.ioc_pipeline import extract_and_store_iocs
from app.services.mitre_mapper import map_to_mitre
from app.analysis.capability_engine import CapabilityEngine
from app.analysis.behavior_engine import BehaviorEngine
from app.analysis.threat_classifier import ThreatClassifier
from app.analysis.impact_engine import ImpactEngine
from app.analysis.v3.risk_engine_v3 import RiskEngineV3
from app.analysis.evidence_envelope import EvidenceEnvelope
from app.analysis.analyst_report import AnalystReportGenerator
from app.analysis.deobfuscation import UniversalDeobfuscator
from app.services.graph_ingester import GraphIngester
from app.services.threat_correlation import build_attack_timeline, ingest_timeline_to_graph
from app.models.job_model import set_report, append_log
from app.core.metrics import jobs_processed_total, malware_detected_total
import asyncio
import logging
import sys
import os
import numpy as np
from opentelemetry import trace

root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)


logger = logging.getLogger("report_generator")
tracer = trace.get_tracer(__name__)

async def _ingest_to_graph(job_id: str, filename: str, static_results: dict,
                           telemetry_events: list, iocs: list, mitre_mappings: list,
                           yara_matches: list):
    """
    Feed all pipeline outputs into Neo4j graph. Failures here are logged
    but never break the MongoDB pipeline — dual-write with graceful degradation.
    """
    try:
        sha256 = static_results.get("hash", {}).get("sha256", "unknown")

        # 1. Create SandboxJob → File relationship
        await GraphIngester.ingest_job_execution(job_id, sha256, filename)

        # 2. Ingest telemetry events as Process / Network / DNS nodes
        for event in telemetry_events:
            evt_type = event.get("type")
            data = event.get("data", {})

            if evt_type == "PROCESS_CREATE":
                await GraphIngester.ingest_process_event(
                    job_id,
                    pid=data.get("pid", 0),
                    ppid=data.get("ppid", 0),
                    executable=data.get("executable", data.get("name", "")),
                    command=data.get("cmdline", "")
                )
            if evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
                await GraphIngester.ingest_network_event(
                    job_id,
                    pid=data.get("pid", 0),
                    ip_address=data.get("dest_ip", ""),
                    port=data.get("dest_port", 0),
                    protocol=data.get("protocol", "TCP")
                )
            elif evt_type == "DNS_QUERY":
                await GraphIngester.ingest_dns_event(
                    job_id,
                    pid=data.get("pid", 0),
                    domain=data.get("query", "")
                )
            elif evt_type in ("REGISTRY_CREATE", "REGISTRY_MODIFY"):
                await GraphIngester.ingest_registry_event(
                    job_id,
                    pid=data.get("pid", 0),
                    key=data.get("key", ""),
                    operation=data.get("operation", "MODIFY")
                )
            elif evt_type == "PERSISTENCE_EVENT":
                await GraphIngester.ingest_persistence_event(
                    job_id,
                    pid=data.get("pid", 0),
                    mechanism=data.get("mechanism", ""),
                    target=data.get("target", "")
                )
            elif evt_type == "MEMORY_INJECTION":
                await GraphIngester.ingest_memory_injection_event(
                    job_id,
                    source_pid=data.get("source_pid", 0),
                    target_pid=data.get("target_pid", 0),
                    api_call=data.get("api_call", "")
                )

        # 3. Ingest IOCs
        await GraphIngester.ingest_iocs_batch(job_id, iocs)

        # 4. Ingest MITRE ATT&CK mappings
        for mapping in mitre_mappings:
            await GraphIngester.ingest_attack_technique(
                job_id,
                technique_id=mapping.get("id", ""),
                technique_name=mapping.get("name", ""),
                tactic=mapping.get("evidence", "")
            )

        # 5. Ingest YARA matches
        for rule_name in yara_matches:
            await GraphIngester.ingest_yara_match(sha256, rule_name, category="yara_detection")

        logger.info(f"[GraphIngester] Successfully ingested job {job_id} into Neo4j")
    except Exception as e:
        logger.error(f"[GraphIngester] Graph ingestion failed for {job_id} (non-fatal): {e}")


async def generate_report_pipeline(job_id: str, local_path: str, filename: str):
    with tracer.start_as_current_span("generate_report_pipeline") as span:
        span.set_attribute("job_id", job_id)
        
        await update_job_status(job_id, "analyzing")
        await publish_state(job_id, "CREATED", {"status": "created"})

        # 1. Static Analysis
        with tracer.start_as_current_span("static_analysis"):
            static_results = {}
            static_results["hash"] = analyze_hashes(local_path)
            static_results["strings"] = extract_strings(local_path)
            
            if filename.endswith(".py"):
                static_results["python"] = analyze_python_file(local_path)
            else:
                static_results["pe"] = analyze_pe_file(local_path)

        # 2. Runtime Telemetry (Sandbox)
        # The orchestrator handles the state machine and returns telemetry
        with tracer.start_as_current_span("sandbox_execution"):
            telemetry_events = await orchestrate_sandbox(job_id, local_path)
            span.set_attribute("telemetry_event_count", len(telemetry_events))

        # 2.4. Artifact Collection & Recursive Analysis
        with tracer.start_as_current_span("artifact_engine"):
            await append_log(job_id, "[Pipeline] Running Artifact Collection & Recursive Analysis...")
            from app.analysis.artifact_engine import ArtifactEngine
            import asyncio
            artifact_engine = ArtifactEngine()
            
            artifact_report = await asyncio.to_thread(artifact_engine.process, telemetry_events, os.path.dirname(local_path))
            
            await append_log(
                job_id,
                f"[Artifacts] Collected {artifact_report.get('artifact_count', 0)} artifacts, "
                f"detected {artifact_report.get('download_count', 0)} downloads."
            )

        # 2.5. Deobfuscation & Normalization Layer
        with tracer.start_as_current_span("deobfuscation"):
            await append_log(job_id, "[Pipeline] Running Universal Deobfuscation Layer...")
            deobfuscator = UniversalDeobfuscator()
            
            # Deobfuscate telemetry (attaches decoded_cmdline, normalized_cmdline to events)
            deobfuscation_report = deobfuscator.process_telemetry(telemetry_events)
            
            # Deobfuscate static strings
            static_deobfuscation = deobfuscator.process_static_strings(static_results)
            
            decoded_count = deobfuscation_report["total_fields_decoded"]
            layers_count = deobfuscation_report["total_encoding_layers_stripped"]
            iocs_recovered = len(deobfuscation_report.get("recovered_iocs", []))
            await append_log(
                job_id,
                f"[Deobfuscation] Decoded {decoded_count} fields, stripped {layers_count} layers, recovered {iocs_recovered} IOCs"
            )

        # 3. Correlation & Analysis
        with tracer.start_as_current_span("correlation_analysis"):
            await append_log(job_id, "[Pipeline] Mapping extracted telemetry to MITRE ATT&CK framework...")
            iocs = extract_and_store_iocs(static_results, telemetry_events)
            mitre_mappings = map_to_mitre(static_results, telemetry_events)
            
            await append_log(job_id, "[Pipeline] Executing Intelligence Layer...")
            
            capabilities = CapabilityEngine.extract_capabilities(static_results, telemetry_events)
            behavior_chains = BehaviorEngine.detect_chains(capabilities)
            threat = ThreatClassifier.classify(capabilities, behavior_chains)
            impact = ImpactEngine.calculate_impact(capabilities, behavior_chains)
            
            # Build YARA scan results (moved earlier so they enter the envelope)
            from app.services.yara_service import YaraService
            yara_svc = YaraService()
            yara_scan_results = yara_svc.scan_file(local_path)
            yara_matches = yara_scan_results if yara_scan_results else []
            yara_match_names = [m["rule"] for m in yara_matches] if yara_matches else []
            
            # ── Risk Engine v2: Build Evidence Envelope ──
            await append_log(job_id, "[Pipeline] Assembling unified evidence envelope...")
            envelope = EvidenceEnvelope.build(
                job_id=job_id,
                static_results=static_results,
                telemetry_events=telemetry_events,
                iocs=iocs,
                mitre_mappings=mitre_mappings,
                yara_matches=yara_matches,
                capabilities=capabilities,
                behavior_chains=behavior_chains,
                threat=threat,
            )
            
            risk_assessment = RiskEngineV3.calculate_risk(envelope)
            
            # Propagate risk from child artifacts
            max_child_risk = artifact_report.get("max_child_risk", 0)
            risk_assessment = RiskEngineV3.propagate_artifact_risk(risk_assessment, max_child_risk)
            
            analyst_report = AnalystReportGenerator.generate(
                capabilities, behavior_chains, threat, list({m.get("tactic", m.get("name", "Unknown")) for m in mitre_mappings}), impact, risk_assessment
            )
            ai_summary = analyst_report.executive_summary

        # ── Neo4j Graph Ingestion (non-blocking, never breaks MongoDB pipeline) ──
        with tracer.start_as_current_span("graph_ingestion"):
            await append_log(job_id, "[Pipeline] Ingesting analysis results into Neo4j graph...")
            await _ingest_to_graph(job_id, filename, static_results, telemetry_events, iocs, mitre_mappings, yara_match_names)
            
            try:
                from app.services.graph_ingester import GraphIngester
                edges = artifact_engine.get_artifact_graph_edges()
                await GraphIngester.ingest_artifact_tree(job_id, edges)
            except Exception as e:
                logger.error(f"Artifact graph ingestion failed (non-fatal): {e}")

        # ── Attack Timeline Correlation ──
        with tracer.start_as_current_span("timeline_generation"):
            await append_log(job_id, "[Pipeline] Building attack timeline...")
            attack_timeline = build_attack_timeline(telemetry_events)
            try:
                await ingest_timeline_to_graph(job_id, attack_timeline)
            except Exception as e:
                logger.error(f"Timeline graph ingestion failed (non-fatal): {e}")

            # ── Graph-Assisted Correlation Scoring ──
            try:
                from app.analysis.graph_scorer import score_graph_correlation
                chain_length, graph_bonus, has_c2_persist, graph_reasons = await score_graph_correlation(job_id)
                if graph_bonus > 0:
                    envelope.graph_chain_length = chain_length
                    envelope.graph_has_c2_persistence = has_c2_persist
                    # Re-score with graph data
                    risk_assessment = RiskEngineV3.calculate_risk(envelope)
                    # Re-propagate child risk
                    risk_assessment = RiskEngineV3.propagate_artifact_risk(risk_assessment, max_child_risk)
                    
                    # Regenerate AI summary to reflect updated score
                    analyst_report = AnalystReportGenerator.generate(
                        capabilities, behavior_chains, threat, list({m.get("tactic", m.get("name", "Unknown")) for m in mitre_mappings}), impact, risk_assessment
                    )
                    ai_summary = analyst_report.executive_summary

                    await append_log(job_id, f"[Pipeline] Graph correlation: chain={chain_length}, bonus=+{graph_bonus}")
            except Exception as e:
                logger.error(f"Graph correlation scoring failed (non-fatal): {e}")

        with tracer.start_as_current_span("finalize_report"):
            await append_log(job_id, "[Pipeline] Compiling final report...")
            # 4. Finalize Report
            report = {
                "metadata": static_results["hash"],
                "yara_matches": yara_match_names,
                "mitre_tactics": mitre_mappings,
                "risk_score": risk_assessment.score,
                "risk_factors": risk_assessment.reasoning,
                "risk_calculation": risk_assessment.model_dump(),
                "analyst_report": analyst_report.model_dump(),
                "ai_summary": ai_summary,
                "iocs": iocs,
                "artifacts": artifact_report,
                "deobfuscation": deobfuscation_report,
                "attack_timeline": attack_timeline,
                "telemetry_count": len(telemetry_events),
                "telemetry_events": telemetry_events
            }

            # State tracking is handled by the orchestrator (it emits COMPLETED)
            await set_report(job_id, report)
            
            await append_log(job_id, "[Pipeline] Pipeline completed successfully. Broadcasting finish signal.")
            
            # Metric Collection
            jobs_processed_total.inc()
            if risk_assessment.score > 60:
                malware_detected_total.inc()
                
            # Finally, emit COMPLETED to signal the frontend to fetch the full report.
            await publish_state(job_id, "COMPLETED")
            
        return report
