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
from app.analysis.risk_engine import RiskEngine
from app.analysis.report_generator import AnalystReportGenerator
from app.services.graph_ingester import GraphIngester
from app.services.threat_correlation import build_attack_timeline, ingest_timeline_to_graph
from app.models.job_model import set_report, append_log
from app.core.metrics import jobs_processed_total, malware_detected_total
import asyncio
import logging
from opentelemetry import trace

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
            elif evt_type in ("SOCKET_CONNECT", "NETWORK_CONNECT"):
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
            
            tactics = {m.get("tactic", m.get("name", "Unknown")) for m in mitre_mappings}
            risk_assessment = RiskEngine.calculate_risk(capabilities, behavior_chains, threat, len(tactics), 0)
            
            analyst_report = AnalystReportGenerator.generate(
                capabilities, behavior_chains, threat, list(tactics), impact, risk_assessment
            )
            ai_summary = analyst_report.executive_summary

            from app.services.yara_service import YaraService
            yara_svc = YaraService()
            yara_scan_results = yara_svc.scan_file(local_path)
            yara_matches = [m["rule"] for m in yara_scan_results] if yara_scan_results else []

        # ── Neo4j Graph Ingestion (non-blocking, never breaks MongoDB pipeline) ──
        with tracer.start_as_current_span("graph_ingestion"):
            await append_log(job_id, "[Pipeline] Ingesting analysis results into Neo4j graph...")
            await _ingest_to_graph(job_id, filename, static_results, telemetry_events, iocs, mitre_mappings, yara_matches)

        # ── Attack Timeline Correlation ──
        with tracer.start_as_current_span("timeline_generation"):
            await append_log(job_id, "[Pipeline] Building attack timeline...")
            attack_timeline = build_attack_timeline(telemetry_events)
            try:
                await ingest_timeline_to_graph(job_id, attack_timeline)
            except Exception as e:
                logger.error(f"Timeline graph ingestion failed (non-fatal): {e}")

        with tracer.start_as_current_span("finalize_report"):
            await append_log(job_id, "[Pipeline] Compiling final report...")
            # 4. Finalize Report
            report = {
                "metadata": static_results["hash"],
                "yara_matches": yara_matches,
                "mitre_tactics": mitre_mappings,
                "risk_score": risk_assessment.score,
                "risk_factors": risk_assessment.reasoning,
                "risk_calculation": risk_assessment.model_dump(),
                "analyst_report": analyst_report.model_dump(),
                "ai_summary": ai_summary,
                "iocs": iocs,
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
