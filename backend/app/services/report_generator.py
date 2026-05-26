from app.models.job_model import update_job_status
from app.services.static_analysis.hash_analyzer import analyze_hashes
from app.services.static_analysis.python_analyzer import analyze_python_file
from app.services.static_analysis.pe_analyzer import analyze_pe_file
from app.services.static_analysis.string_extractor import extract_strings
from app.services.runtime_analysis.sandbox_runner import run_sandbox, publish_event
from app.services.ioc_pipeline import extract_and_store_iocs
from app.services.mitre_mapper import map_to_mitre
from app.services.risk_engine import calculate_risk
from app.services.ai_correlator import generate_ai_summary
import asyncio

async def generate_report_pipeline(job_id: str, local_path: str, filename: str):
    await update_job_status(job_id, "analyzing")
    await publish_event(job_id, "STATUS_CHANGE", {"type": "STATUS_CHANGE", "severity": "info", "data": {"status": "analyzing"}})

    # 1. Static Analysis
    static_results = {}
    static_results["hash"] = analyze_hashes(local_path)
    static_results["strings"] = extract_strings(local_path)
    
    if filename.endswith(".py"):
        static_results["python"] = analyze_python_file(local_path)
    else:
        static_results["pe"] = analyze_pe_file(local_path)

    # 2. Runtime Telemetry (Sandbox)
    # The sandbox will run the script safely and stream telemetry to Redis
    telemetry_events = await run_sandbox(job_id, local_path)

    # 3. Correlation & Analysis
    iocs = extract_and_store_iocs(static_results, telemetry_events)
    mitre_mappings = map_to_mitre(static_results, telemetry_events)
    risk_data = calculate_risk(static_results, telemetry_events, mitre_mappings)
    ai_summary = generate_ai_summary(risk_data, iocs, mitre_mappings, telemetry_events)

    # 4. Finalize Report
    report = {
        "metadata": static_results["hash"],
        "yara_matches": [], # Stubbed out for now unless we implement full Yara scanning
        "mitre_tactics": mitre_mappings,
        "risk_score": risk_data["score"],
        "ai_summary": ai_summary,
        "iocs": iocs,
        "telemetry_count": len(telemetry_events),
        "telemetry_events": telemetry_events
    }

    # Publish completion
    await publish_event(job_id, "STATUS_CHANGE", {"type": "STATUS_CHANGE", "severity": "info", "data": {"status": "completed"}})
    await update_job_status(job_id, "completed", report)
    
    return report
