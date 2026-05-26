from datetime import datetime
from typing import Optional, Dict, Any

from app.database.mongodb import db

jobs = db.get_collection("sandbox_jobs")


async def create_job(job_id: str, filename: str, path: str, sha256: str, md5: str = None, size: int = 0, entropy: float = 0.0, extra: Optional[Dict[str, Any]] = None):
    now = datetime.utcnow()
    doc = {
        "job_id": job_id,
        "filename": filename,
        "path": path,
        "sha256": sha256,
        "md5": md5,
        "size": size,
        "entropy": entropy,
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "risk_score": None,
        "threat_level": None,
        "worker_id": None,
        "sandbox_id": None,
        "logs": [],
        "errors": [],
        "metrics": {
            "cpu": None,
            "memory": None,
            "network_connections": None
        },
        "telemetry": [],
        "iocs": [],
        "mitre_tactics": [],
        "analysis": {},
        "retry_count": 0,
        "max_retries": 3,
        "report": None,
        "sandbox_metadata": {},
    }
    if extra:
        doc.update(extra)
    await jobs.insert_one(doc)
    return doc


async def update_job_status(job_id: str, status: str, extra: Optional[Dict[str, Any]] = None):
    update = {"status": status, "updated_at": datetime.utcnow()}
    if extra:
        update.update(extra)
    await jobs.update_one({"job_id": job_id}, {"$set": update})


async def append_log(job_id: str, message: str):
    entry = {"ts": datetime.utcnow(), "message": message}
    await jobs.update_one({"job_id": job_id}, {"$push": {"logs": entry}, "$set": {"updated_at": datetime.utcnow()}})


async def add_error(job_id: str, error: str):
    entry = {"ts": datetime.utcnow(), "error": error}
    await jobs.update_one({"job_id": job_id}, {"$push": {"errors": entry}, "$set": {"updated_at": datetime.utcnow(), "status": "failed"}})


async def update_metrics(job_id: str, metrics: Dict[str, Any]):
    await jobs.update_one({"job_id": job_id}, {"$set": {"metrics": metrics, "updated_at": datetime.utcnow()}})


async def set_report(job_id: str, report_doc: Dict[str, Any]):
    update_fields = {
        "report": report_doc,
        "updated_at": datetime.utcnow()
    }
    
    # Extract important fields to top-level for easier querying
    if "risk_score" in report_doc:
        update_fields["risk_score"] = report_doc["risk_score"]
    if "ai_summary" in report_doc:
        update_fields["ai_summary"] = report_doc["ai_summary"]
    if "iocs" in report_doc:
        update_fields["iocs"] = report_doc["iocs"]
    if "mitre_tactics" in report_doc:
        update_fields["mitre_tactics"] = report_doc["mitre_tactics"]
    if "telemetry_events" in report_doc:
        update_fields["telemetry"] = report_doc["telemetry_events"]
    
    await jobs.update_one({"job_id": job_id}, {"$set": update_fields})


async def increment_retry(job_id: str):
    await jobs.update_one({"job_id": job_id}, {"$inc": {"retry_count": 1}, "$set": {"updated_at": datetime.utcnow()}})


async def get_job(job_id: str):
    doc = await jobs.find_one({"job_id": job_id}, projection={"_id": False})
    return doc


async def get_logs(job_id: str):
    doc = await jobs.find_one({"job_id": job_id}, projection={"_id": False, "logs": True})
    return doc.get("logs") if doc else []


async def get_metrics(job_id: str):
    doc = await jobs.find_one({"job_id": job_id}, projection={"_id": False, "metrics": True})
    return doc.get("metrics") if doc else {}
