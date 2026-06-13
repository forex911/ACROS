from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/dashboard/overview")
async def get_dashboard_overview(user=Depends(get_current_user)):
    """
    Returns real, live metrics from MongoDB for the Dashboard overview.
    """
    jobs_collection = db["sandbox_jobs"]

    # Active sandboxes
    active_count = await jobs_collection.count_documents({"status": {"$in": ["pending", "analyzing"]}})

    # Total threats detected (risk score >= 70)
    threats_count = await jobs_collection.count_documents({"risk_score": {"$gte": 70}})

    # Stored Artifacts (total jobs representing uploaded files)
    artifacts_count = await jobs_collection.count_documents({})

    # Recent Activity (last 5 jobs)
    cursor = jobs_collection.find({}).sort("created_at", -1).limit(5)
    recent_jobs = await cursor.to_list(length=5)
    
    formatted_jobs = []
    for job in recent_jobs:
        formatted_jobs.append({
            "id": job.get("job_id", ""),
            "filename": job.get("filename", "unknown"),
            "status": job.get("status", "unknown"),
            "risk_score": job.get("risk_score", 0),
            "created_at": job.get("created_at", datetime.utcnow().isoformat())
        })

    # Detection Frequency Timeline (Mocking timeseries using actual db data spread over hours)
    # We will aggregate jobs by hour or just generate a dynamic timeline based on recent threats.
    # For a real implementation, we would use $group by date truncation.
    # Here we simulate the past 6 hours of detections.
    pipeline = [
        {"$match": {"risk_score": {"$gte": 70}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d %H:00", "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 10}
    ]
    
    timeline_cursor = jobs_collection.aggregate(pipeline)
    timeline_docs = await timeline_cursor.to_list(length=10)
    # Total scans for chart timeline
    pipeline_all = [
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d %H:00", "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 10}
    ]
    
    timeline_cursor_all = jobs_collection.aggregate(pipeline_all)
    timeline_docs_all = await timeline_cursor_all.to_list(length=10)
    
    scans_by_time = {doc["_id"].split(" ")[1]: doc["count"] for doc in timeline_docs_all}
    threats_by_time = {doc["_id"].split(" ")[1]: doc["count"] for doc in timeline_docs}
    
    chart_data = []
    if not timeline_docs_all:
        now = datetime.utcnow()
        for i in range(6, -1, -1):
            dt = now - timedelta(hours=i)
            time_label = dt.strftime("%H:00")
            chart_data.append({"time": time_label, "detections": 0, "scans": 0})
    else:
        for time_label, scan_count in scans_by_time.items():
            chart_data.append({
                "time": time_label, 
                "detections": threats_by_time.get(time_label, 0),
                "scans": scan_count
            })

    # Threat Feed (Latest 5 threats)
    threat_cursor = jobs_collection.find({"risk_score": {"$gte": 70}}).sort("created_at", -1).limit(5)
    recent_threats = await threat_cursor.to_list(length=5)
    
    threat_feed = []
    for t in recent_threats:
        # Try to get the highest MITRE tactic as the name, otherwise use generic name
        tactics = t.get("mitre_tactics", [])
        name = tactics[0].get("name") if tactics else "Malware"
        threat_feed.append({
            "name": name,
            "id": t.get("filename", "unknown"),
            "score": t.get("risk_score", 0),
            "trend": "+0.0" # Static trend as we don't have historical trend per malware family
        })

    return {
        "active_sandboxes": active_count,
        "total_threats": threats_count,
        "stored_artifacts": artifacts_count,
        "recent_activity": formatted_jobs,
        "chart_data": chart_data,
        "threat_feed": threat_feed
    }
