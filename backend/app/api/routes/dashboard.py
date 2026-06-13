from fastapi import APIRouter, Depends
from typing import List, Dict, Any
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user
from datetime import datetime, timedelta

router = APIRouter()

@router.get("/dashboard/overview")
async def get_dashboard_overview(timeframe: str = "1W", user=Depends(get_current_user)):
    """
    Returns real, live metrics from MongoDB for the Dashboard overview.
    """
    jobs_collection = db["sandbox_jobs"]

    now = datetime.utcnow()
    date_filter = {}
    if timeframe == "1D":
        date_filter = {"created_at": {"$gte": now - timedelta(days=1)}}
    elif timeframe == "1W":
        date_filter = {"created_at": {"$gte": now - timedelta(days=7)}}
    elif timeframe == "1M":
        date_filter = {"created_at": {"$gte": now - timedelta(days=30)}}
    elif timeframe == "3M":
        date_filter = {"created_at": {"$gte": now - timedelta(days=90)}}

    query_active = {"status": {"$in": ["pending", "analyzing"]}}
    query_threats = {"risk_score": {"$gte": 70}}
    query_all = {}

    if date_filter:
        query_active.update(date_filter)
        query_threats.update(date_filter)
        query_all.update(date_filter)

    # Active sandboxes
    active_count = await jobs_collection.count_documents(query_active)

    # Total threats detected (risk score >= 70)
    threats_count = await jobs_collection.count_documents(query_threats)

    # Stored Artifacts (total jobs representing uploaded files)
    artifacts_count = await jobs_collection.count_documents(query_all)

    # Recent Activity (last 5 jobs)
    cursor = jobs_collection.find(query_all).sort("created_at", -1).limit(5)
    recent_jobs = await cursor.to_list(length=5)
    
    formatted_jobs = []
    for job in recent_jobs:
        created_at_val = job.get("created_at")
        if isinstance(created_at_val, datetime):
            created_at_val = created_at_val.isoformat()
        formatted_jobs.append({
            "id": job.get("job_id", ""),
            "filename": job.get("filename", "unknown"),
            "status": job.get("status", "unknown"),
            "risk_score": job.get("risk_score", 0),
            "created_at": created_at_val
        })

    # Detection Frequency Timeline
    # Determine grouping format based on timeframe
    if timeframe == "1D":
        date_format = "%Y-%m-%d %H:00"
    else:
        date_format = "%Y-%m-%d"

    match_threats = {"risk_score": {"$gte": 70}}
    if date_filter:
        match_threats.update(date_filter)

    pipeline = [
        {"$match": match_threats},
        {"$group": {
            "_id": {"$dateToString": {"format": date_format, "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 30}
    ]
    
    timeline_cursor = jobs_collection.aggregate(pipeline)
    timeline_docs = await timeline_cursor.to_list(length=30)
    
    pipeline_all = [
        {"$match": query_all},
        {"$group": {
            "_id": {"$dateToString": {"format": date_format, "date": "$created_at"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
        {"$limit": 30}
    ]
    
    timeline_cursor_all = jobs_collection.aggregate(pipeline_all)
    timeline_docs_all = await timeline_cursor_all.to_list(length=30)
    
    def format_label(val):
        if timeframe == "1D":
            return val.split(" ")[1] if " " in val else val
        return val

    scans_by_time = {format_label(doc["_id"]): doc["count"] for doc in timeline_docs_all if doc.get("_id")}
    threats_by_time = {format_label(doc["_id"]): doc["count"] for doc in timeline_docs if doc.get("_id")}
    
    # Always generate a contiguous timeline
    chart_data = []
    
    if timeframe == "1D":
        # Last 24 hours
        for i in range(23, -1, -1):
            dt = now - timedelta(hours=i)
            time_label = dt.strftime("%H:00")
            chart_data.append({
                "time": time_label,
                "detections": threats_by_time.get(time_label, 0),
                "scans": scans_by_time.get(time_label, 0)
            })
    elif timeframe == "1W":
        # Last 7 days
        for i in range(6, -1, -1):
            dt = now - timedelta(days=i)
            time_label = dt.strftime("%Y-%m-%d")
            chart_data.append({
                "time": time_label,
                "detections": threats_by_time.get(time_label, 0),
                "scans": scans_by_time.get(time_label, 0)
            })
    elif timeframe == "1M":
        # Last 30 days
        for i in range(29, -1, -1):
            dt = now - timedelta(days=i)
            time_label = dt.strftime("%Y-%m-%d")
            chart_data.append({
                "time": time_label,
                "detections": threats_by_time.get(time_label, 0),
                "scans": scans_by_time.get(time_label, 0)
            })
    elif timeframe == "3M":
        # Last 12 weeks
        for i in range(11, -1, -1):
            # Group by week for 3M to avoid too many bars
            dt_start = now - timedelta(weeks=i+1)
            dt_end = now - timedelta(weeks=i)
            time_label = f"W{dt_end.strftime('%U')}"
            
            # Aggregate counts for the week
            week_scans = sum(count for date, count in scans_by_time.items() if dt_start.strftime("%Y-%m-%d") <= date <= dt_end.strftime("%Y-%m-%d"))
            week_threats = sum(count for date, count in threats_by_time.items() if dt_start.strftime("%Y-%m-%d") <= date <= dt_end.strftime("%Y-%m-%d"))
            
            chart_data.append({
                "time": time_label,
                "detections": week_threats,
                "scans": week_scans
            })

    # Threat Feed (Latest 5 threats)
    threat_cursor = jobs_collection.find(query_threats).sort("created_at", -1).limit(5)
    recent_threats = await threat_cursor.to_list(length=5)
    
    threat_feed = []
    for t in recent_threats:
        tactics = t.get("mitre_tactics", [])
        name = tactics[0].get("name") if tactics else "Malware"
        threat_feed.append({
            "name": name,
            "id": t.get("filename", "unknown"),
            "score": t.get("risk_score", 0),
            "trend": "+0.0" 
        })

    return {
        "active_sandboxes": active_count,
        "total_threats": threats_count,
        "stored_artifacts": artifacts_count,
        "recent_activity": formatted_jobs,
        "chart_data": chart_data,
        "threat_feed": threat_feed
    }
