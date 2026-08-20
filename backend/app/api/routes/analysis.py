from fastapi import APIRouter, HTTPException, Depends
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user
from bson import ObjectId

router = APIRouter()

@router.get("/analysis/{file_id}")
async def get_analysis(file_id: str, user=Depends(get_current_user)):
    if file_id == "latest":
        is_admin = "admin" in user.get("roles", [])
        base_query = {} if is_admin else {"$or": [{"submitted_by": user["username"]}, {"shared_with": user["username"]}]}
        job = await db["sandbox_jobs"].find_one(base_query, sort=[("created_at", -1)])
        if not job:
            # Return a placeholder if the DB is completely empty
            return {
                "file_id": "latest",
                "filename": "No file uploaded yet",
                "status": "pending",
                "risk_score": 0,
                "ai_summary": "No analysis jobs found. Please upload a file in the Workspace.",
                "yara_matches": [],
                "mitre_tactics": [],
                "metadata": {}
            }
    else:
        job = await db["sandbox_jobs"].find_one({"job_id": file_id})
        
    if job:
        is_admin = "admin" in user.get("roles", [])
        submitted_by = job.get("submitted_by")
        shared_with = job.get("shared_with", [])
        if not is_admin and submitted_by != user["username"] and user["username"] not in shared_with:
            raise HTTPException(status_code=403, detail="Not authorized to view this analysis")
        
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return {
        "file_id": job.get("job_id"),
        "filename": job.get("filename"),
        "status": job.get("status"),
        "risk_score": job.get("risk_score"),
        "ai_summary": job.get("ai_summary", "Analysis in progress..."),
        "yara_matches": job.get("yara_matches", []),
        "mitre_tactics": job.get("mitre_tactics", []),
        "iocs": job.get("iocs", []),
        "artifacts": job.get("artifacts", {}),
        "telemetry_events": job.get("telemetry", []),
        "telemetry_count": job.get("telemetry_count", 0),
        "logs": job.get("logs", []),
        "metadata": {
            "artifact_sha256": job.get("sha256"),
            "md5": job.get("md5"),
            "size": job.get("size"),
            "entropy": job.get("entropy"),
            **(job.get("metadata", {})),
            **(job.get("extra", {}))
        }
    }

@router.get("/analysis/{file_id}/telemetry")
async def get_analysis_telemetry(file_id: str, user=Depends(get_current_user)):
    job = await db["sandbox_jobs"].find_one({"job_id": file_id}, {"telemetry": 1, "submitted_by": 1, "shared_with": 1})
    if job:
        is_admin = "admin" in user.get("roles", [])
        submitted_by = job.get("submitted_by")
        shared_with = job.get("shared_with", [])
        if not is_admin and submitted_by != user["username"] and user["username"] not in shared_with:
            raise HTTPException(status_code=403, detail="Not authorized")
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return {
        "events": job.get("telemetry", [])
    }

@router.get("/analysis/{file_id}/artifacts")
async def get_analysis_artifacts(file_id: str, user=Depends(get_current_user)):
    job = await db["sandbox_jobs"].find_one({"job_id": file_id}, {"artifacts": 1, "submitted_by": 1, "shared_with": 1})
    if job:
        is_admin = "admin" in user.get("roles", [])
        submitted_by = job.get("submitted_by")
        shared_with = job.get("shared_with", [])
        if not is_admin and submitted_by != user["username"] and user["username"] not in shared_with:
            raise HTTPException(status_code=403, detail="Not authorized")
    if not job:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    return job.get("artifacts", {})