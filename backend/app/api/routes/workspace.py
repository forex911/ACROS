from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel
from datetime import datetime
from app.models.case_model import create_case, list_cases, get_case, add_note, pin_artifact
from app.database.mongodb import db
from app.api.dependencies.auth import get_current_user

router = APIRouter()

class CaseCreate(BaseModel):
    title: str
    description: str

class NoteCreate(BaseModel):
    content: str

class ArtifactPin(BaseModel):
    type: str
    value: str


@router.get("/workspace/jobs")
async def list_workspace_jobs(q: str = None, user=Depends(get_current_user)):
    """
    Returns all sandbox analysis jobs for the Workspace view,
    sorted by most recent first.
    """
    jobs_collection = db["sandbox_jobs"]
    
    # Isolation: only jobs submitted by or shared with current user (unless admin)
    is_admin = "admin" in user.get("roles", [])
    base_query = {} if is_admin else {"$or": [{"extra.submitted_by": user["username"]}, {"shared_with": user["username"]}]}
    
    query = base_query.copy()
    if q:
        query = {
            "$and": [
                base_query,
                {"$or": [
                {"filename": {"$regex": q, "$options": "i"}},
                {"job_id": {"$regex": q, "$options": "i"}},
                {"sha256": {"$regex": q, "$options": "i"}}
                ]}
            ]
        }
        
    cursor = jobs_collection.find(
        query,
        projection={
            "_id": False,
            "job_id": True,
            "filename": True,
            "status": True,
            "risk_score": True,
            "created_at": True,
            "sha256": True,
        }
    ).sort("created_at", -1).limit(50)

    jobs = await cursor.to_list(length=50)

    formatted = []
    for job in jobs:
        created = job.get("created_at")
        if isinstance(created, datetime):
            created = created.isoformat()
        formatted.append({
            "id": job.get("job_id", ""),
            "filename": job.get("filename", "unknown"),
            "status": job.get("status", "unknown"),
            "risk_score": job.get("risk_score") or 0,
            "created_at": created or datetime.utcnow().isoformat(),
            "sha256": job.get("sha256", ""),
        })

    return formatted


@router.post("/cases", status_code=201)
async def create_new_case(payload: CaseCreate, user=Depends(get_current_user)):
    case_id = await create_case(payload.title, payload.description, user["username"])
    return {"case_id": case_id}

@router.get("/cases", response_model=List[Dict[str, Any]])
async def get_all_cases(status: str = None, user=Depends(get_current_user)):
    cases = await list_cases(status)
    return cases

@router.get("/cases/{case_id}", response_model=Dict[str, Any])
async def get_case_details(case_id: str, user=Depends(get_current_user)):
    case = await get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@router.post("/cases/{case_id}/notes", status_code=201)
async def create_note(case_id: str, payload: NoteCreate, user=Depends(get_current_user)):
    await add_note(case_id, user["username"], payload.content)
    return {"status": "added"}

@router.post("/cases/{case_id}/artifacts", status_code=201)
async def pin_case_artifact(case_id: str, payload: ArtifactPin, user=Depends(get_current_user)):
    await pin_artifact(case_id, payload.type, payload.value)
    return {"status": "pinned"}
