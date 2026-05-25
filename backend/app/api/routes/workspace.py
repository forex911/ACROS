from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel
from app.models.case_model import create_case, list_cases, get_case, add_note, pin_artifact
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
