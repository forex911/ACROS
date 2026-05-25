from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from app.services.hunting_service import HuntingService
from app.api.dependencies.auth import get_current_user

router = APIRouter()

@router.get("/hunt/search", response_model=Dict[str, Any])
async def global_ioc_search(q: str, user=Depends(get_current_user)):
    """
    Enterprise Threat Hunting Endpoint.
    Searches across historical sandbox telemetry, static analysis, and graph relationships
    for any matching IOCs (IPs, Hashes, Domains, Process names).
    """
    if not q or len(q) < 3:
        raise HTTPException(status_code=400, detail="Search query must be at least 3 characters")
        
    results = await HuntingService.global_ioc_search(q)
    return results

@router.get("/hunt/ancestry/{job_id}/{pid}", response_model=List[Any])
async def process_ancestry(job_id: str, pid: int, user=Depends(get_current_user)):
    """
    Reconstructs the full process execution tree leading up to a specific PID.
    """
    results = await HuntingService.process_ancestry_search(pid, job_id)
    return results
