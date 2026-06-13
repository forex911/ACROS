from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel
from app.database.mongodb import db
from app.api.dependencies.auth import require_roles, Role
from bson import ObjectId

router = APIRouter()

class IntegrationCreate(BaseModel):
    type: str
    url: str
    secret: str = ""
    token: str = ""

@router.post("/integrations", status_code=201)
async def create_integration(payload: IntegrationCreate, user=Depends(require_roles([Role.ADMIN]))):
    """
    Registers a new SIEM or webhook integration target for alerts.
    """
    if db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
        
    integration = payload.dict()
    integration["active"] = True
    
    result = await db.integrations.insert_one(integration)
    return {"id": str(result.inserted_id), "status": "created"}

@router.get("/integrations", response_model=List[Dict[str, Any]])
async def get_integrations(user=Depends(require_roles([Role.ADMIN]))):
    """Lists configured SIEM integrations."""
    if db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
        
    cursor = db.integrations.find({})
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        # Redact secrets for API response
        doc["secret"] = "***" if doc.get("secret") else ""
        doc["token"] = "***" if doc.get("token") else ""
        results.append(doc)
    return results

@router.delete("/integrations/{integration_id}")
async def delete_integration(integration_id: str, user=Depends(require_roles([Role.ADMIN]))):
    """Removes a SIEM integration."""
    if db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
        
    await db.integrations.delete_one({"_id": ObjectId(integration_id)})
    return {"status": "deleted"}
