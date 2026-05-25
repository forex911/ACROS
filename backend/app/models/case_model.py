import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from bson import ObjectId
from app.database.mongodb import db

logger = logging.getLogger("case_model")

async def create_case(title: str, description: str, owner: str) -> str:
    """Creates a new SOC investigation case."""
    if db is None:
        raise Exception("Database not initialized")
        
    doc = {
        "title": title,
        "description": description,
        "owner": owner,
        "status": "OPEN",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "artifacts": [], # Pinned Hashes, IPs, Domains
        "notes": []
    }
    result = await db.cases.insert_one(doc)
    return str(result.inserted_id)

async def list_cases(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists all cases, optionally filtered by status."""
    if db is None: return []
    
    query = {}
    if status:
        query["status"] = status
        
    cursor = db.cases.find(query).sort("updated_at", -1)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return results

async def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    """Gets a specific case."""
    if db is None: return None
    doc = await db.cases.find_one({"_id": ObjectId(case_id)})
    if doc:
        doc["_id"] = str(doc["_id"])
    return doc

async def add_note(case_id: str, author: str, content: str):
    """Adds an analyst note to the case."""
    if db is None: return
    note = {
        "id": str(ObjectId()),
        "author": author,
        "content": content,
        "timestamp": datetime.utcnow().isoformat()
    }
    await db.cases.update_one(
        {"_id": ObjectId(case_id)},
        {
            "$push": {"notes": note},
            "$set": {"updated_at": datetime.utcnow().isoformat()}
        }
    )

async def pin_artifact(case_id: str, type: str, value: str):
    """Bookmarks an IOC (hash, ip, domain) to the case."""
    if db is None: return
    artifact = {
        "type": type,
        "value": value,
        "added_at": datetime.utcnow().isoformat()
    }
    await db.cases.update_one(
        {"_id": ObjectId(case_id)},
        {
            "$push": {"artifacts": artifact},
            "$set": {"updated_at": datetime.utcnow().isoformat()}
        }
    )
