from datetime import datetime
from typing import Optional, List, Dict, Any
from app.database.mongodb import db

users = db.get_collection("users")


async def create_user(username: str, hashed_password: str, roles: Optional[List[str]] = None, extra: Optional[Dict[str, Any]] = None):
    now = datetime.utcnow()
    doc = {
        "username": username,
        "hashed_password": hashed_password,
        "roles": roles or ["user"],
        "api_keys": [],
        "created_at": now,
        "updated_at": now,
    }
    if extra:
        doc.update(extra)
    await users.insert_one(doc)
    doc.pop("hashed_password", None)
    return doc


async def find_by_username(username: str):
    doc = await users.find_one({"username": username}, projection={"_id": False})
    return doc


async def add_api_key(username: str, key: str, meta: Optional[Dict[str, Any]] = None):
    entry = {"key": key, "created_at": datetime.utcnow()}
    if meta:
        entry.update(meta)
    await users.update_one({"username": username}, {"$push": {"api_keys": entry}, "$set": {"updated_at": datetime.utcnow()}})


async def revoke_api_key(username: str, key: str):
    await users.update_one({"username": username}, {"$pull": {"api_keys": {"key": key}}, "$set": {"updated_at": datetime.utcnow()}})
