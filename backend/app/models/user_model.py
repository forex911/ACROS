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


async def find_by_supabase_id(supabase_user_id: str):
    """Look up a user by their Supabase user ID."""
    doc = await users.find_one(
        {"supabase_user_id": supabase_user_id},
        projection={"_id": False}
    )
    return doc


async def find_by_email(email: str):
    """Look up a user by email."""
    doc = await users.find_one(
        {"email": email},
        projection={"_id": False}
    )
    return doc


async def create_supabase_user(
    supabase_user_id: str,
    email: str,
    username: str,
    roles: list = None
):
    """Create a new user linked to a Supabase account."""
    now = datetime.utcnow()
    doc = {
        "supabase_user_id": supabase_user_id,
        "email": email,
        "username": username,
        "hashed_password": "",  # No local password — Supabase handles auth
        "roles": roles or ["user"],
        "api_keys": [],
        "created_at": now,
        "updated_at": now,
    }
    await users.insert_one(doc)
    doc.pop("hashed_password", None)
    doc.pop("_id", None)
    return doc
