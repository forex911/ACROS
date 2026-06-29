"""
MongoDB Auth Repository — Production Implementation
=====================================================
Implements AuthRepository against the existing MongoDB collections.
This extracts the auth storage logic that was previously inlined
in the route handlers.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timezone

from app.core.auth_repository import AuthRepository
from app.database.mongodb import db


class MongoAuthRepository(AuthRepository):
    """MongoDB-backed auth storage using the existing 'users' collection."""

    def __init__(self):
        self.users = db.users
        self.tokens = db.refresh_tokens

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        user = await self.users.find_one({"email": email})
        if user:
            user["_id"] = str(user["_id"])
        return user

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        user = await self.users.find_one({"username": username})
        if user:
            user["_id"] = str(user["_id"])
        return user

    async def create_user(
        self, username: str, email: str, hashed_password: str, role: str = "analyst"
    ) -> Dict[str, Any]:
        user_doc = {
            "username": username,
            "email": email,
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now(timezone.utc),
        }
        result = await self.users.insert_one(user_doc)
        user_doc["_id"] = str(result.inserted_id)
        return user_doc

    async def store_refresh_token(
        self, user_id: str, token_jti: str, expires_at: int
    ) -> None:
        await self.tokens.insert_one({
            "user_id": user_id,
            "jti": token_jti,
            "expires_at": expires_at,
            "revoked": False,
            "created_at": datetime.now(timezone.utc),
        })

    async def revoke_refresh_token(self, token_jti: str) -> None:
        await self.tokens.update_one(
            {"jti": token_jti},
            {"$set": {"revoked": True}},
        )

    async def is_token_revoked(self, token_jti: str) -> bool:
        token = await self.tokens.find_one({"jti": token_jti})
        if not token:
            return True  # Unknown tokens are considered revoked
        return token.get("revoked", False)
