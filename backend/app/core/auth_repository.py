"""
Auth Repository — Abstract Interface for User Storage
======================================================
Defines the contract for user authentication storage.
Implementations can target MongoDB (current), SQLite (dev), or
Neon PostgreSQL (production cloud) without changing the auth logic.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any


class AuthRepository(ABC):
    """Abstract interface for authentication storage."""

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find a user by email address. Returns None if not found."""
        ...

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Find a user by username. Returns None if not found."""
        ...

    @abstractmethod
    async def create_user(
        self, username: str, email: str, hashed_password: str, role: str = "analyst"
    ) -> Dict[str, Any]:
        """Create a new user. Returns the created user dict."""
        ...

    @abstractmethod
    async def store_refresh_token(
        self, user_id: str, token_jti: str, expires_at: int
    ) -> None:
        """Persist a refresh token JTI for revocation checks."""
        ...

    @abstractmethod
    async def revoke_refresh_token(self, token_jti: str) -> None:
        """Revoke a refresh token by its JTI."""
        ...

    @abstractmethod
    async def is_token_revoked(self, token_jti: str) -> bool:
        """Check if a refresh token JTI has been revoked."""
        ...
