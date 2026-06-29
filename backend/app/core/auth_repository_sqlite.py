"""
SQLite Auth Repository — Development/Offline Implementation
============================================================
Implements AuthRepository against a local SQLite database for
development and offline use. No external database required.
"""

import sqlite3
import os
from typing import Optional, Dict, Any
from datetime import datetime, timezone

from app.core.auth_repository import AuthRepository


class SQLiteAuthRepository(AuthRepository):
    """SQLite-backed auth storage for development and offline mode."""

    def __init__(self, db_path: str = ""):
        if not db_path:
            db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "sentinel_auth.db",
            )
        self.db_path = db_path
        self._ensure_tables()

    def _ensure_tables(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                jti TEXT UNIQUE NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _dict_from_row(self, cursor, row) -> dict:
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

    async def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row) | {"_id": str(row["id"])}
        return None

    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row) | {"_id": str(row["id"])}
        return None

    async def create_user(
        self, username: str, email: str, hashed_password: str, role: str = "analyst"
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "INSERT INTO users (username, email, hashed_password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, hashed_password, role, now),
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return {
            "_id": str(user_id),
            "username": username,
            "email": email,
            "role": role,
            "created_at": now,
        }

    async def store_refresh_token(
        self, user_id: str, token_jti: str, expires_at: int
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO refresh_tokens (user_id, jti, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
            (user_id, token_jti, expires_at, now),
        )
        conn.commit()
        conn.close()

    async def revoke_refresh_token(self, token_jti: str) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?",
            (token_jti,),
        )
        conn.commit()
        conn.close()

    async def is_token_revoked(self, token_jti: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT revoked FROM refresh_tokens WHERE jti = ?", (token_jti,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return True
        return bool(row["revoked"])
