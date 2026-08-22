from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import settings
from app.models.user_model import find_by_username
from app.core.security import decode_token
from app.database.mongodb import db

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Validate the native JWT token and return the user doc.
    """
    token = credentials.credentials
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    user = await find_by_username(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    return current_user

from enum import Enum
from typing import List

class Role(str, Enum):
    ADMIN = 'admin'
    ANALYST = 'analyst'
    USER = 'user'

def require_roles(*allowed_roles: Role):
    async def role_checker(current_user: dict = Depends(get_current_user)):
        user_roles = current_user.get('roles', [])
        for role in allowed_roles:
            if role.value in user_roles:
                return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Insufficient permissions'
        )
    return role_checker
