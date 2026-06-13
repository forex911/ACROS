from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List

from app.core.security import decode_token
from app.database.redis import redis_client
from app.models.user_model import find_by_username
from app.core.config import settings
from fastapi import Header
from app.models.user_model import users
from enum import Enum

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"

bearer_scheme = HTTPBearer(auto_error=False)


async def _is_token_revoked(jti: str) -> bool:
    # token revocation stored in redis as key 'revoked:{jti}'
    key = f"revoked:{jti}"
    val = await redis_client.get(key)
    return val is not None


async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    # Support API key header as alternative auth mechanism
    api_key = request.headers.get(settings.API_KEY_HEADER)
    if api_key:
        user = await users.find_one({"api_keys.key": api_key}, projection={"_id": False})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        return user

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    jti = payload.get('jti')
    if await _is_token_revoked(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    username = payload.get('sub')
    user = await find_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_roles(roles: List[Role]):
    async def _validator(user=Depends(get_current_user)):
        user_roles = user.get('roles', [])
        # Check against enum values
        allowed_roles = [r.value for r in roles]
        if not any(r in allowed_roles for r in user_roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role")
        return user

    return _validator
