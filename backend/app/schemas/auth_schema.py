from pydantic import BaseModel, Field
from typing import Optional, List


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    jti: str
    expires_at: int


class RefreshResponse(BaseModel):
    refresh_token: str
    jti: str
    expires_at: int


class LoginRequest(BaseModel):
    username: str
    password: str


class MeResponse(BaseModel):
    username: str
    roles: List[str]


class APIKeyResponse(BaseModel):
    key: str
    created_at: Optional[str]
