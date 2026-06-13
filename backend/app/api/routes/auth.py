from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from datetime import datetime
import secrets
import time

from app.schemas.auth_schema import UserCreate, TokenResponse, RefreshResponse, LoginRequest, MeResponse, APIKeyResponse
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from app.models.user_model import create_user, find_by_username, add_api_key, revoke_api_key
from app.database.redis import redis_client
from app.api.dependencies.auth import require_roles, get_current_user, Role
from app.core.config import settings
from app.core.limiter import limiter

router = APIRouter()


@router.post('/auth/register', status_code=201)
@limiter.limit("5/minute")
async def register(request: Request, payload: UserCreate):
    existing = await find_by_username(payload.username)
    if existing:
        raise HTTPException(status_code=400, detail='user_exists')
    hashed = hash_password(payload.password)
    user = await create_user(payload.username, hashed)
    return {"username": user['username'], "roles": user['roles']}


@router.post('/auth/login')
@limiter.limit("5/minute")
async def login(request: Request, payload: LoginRequest, response: Response):
    user = await find_by_username(payload.username)
    if not user or not verify_password(payload.password, user.get('hashed_password', '')):
        raise HTTPException(status_code=401, detail='invalid_credentials')

    access = create_access_token(subject=payload.username, scopes=user.get('roles', []))
    refresh = create_refresh_token(subject=payload.username)

    # Store refresh JTI in Redis for revocation tracking.
    # Key: refresh:{jti} → username, TTL = token lifetime
    ttl = refresh['expires_at'] - int(time.time())
    await redis_client.set(f"refresh:{refresh['jti']}", payload.username, ex=max(ttl, 1))

    # Send refresh token as HttpOnly secure cookie — never accessible to JS
    response.set_cookie(
        'refresh_token', refresh['refresh_token'],
        httponly=True, secure=settings.COOKIE_SECURE, samesite='lax',
    )
    return TokenResponse(
        access_token=access['access_token'],
        token_type=access['token_type'],
        jti=access['jti'],
        expires_at=access['expires_at'],
    )


@router.post('/auth/refresh')
async def refresh(request: Request, response: Response, refresh_token: str = None):
    # Prefer cookie, fall back to body parameter
    token = request.cookies.get('refresh_token') or refresh_token
    if not token:
        raise HTTPException(status_code=400, detail='refresh_token_required')

    # Decode and validate structure
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail='invalid_refresh')

    if payload.get('type') != 'refresh':
        raise HTTPException(status_code=401, detail='invalid_refresh')

    jti = payload.get('jti')
    username = payload.get('sub')
    token_iat = payload.get('iat', 0)

    # ── Revocation check 1: was this specific JTI explicitly deleted? ─────
    stored = await redis_client.get(f"refresh:{jti}")
    if not stored:
        raise HTTPException(status_code=401, detail='refresh_revoked')

    # ── Revocation check 2: was a user-wide logout issued after this token? ─
    last_logout = await redis_client.get(f"user_logout:{username}")
    if last_logout:
        try:
            logout_ts = int(last_logout)
        except (ValueError, TypeError):
            logout_ts = 0
        if token_iat <= logout_ts:
            # This token was issued before the user logged out — reject it
            # Also clean up the now-invalid JTI key
            await redis_client.delete(f"refresh:{jti}")
            raise HTTPException(status_code=401, detail='refresh_revoked_by_logout')

    # ── Token rotation: invalidate old JTI, issue new refresh + access ────
    await redis_client.delete(f"refresh:{jti}")

    # Issue fresh tokens
    user = await find_by_username(username)
    new_access = create_access_token(subject=username, scopes=user.get('roles', []) if user else [])
    new_refresh = create_refresh_token(subject=username)

    ttl = new_refresh['expires_at'] - int(time.time())
    await redis_client.set(f"refresh:{new_refresh['jti']}", username, ex=max(ttl, 1))

    response.set_cookie(
        'refresh_token', new_refresh['refresh_token'],
        httponly=True, secure=settings.COOKIE_SECURE, samesite='lax',
    )
    return TokenResponse(
        access_token=new_access['access_token'],
        token_type=new_access['token_type'],
        jti=new_access['jti'],
        expires_at=new_access['expires_at'],
    )


@router.post('/auth/logout')
async def logout(request: Request, response: Response, user=Depends(get_current_user)):
    username = user['username']

    # ── Explicit JTI revocation: delete the specific refresh token's JTI ──
    # Extract from cookie if present
    refresh_cookie = request.cookies.get('refresh_token')
    if refresh_cookie:
        try:
            payload = decode_token(refresh_cookie)
            jti = payload.get('jti')
            if jti:
                await redis_client.delete(f"refresh:{jti}")
        except Exception:
            pass  # token might be expired/invalid — that's fine, we still log out

    # ── User-wide revocation timestamp ────────────────────────────────────
    # Any refresh token issued before this timestamp is rejected on use.
    await redis_client.set(f"user_logout:{username}", str(int(time.time())))

    response.delete_cookie('refresh_token', secure=settings.COOKIE_SECURE, samesite='lax')
    return {"status": "ok"}


@router.get('/auth/me', response_model=MeResponse)
async def me(user=Depends(get_current_user)):
    return MeResponse(username=user['username'], roles=user.get('roles', []))


@router.post('/auth/apikey', response_model=APIKeyResponse, status_code=201)
async def create_api_key(user=Depends(require_roles([Role.ADMIN]))):
    key = secrets.token_urlsafe(32)
    await add_api_key(user['username'], key)
    return APIKeyResponse(key=key, created_at=str(datetime.utcnow()))


@router.delete('/auth/apikey/{key}', status_code=204)
async def delete_api_key(key: str, user=Depends(require_roles([Role.ADMIN]))):
    await revoke_api_key(user['username'], key)
    return {"status": "ok"}
