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


@router.get('/auth/profile')
async def profile(user=Depends(get_current_user)):
    """
    Returns rich profile data: user info, scan statistics, API keys.
    """
    from app.database.mongodb import db
    username = user['username']

    # Fetch full user doc
    user_doc = await find_by_username(username)
    created_at = user_doc.get('created_at', datetime.utcnow())
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()

    # Scan statistics
    jobs_col = db["sandbox_jobs"]
    is_admin = "admin" in user_doc.get("roles", [])
    base_query = {} if is_admin else {"$or": [{"submitted_by": username}, {"shared_with": username}]}
    
    total_scans = await jobs_col.count_documents(base_query)
    threats_found = await jobs_col.count_documents({"risk_score": {"$gte": 70}, **base_query})
    completed_scans = await jobs_col.count_documents({"status": "completed", **base_query})
    pending_scans = await jobs_col.count_documents({"status": {"$in": ["pending", "analyzing"]}, **base_query})

    # API Keys (redacted)
    api_keys = []
    for k in user_doc.get('api_keys', []):
        key_val = k.get('key', '')
        key_created = k.get('created_at', '')
        if isinstance(key_created, datetime):
            key_created = key_created.isoformat()
        api_keys.append({
            "prefix": key_val[:8] + '...' if len(key_val) > 8 else key_val,
            "created_at": key_created,
        })

    return {
        "username": username,
        "roles": user_doc.get('roles', []),
        "created_at": created_at,
        "stats": {
            "total_scans": total_scans,
            "threats_found": threats_found,
            "completed_scans": completed_scans,
            "pending_scans": pending_scans,
        },
        "api_keys": api_keys,
    }


@router.post('/auth/apikey', response_model=APIKeyResponse, status_code=201)
async def create_api_key(user=Depends(require_roles([Role.ADMIN]))):
    key = secrets.token_urlsafe(32)
    await add_api_key(user['username'], key)
    return APIKeyResponse(key=key, created_at=str(datetime.utcnow()))


@router.delete('/auth/apikey/{key}', status_code=204)
async def delete_api_key(key: str, user=Depends(require_roles([Role.ADMIN]))):
    await revoke_api_key(user['username'], key)
    return {"status": "ok"}

from app.models.job_model import share_job, unshare_job, get_job
from pydantic import BaseModel

class ShareRequest(BaseModel):
    username: str

@router.post('/auth/jobs/{job_id}/share', status_code=200)
async def share_job_route(job_id: str, payload: ShareRequest, user=Depends(get_current_user)):
    job = await get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    is_admin = "admin" in user.get("roles", [])
    submitted_by = job.get("submitted_by")
    if not is_admin and submitted_by != user["username"]:
        raise HTTPException(status_code=403, detail="Only the owner can share this job")
        
    await share_job(job_id, payload.username)
    return {"status": "shared"}

@router.delete('/auth/jobs/{job_id}/share/{username}', status_code=204)
async def unshare_job_route(job_id: str, username: str, user=Depends(get_current_user)):
    job = await get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    is_admin = "admin" in user.get("roles", [])
    submitted_by = job.get("submitted_by")
    if not is_admin and submitted_by != user["username"]:
        raise HTTPException(status_code=403, detail="Only the owner can unshare this job")
        
    await unshare_job(job_id, username)
    return {"status": "unshared"}

@router.get('/auth/jobs/mine')
async def get_my_jobs(user=Depends(get_current_user)):
    # Returns jobs explicitly submitted by this user for the sharing management UI
    from app.database.mongodb import db
    jobs_col = db["sandbox_jobs"]
    cursor = jobs_col.find({"submitted_by": user["username"]}, {"_id": 0, "job_id": 1, "filename": 1, "status": 1, "shared_with": 1, "created_at": 1}).sort("created_at", -1).limit(20)
    jobs = await cursor.to_list(length=20)
    return jobs

