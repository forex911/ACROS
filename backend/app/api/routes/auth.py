from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.database.mongodb import db
from app.schemas.auth_schema import TokenResponse as Token, LoginRequest as Login, UserCreate as Register, MeResponse as UserResponse, ForgotPasswordRequest, ResetPasswordRequest
from app.models.user_model import create_user, find_by_username, users
from app.core.security import verify_password, hash_password, create_access_token
from app.api.dependencies.auth import get_current_user
from app.core.limiter import limiter
from datetime import datetime, timedelta
import secrets
import hashlib
from pydantic import BaseModel
from app.services.email_service import send_otp_email

router = APIRouter(tags=["auth"])

class VerifyOTP(BaseModel):
    email: str
    otp: str

class ResendOTP(BaseModel):
    email: str


@router.post("/auth/register")
@limiter.limit("5/minute")
async def register(request: Request, user_in: Register):
    existing_user = await find_by_username(user_in.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    existing_email = await users.find_one({"email": user_in.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user_in.password)
    user = await create_user(
        username=user_in.username, 
        hashed_password=hashed_password,
        extra={"email": user_in.email, "email_verified": False}
    )
    
    # Generate 6-digit OTP
    otp_code = str(secrets.randbelow(900000) + 100000)
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    
    now = datetime.utcnow()
    await users.update_one(
        {"username": user_in.username},
        {"$set": {
            "otp_hash": otp_hash,
            "otp_expires_at": now + timedelta(minutes=5),
            "otp_attempts": 0,
            "otp_last_sent_at": now
        }}
    )
    
    send_otp_email(user_in.email, otp_code)
    
    return {
        "success": True,
        "requiresOTP": True,
        "message": "Verification code sent to email"
    }

@router.post("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request, login_data: Login):
    user = await users.find_one({"email": login_data.username})
    if not user:
        user = await find_by_username(login_data.username)
        
    if not user or not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email/username or password")

    if not user.get("email_verified", False):
        # Generate 6-digit OTP
        otp_code = str(secrets.randbelow(900000) + 100000)
        otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
        
        now = datetime.utcnow()
        await users.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "otp_hash": otp_hash,
                "otp_expires_at": now + timedelta(minutes=5),
                "otp_attempts": 0,
                "otp_last_sent_at": now
            }}
        )
        send_otp_email(user["email"], otp_code)
        
        return {
            "success": True,
            "requiresOTP": True,
            "message": "Please verify your email. Code sent."
        }

    # If verified, just issue JWT
    return create_access_token(subject=user["username"])

@router.post("/auth/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(request: Request, data: VerifyOTP):
    user = await users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not user.get("otp_hash"):
        raise HTTPException(status_code=400, detail="No OTP requested")
        
    if user.get("otp_attempts", 0) >= 5:
        raise HTTPException(status_code=400, detail="Too many verification attempts. Please request a new OTP.")
        
    if datetime.utcnow() > user.get("otp_expires_at", datetime.utcnow()):
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new one.")
        
    submitted_hash = hashlib.sha256(data.otp.encode()).hexdigest()
    
    if submitted_hash != user["otp_hash"]:
        await users.update_one({"_id": user["_id"]}, {"$inc": {"otp_attempts": 1}})
        raise HTTPException(status_code=400, detail="Invalid verification code")
        
    # Clear OTP fields and set email_verified
    await users.update_one(
        {"_id": user["_id"]},
        {"$unset": {
            "otp_hash": "",
            "otp_expires_at": "",
            "otp_attempts": "",
            "otp_last_sent_at": ""
        }, "$set": {
            "email_verified": True
        }}
    )
    
    # Issue native JWT
    return create_access_token(subject=user["username"])

@router.post("/auth/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(request: Request, data: ForgotPasswordRequest):
    user = await users.find_one({"email": data.email})
    if not user:
        # Prevent email enumeration
        return {"success": True, "requiresOTP": True, "message": "If the email is registered, an OTP was sent."}
        
    otp_code = str(secrets.randbelow(900000) + 100000)
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    
    now = datetime.utcnow()
    await users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "otp_hash": otp_hash,
            "otp_expires_at": now + timedelta(minutes=5),
            "otp_attempts": 0,
            "otp_last_sent_at": now
        }}
    )
    
    send_otp_email(user["email"], otp_code)
    return {"success": True, "requiresOTP": True, "message": "OTP sent to email"}

@router.post("/auth/reset-password")
@limiter.limit("5/minute")
async def reset_password(request: Request, data: ResetPasswordRequest):
    user = await users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not user.get("otp_hash"):
        raise HTTPException(status_code=400, detail="No OTP requested")
        
    if user.get("otp_attempts", 0) >= 5:
        raise HTTPException(status_code=400, detail="Too many verification attempts.")
        
    if datetime.utcnow() > user.get("otp_expires_at", datetime.utcnow()):
        raise HTTPException(status_code=400, detail="OTP expired.")
        
    submitted_hash = hashlib.sha256(data.otp.encode()).hexdigest()
    if submitted_hash != user["otp_hash"]:
        await users.update_one({"_id": user["_id"]}, {"$inc": {"otp_attempts": 1}})
        raise HTTPException(status_code=400, detail="Invalid verification code")
        
    hashed_password = hash_password(data.new_password)
    
    await users.update_one(
        {"_id": user["_id"]},
        {"$unset": {
            "otp_hash": "",
            "otp_expires_at": "",
            "otp_attempts": "",
            "otp_last_sent_at": ""
        }, "$set": {
            "hashed_password": hashed_password
        }}
    )
    
    return {"success": True, "message": "Password reset successfully"}

@router.post("/auth/resend-otp")
@limiter.limit("3/minute")
async def resend_otp(request: Request, data: ResendOTP):
    user = await users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    now = datetime.utcnow()
    last_sent = user.get("otp_last_sent_at")
    
    # 60s cooldown
    if last_sent and (now - last_sent).total_seconds() < 60:
        raise HTTPException(status_code=429, detail="Please wait 60 seconds before requesting another code.")
        
    otp_code = str(secrets.randbelow(900000) + 100000)
    otp_hash = hashlib.sha256(otp_code.encode()).hexdigest()
    
    await users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "otp_hash": otp_hash,
            "otp_expires_at": now + timedelta(minutes=5),
            "otp_attempts": 0,
            "otp_last_sent_at": now
        }}
    )
    
    send_otp_email(user["email"], otp_code)
    
    return {"success": True, "message": "New verification code sent"}

@router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return current_user

@router.get('/auth/resolve-username')
async def resolve_username(username: str):
    user = await users.find_one(
        {'username': username},
        projection={'email': True, '_id': False}
    )
    if not user or not user.get('email'):
        raise HTTPException(status_code=404, detail='Username not found')
    return {'email': user['email']}


@router.get("/auth/profile")
async def get_full_profile(current_user: dict = Depends(get_current_user)):
    user_dict = dict(current_user)
    if "_id" in user_dict:
        user_dict["_id"] = str(user_dict["_id"])

    username = user_dict.get("username")
    
    total = await db["sandbox_jobs"].count_documents({"submitted_by": {"$regex": f"^{username}$", "$options": "i"}})
    completed = await db["sandbox_jobs"].count_documents({"submitted_by": {"$regex": f"^{username}$", "$options": "i"}, "status": "completed"})
    pending = await db["sandbox_jobs"].count_documents({"submitted_by": {"$regex": f"^{username}$", "$options": "i"}, "status": {"$in": ["pending", "processing"]}})
    threats = await db["sandbox_jobs"].count_documents({"submitted_by": {"$regex": f"^{username}$", "$options": "i"}, "risk_score": {"$gte": 50}})

    user_dict["stats"] = {
        "total_scans": total,
        "threats_found": threats,
        "completed_scans": completed,
        "pending_scans": pending
    }
    user_dict["api_keys"] = user_dict.get("api_keys", [])

    if "created_at" in user_dict and hasattr(user_dict["created_at"], "isoformat"):
        user_dict["created_at"] = user_dict["created_at"].isoformat()

    return user_dict

@router.get("/auth/jobs/mine")
async def get_my_jobs(current_user: dict = Depends(get_current_user)):
    username = current_user.get("username")
    cursor = db["sandbox_jobs"].find({"submitted_by": username}).sort("created_at", -1).limit(20)
    jobs = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        jobs.append(doc)
    return jobs

@router.post("/auth/jobs/{job_id}/share")
async def share_job(job_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    return {"success": True}
