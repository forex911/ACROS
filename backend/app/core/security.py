from datetime import datetime, timedelta
from typing import Optional
import uuid

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_jti() -> str:
    return str(uuid.uuid4())


def create_access_token(subject: str, scopes: Optional[list] = None, expires_delta: Optional[timedelta] = None) -> dict:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.utcnow()
    exp = now + expires_delta
    jti = create_jti()
    to_encode = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "jti": jti}
    if scopes:
        to_encode["scopes"] = scopes
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "jti": jti, "expires_at": int(exp.timestamp())}


def create_refresh_token(subject: str, expires_days: Optional[int] = None) -> dict:
    if expires_days is None:
        expires_days = REFRESH_TOKEN_EXPIRE_DAYS
    now = datetime.utcnow()
    exp = now + timedelta(days=expires_days)
    jti = create_jti()
    to_encode = {"sub": subject, "iat": int(now.timestamp()), "exp": int(exp.timestamp()), "jti": jti, "type": "refresh"}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"refresh_token": token, "jti": jti, "expires_at": int(exp.timestamp())}


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as exc:
        raise
