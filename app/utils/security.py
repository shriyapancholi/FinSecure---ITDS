# app/utils/security.py
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from jose import jwt, JWTError  # use python-jose explicitly
from passlib.context import CryptContext
from dotenv import load_dotenv

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

load_dotenv()

# ---- Password hashing (bcrypt) ----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ---- JWT settings ----
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")  # set in .env in prod
ALGO = os.getenv("JWT_ALGO", "HS256")
ACCESS_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ISSUER = os.getenv("JWT_ISS", None)      # optional
AUDIENCE = os.getenv("JWT_AUD", None)    # optional

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")  # adjust if your login route differs

def create_access_token(payload: Dict[str, Any], minutes: int = ACCESS_MIN) -> str:
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    to_encode.setdefault("iat", int(now.timestamp()))
    to_encode["exp"] = int((now + timedelta(minutes=minutes)).timestamp())
    if ISSUER:
        to_encode.setdefault("iss", ISSUER)
    if AUDIENCE:
        to_encode.setdefault("aud", AUDIENCE)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGO)

def decode_token(token: str) -> Dict[str, Any]:
    options = {"verify_aud": bool(AUDIENCE)}
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGO],
        audience=AUDIENCE if AUDIENCE else None,
        issuer=ISSUER if ISSUER else None,
        options=options,
    )

# NEW: safe dependency that returns 401 instead of 500
async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise cred_exc
        return str(user_id)
    except JWTError:
        raise cred_exc