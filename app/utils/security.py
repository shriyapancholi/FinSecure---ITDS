import os
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

import bcrypt
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# Load environment variables
load_dotenv()

# Constants
_BCRYPT_MAX_BYTES = 72
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
ALGO = os.getenv("JWT_ALGO", "HS256")
ACCESS_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ISSUER = os.getenv("JWT_ISS", None)
AUDIENCE = os.getenv("JWT_AUD", None)

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY missing – add it to .env")


# --------------------------
# 🧠 PASSWORD HASHING
# --------------------------

def _truncate_to_bytes(s: Optional[str], max_bytes: int = _BCRYPT_MAX_BYTES) -> Optional[str]:
    """Ensure string’s UTF-8 encoding ≤ max_bytes by truncating safely."""
    if s is None:
        return None
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s
    truncated = b[:max_bytes]
    while True:
        try:
            return truncated.decode("utf-8")
        except UnicodeDecodeError:
            truncated = truncated[:-1]


def hash_password(password: str) -> str:
    """Truncate then hash password using bcrypt (returns utf-8 string)."""
    if password is None:
        raise ValueError("Password cannot be None")
    safe = _truncate_to_bytes(password, _BCRYPT_MAX_BYTES)
    safe_bytes = safe.encode("utf-8")
    hashed = bcrypt.hashpw(safe_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password using bcrypt after truncation."""
    if password is None or hashed is None:
        return False
    safe = _truncate_to_bytes(password, _BCRYPT_MAX_BYTES)
    safe_bytes = safe.encode("utf-8")
    hashed_bytes = hashed.encode("utf-8") if isinstance(hashed, str) else hashed
    try:
        return bcrypt.checkpw(safe_bytes, hashed_bytes)
    except ValueError:
        return False


# --------------------------
# 🔐 JWT AUTHENTICATION
# --------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def create_access_token(payload: Dict[str, Any], minutes: int = ACCESS_MIN) -> str:
    """Generate a signed JWT access token."""
    now = datetime.now(timezone.utc)
    to_encode = payload.copy()

    if "sub" not in to_encode:
        if "user_id" in to_encode:
            to_encode["sub"] = str(to_encode["user_id"])
        elif "username" in to_encode:
            to_encode["sub"] = to_encode["username"]

    to_encode.update({
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    })

    if ISSUER:
        to_encode.setdefault("iss", ISSUER)
    if AUDIENCE:
        to_encode.setdefault("aud", AUDIENCE)

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGO)


def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate JWT token."""
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGO],
            audience=AUDIENCE if AUDIENCE else None,
            issuer=ISSUER if ISSUER else None,
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    """Extract user_id (sub) from JWT token."""
    try:
        payload = decode_token(token)
        user_id = payload.get("sub") or payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Missing user ID in token")
        return str(user_id)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )