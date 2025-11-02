# auth_app.py
"""
Improved FastAPI auth app:
- bcrypt password hashing
- JWT access tokens + refresh tokens
- role-based access using Enum
- CORS middleware
- safe sqlite usage with context managers
- logs actions via log_manager.log_event(...)
"""
from financial_threats import detect_threats
import os
import sqlite3
from enum import Enum
from typing import Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt
import jwt  # PyJWT

# Your logging function (make sure log_manager.py exports log_event)
from log_manager import log_event

# ---------------- CONFIG ----------------
DB_PATH = os.getenv("FINSEC_DB", "finsecure.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ---------------- APP & CORS ----------------
app = FastAPI(title="FinSecure Auth System (improved)")

# Adjust allow_origins to real frontend domains in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # <-- tighten this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ---------------- Role Enum ----------------
class RoleEnum(str, Enum):
    user = "user"
    analyst = "analyst"
    admin = "admin"

# ---------------- Pydantic Models ----------------
class SignupModel(BaseModel):
    username: str
    password: str
    role: RoleEnum = RoleEnum.user

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: Optional[str] = None

# ---------------- DB HELPERS ----------------
def init_db():
    """Create required tables if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                last_login TEXT,
                status TEXT DEFAULT 'active'
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE,
                username TEXT,
                expires_at DATETIME
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                status TEXT,
                message TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB on import
init_db()

# ---------------- Utility: tokens ----------------
def create_access_token(username: str, role: str, minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    exp = datetime.utcnow() + timedelta(minutes=minutes)
    payload = {"sub": username, "role": role, "exp": int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(username: str, days: int = REFRESH_TOKEN_EXPIRE_DAYS):
    exp = datetime.utcnow() + timedelta(days=days)
    payload = {"sub": username, "type": "refresh", "exp": int(exp.timestamp())}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # store in DB
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO refresh_tokens (token, username, expires_at) VALUES (?, ?, ?)",
                    (token, username, exp.isoformat()))
        conn.commit()
    return token

def revoke_refresh_token(token: str):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        conn.commit()

def is_refresh_token_valid(token: str) -> bool:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT expires_at FROM refresh_tokens WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return False
        expires_at = datetime.fromisoformat(row["expires_at"])
        return datetime.utcnow() < expires_at

# ---------------- Auth logic ----------------
def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def get_user(username: str):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()

# ---------------- ENDPOINTS ----------------

@app.post("/signup", response_model=dict, status_code=201)
def signup(payload: SignupModel):
    hashed_pw = hash_password(payload.password)
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (payload.username, hashed_pw, payload.role.value))
            conn.commit()
        log_event(payload.username, "signup", "success", "User created")
        return {"msg": "User created"}
    except sqlite3.IntegrityError:
        log_event(payload.username, "signup", "failed", "Username exists")
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/token", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        log_event(form_data.username, "login", "failed", "Invalid credentials")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token(user["username"], user["role"])
    refresh_token = create_refresh_token(user["username"])

    # update last_login
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET last_login = ? WHERE username = ?", (datetime.utcnow().isoformat(), user["username"]))
        conn.commit()

    log_event(user["username"], "login", "success", "User logged in")
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str = Body(..., embed=True)):
    # verify signature and expiration first
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # ensure token is the stored, not revoked
    if not is_refresh_token_valid(refresh_token):
        raise HTTPException(status_code=401, detail="Refresh token revoked or unknown")

    username = payload.get("sub")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    # issue new access token (short lived) and optionally a new refresh token
    new_access = create_access_token(username, user["role"])
    # (Optionally rotate refresh tokens: we'll keep existing refresh token until expiry)
    log_event(username, "refresh", "success", "Access token refreshed")
    return {"access_token": new_access, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/logout", status_code=204)
def logout(refresh_token: str = Body(..., embed=True)):
    # remove refresh token from DB (revoke it)
    revoke_refresh_token(refresh_token)
    # You might also want to add an entry to logs
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except Exception:
        username = None
    log_event(username or "unknown", "logout", "success", "Refresh token revoked")
    return {}

# ---------------- Dependencies: token verify & role checker ----------------
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return {"username": payload["sub"], "role": payload["role"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def role_required(required_roles: list):
    def wrapper(user = Depends(verify_token)):
        if user["role"] not in required_roles:
            log_event(user["username"], "access_denied", "failed", f"Role {user['role']} insufficient for {required_roles}")
            raise HTTPException(status_code=403, detail="Access forbidden: insufficient role")
        return user
    return wrapper

# ---------------- Protected endpoints examples ----------------
@app.get("/me")
def me(user = Depends(verify_token)):
    return {"username": user["username"], "role": user["role"]}

@app.get("/admin/dashboard")
def admin_dashboard(user = Depends(role_required([RoleEnum.admin.value]))):
    log_event(user["username"], "access_admin_dashboard", "success", "Viewed admin dashboard")
    return {"message": "Admin dashboard"}

# ---------------- Threat Detection Endpoint ----------------
@app.post("/analyst/detect-threats")
def detect_financial_threats(transactions: list, user=Depends(role_required(["analyst", "admin"]))):
    """
    Endpoint for analysts/admins to analyze transactions and detect potential financial threats.
    """
    if not isinstance(transactions, list):
        raise HTTPException(status_code=400, detail="Invalid input format. Must be a list of transactions.")

    summary = detect_threats(transactions)
    log_event(user["username"], "detect_threats", "success", f"Detected {len(summary)} potential threats ⚠️")

    return {
        "message": "Threat detection completed",
        "detected_threats": summary
    }


@app.get("/analyst/reports")
def analyst_reports(user = Depends(role_required([RoleEnum.analyst.value, RoleEnum.admin.value]))):
    log_event(user["username"], "access_reports", "success", "Viewed analyst reports")
    return {"message": "Analyst reports"}
