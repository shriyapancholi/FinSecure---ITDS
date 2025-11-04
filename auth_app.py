# auth_app.py
"""
Improved FastAPI auth app with rule-based anomaly detection.
Rules implemented:
- LOW: exactly 2 failed logins in 15 min, OR odd-hour (01–05) successful login
- MEDIUM: 3–4 failed logins in 15 min, OR successful login from a new device (User-Agent change)
- HIGH: >=5 failed logins in 15 min -> auto-suspend user
Also:
- persists anomalies to sqlite table `anomalies`
- keeps local `auth_logs` for counting
- stores last_user_agent in users to detect new devices
"""
from financial_threats import detect_threats
import os
import sqlite3
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status, Body, Request, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt
import jwt  # PyJWT
import json
from dotenv import load_dotenv

load_dotenv()
# external logger (your existing module)
from log_manager import log_event

# ---------------- CONFIG ----------------
DB_PATH = os.getenv("FINSEC_DB", "finsecure.db")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ADMIN_SECRET = os.getenv("sentienl@admin123") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Rule params
LOCKOUT_WINDOW_MINUTES = 15
SUSPEND_ON_FAILS = 5  # threshold for HIGH + suspend

# ---------------- APP & CORS ----------------
app = FastAPI(title="FinSecure Auth System (with anomalies)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
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
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create required tables if they don't exist and apply simple migrations."""
    with get_db() as conn:
        cur = conn.cursor()
        # users
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                last_login TEXT,
                status TEXT DEFAULT 'active',
                last_user_agent TEXT
            )
        """)
        # refresh tokens
        cur.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE,
                username TEXT,
                expires_at DATETIME
            )
        """)
        # local auth logs (used by rules)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip TEXT,
                user_agent TEXT,
                action TEXT,       -- signup/login/logout
                status TEXT,       -- success/failed/blocked
                message TEXT,
                ts DATETIME
            )
        """)
        # anomalies for dashboard
        cur.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                severity TEXT,       -- high/medium/low
                score REAL,
                details TEXT,        -- JSON
                created_at DATETIME
            )
        """)
        conn.commit()

# run migrations at import
init_db()

# ---------------- Utility ----------------
def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def save_auth_log(username: Optional[str], ip: str, ua: str, action: str, status_: str, message: str):
    """Local resilient log store for rule counting."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO auth_logs (username, ip, user_agent, action, status, message, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, ip, ua, action, status_, message, now_iso())
            )
            conn.commit()
    except Exception:
        # never break flow because of logging
        pass

def create_access_token(username: str, role: str, minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    exp = datetime.utcnow() + timedelta(minutes=minutes)
    payload = {"sub": username, "role": role, "exp": int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(username: str, days: int = REFRESH_TOKEN_EXPIRE_DAYS):
    exp = datetime.utcnow() + timedelta(days=days)
    payload = {"sub": username, "type": "refresh", "exp": int(exp.timestamp())}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO refresh_tokens (token, username, expires_at) VALUES (?, ?, ?)",
            (token, username, exp.isoformat())
        )
        conn.commit()
    return token

def revoke_refresh_token(token: str):
    with get_db() as conn:
        conn.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        conn.commit()

def is_refresh_token_valid(token: str) -> bool:
    with get_db() as conn:
        row = conn.execute("SELECT expires_at FROM refresh_tokens WHERE token = ?", (token,)).fetchone()
        if not row:
            return False
        return datetime.utcnow() < datetime.fromisoformat(row["expires_at"])

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def get_user(username: str):
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

def set_user_status(username: str, status_: str):
    with get_db() as conn:
        conn.execute("UPDATE users SET status = ? WHERE username = ?", (status_, username))
        conn.commit()

def update_user_last_ua(username: str, ua: str):
    with get_db() as conn:
        conn.execute("UPDATE users SET last_user_agent = ? WHERE username = ?", (ua, username))
        conn.commit()

def count_recent_failed(username: str, ip: str, minutes: int = LOCKOUT_WINDOW_MINUTES) -> int:
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM auth_logs
            WHERE status='failed'
              AND action='login'
              AND ts >= ?
              AND (username = ? OR ip = ?)
            """,
            (cutoff.strftime("%Y-%m-%d %H:%M:%S"), username, ip)
        ).fetchone()
        return int(row["cnt"] if row else 0)

def raise_anomaly(username: Optional[str], severity: str, score: float, details: Dict[str, Any]):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO anomalies (username, severity, score, details, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, severity, float(score), json.dumps(details, ensure_ascii=False), now_iso())
            )
            conn.commit()
    except Exception:
        pass

# ---------------- ENDPOINTS ----------------
@app.post("/signup", response_model=dict, status_code=201)
def signup(payload: SignupModel, request: Request):
    hashed_pw = hash_password(payload.password)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password, role, status, last_user_agent) VALUES (?, ?, ?, 'active', NULL)",
                (payload.username, hashed_pw, payload.role.value)
            )
            conn.commit()
        # logs (external + local)
        log_event(payload.username, "signup", "success", "User created")
        ip = request.headers.get("X-Forwarded-For", request.client.host)
        ua = request.headers.get("User-Agent", "-")
        save_auth_log(payload.username, ip, ua, "signup", "success", "User created")
        return {"msg": "User created"}
    except sqlite3.IntegrityError:
        log_event(payload.username, "signup", "failed", "Username exists")
        ip = request.headers.get("X-Forwarded-For", request.client.host)
        ua = request.headers.get("User-Agent", "-")
        save_auth_log(payload.username, ip, ua, "signup", "failed", "Username exists")
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/token", response_model=TokenResponse)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    ip = request.headers.get("X-Forwarded-For", request.client.host)
    ua = request.headers.get("User-Agent", "-")
    username = form_data.username

    user = get_user(username)

    # If user exists but is suspended -> block immediately
    if user and (user["status"] or "active") != "active":
        msg = "Account suspended"
        log_event(username, "login", "blocked", msg)
        save_auth_log(username, ip, ua, "login", "blocked", msg)
        raise HTTPException(status_code=403, detail=msg)

    # Wrong creds path
    if (not user) or (not verify_password(form_data.password, user["password"])):
        log_event(username, "login", "failed", "Invalid credentials")
        save_auth_log(username, ip, ua, "login", "failed", "Invalid credentials")

        # ---- RULES on failure (window-based) ----
        fails = count_recent_failed(username, ip, LOCKOUT_WINDOW_MINUTES)

        if fails == 2:
            raise_anomaly(username, "low", 0.4, {
                "reason": "multiple_failed_attempts",
                "failed_count": fails,
                "window_minutes": LOCKOUT_WINDOW_MINUTES,
                "ip": ip
            })
        elif 3 <= fails <= 4:
            raise_anomaly(username, "medium", 0.7, {
                "reason": "brute_force_suspected",
                "failed_count": fails,
                "window_minutes": LOCKOUT_WINDOW_MINUTES,
                "ip": ip
            })
        elif fails >= SUSPEND_ON_FAILS:
            # HIGH + suspend
            raise_anomaly(username, "high", 1.0, {
                "reason": "failed_login_threshold",
                "failed_count": fails,
                "window_minutes": LOCKOUT_WINDOW_MINUTES,
                "ip": ip,
                "auto_action": "suspend_user"
            })
            if user:
                set_user_status(username, "suspended")

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # ---- Success path ----
    # Odd-hour success (low)
    hour = datetime.utcnow().hour
    if 1 <= hour <= 5:
        raise_anomaly(username, "low", 0.35, {
            "reason": "odd_hour_login",
            "hour_utc": hour,
            "ip": ip
        })

    # New device / UA change (medium)
    last_ua = user["last_user_agent"]
    if last_ua and last_ua != ua:
        raise_anomaly(username, "medium", 0.6, {
            "reason": "new_device_login",
            "prev_user_agent": last_ua,
            "new_user_agent": ua,
            "ip": ip
        })

    # Issue tokens
    access_token = create_access_token(user["username"], user["role"])
    refresh_token = create_refresh_token(user["username"])

    # Update last_login and last_user_agent
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login = ?, last_user_agent = ?, status = 'active' WHERE username = ?",
            (now_iso(), ua, user["username"])
        )
        conn.commit()

    # logs
    log_event(user["username"], "login", "success", "User logged in")
    save_auth_log(user["username"], ip, ua, "login", "success", "User logged in")

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/refresh", response_model=TokenResponse)
def refresh(refresh_token: str = Body(..., embed=True)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if not is_refresh_token_valid(refresh_token):
        raise HTTPException(status_code=401, detail="Refresh token revoked or unknown")

    username = payload.get("sub")
    user = get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")

    new_access = create_access_token(username, user["role"])
    log_event(username, "refresh", "success", "Access token refreshed")
    return {"access_token": new_access, "token_type": "bearer", "refresh_token": refresh_token}

@app.post("/logout", status_code=204)
def logout(refresh_token: str = Body(..., embed=True)):
    revoke_refresh_token(refresh_token)
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

# ---------------- Protected examples ----------------
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
    if not isinstance(transactions, list):
        raise HTTPException(status_code=400, detail="Invalid input format. Must be a list of transactions.")
    summary = detect_threats(transactions)
    log_event(user["username"], "detect_threats", "success", f"Detected {len(summary)} potential threats ⚠️")
    return {"message": "Threat detection completed", "detected_threats": summary}

@app.get("/analyst/reports")
def analyst_reports(user = Depends(role_required([RoleEnum.analyst.value, RoleEnum.admin.value]))):
    log_event(user["username"], "access_reports", "success", "Viewed analyst reports")
    return {"message": "Analyst reports"}

# ---------------- Admin utility to resume a user ----------------
@app.post("/admin/users/{username}/resume")
def admin_resume_user(
    username: str = Path(...),
    user = Depends(role_required([RoleEnum.admin.value]))
):
    target = get_user(username)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    set_user_status(username, "active")
    log_event(user["username"], "resume_user", "success", f"Resumed {username}")
    return {"message": f"{username} resumed"}