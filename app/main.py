# app/main.py
import asyncio
from datetime import datetime, date, timedelta, time as dt_time
from typing import Annotated, List
from functools import partial
import os

from fastapi import (
    FastAPI, Request, Depends, HTTPException, status, Body
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import models, database, schemas
from app.utils.security import (
    hash_password, verify_password,
    create_access_token, decode_token
)
from app.database import SessionLocal
from logging_module.logger import create_db_log
from logging_module import integrity_check
from logging_module.integrity_check import (
    verify_file_chain, verify_all_logs, seal_and_record
)
from logging_module.logger import ensure_logs_dir, get_file_name_for_date

from app.utils.rbac import require_roles, admin_prefix_middleware_factory

# --------------------------------------------------
# FastAPI App Initialization
# --------------------------------------------------
app = FastAPI(
    title="Insider Threat System API",
    version="0.1.0",
    description="FinSecure backend — Auth, RBAC, Logging, and Threat Detection 🚀",
)

# Optional: enforce admin role for /admin/* paths
# AdminMiddleware = admin_prefix_middleware_factory(("admin",))
# app.add_middleware(AdminMiddleware)


# --------------------------------------------------
# Middleware: Async Logging of Every Request
# --------------------------------------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)

    async def _log():
        user_id = 0
        action = f"{request.method} {request.url.path}"
        await run_in_threadpool(partial(create_db_log, user_id=user_id, action=action))

    asyncio.create_task(_log())
    return response


# --------------------------------------------------
# CORS Middleware
# --------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# --------------------------------------------------
# Database Dependency
# --------------------------------------------------
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------
# Basic Health Routes
# --------------------------------------------------
@app.get("/")
def home():
    return {"message": "Insider Threat System running... 🚀"}


@app.get("/health")
def health():
    return {"ok": True}


# --------------------------------------------------
# USERS
# --------------------------------------------------
@app.post("/users/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user: Annotated[schemas.UserCreate, Body(...)],
    db: Session = Depends(get_db),
):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="Username already registered")

    new_user = models.User(
        username=user.username,
        hashed_password=hash_password(user.password),
        role=user.role,
        status="active",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    if getattr(new_user, "created_at", None) is None:
        new_user.created_at = datetime.utcnow()

    return schemas.UserResponse.model_validate(new_user)


@app.get("/users/", response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return [schemas.UserResponse.model_validate(u) for u in users]


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------
@app.post("/auth/login", response_model=schemas.Token)
def login(
    form: Annotated[schemas.LoginRequest, Body(...)],
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token({
        "sub": user.username,
        "role": user.role,
        "uid": user.id,
        "user_id": user.id,
    })
    return {"access_token": token, "token_type": "bearer"}


# --------------------------------------------------
# AUTH HELPERS (JWT + ROLE GUARD)
# --------------------------------------------------
bearer_scheme = HTTPBearer(description="Paste JWT from /auth/login")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_roles_db(*roles):
    def _dep(payload=Depends(require_roles(*roles)), db: Session = Depends(get_db)):
        username = payload.get("sub")
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    return _dep


# --------------------------------------------------
# USER SELF + ADMIN ROUTES
# --------------------------------------------------
@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@app.get("/admin/ping")
def admin_ping(user=Depends(require_roles_db("admin"))):
    return {"ok": True, "by": user.username}


# --------------------------------------------------
# ADMIN LOGGING & INTEGRITY ROUTES
# --------------------------------------------------
@app.get("/admin/logs/verify")
def admin_verify_log(target_date: str | None = None, user=Depends(require_roles_db("admin"))):
    """
    Verify the per-day log file for `target_date` (YYYY-MM-DD). Defaults to today.
    """
    if target_date:
        try:
            d = date.fromisoformat(target_date)
        except Exception:
            raise HTTPException(status_code=400, detail="target_date must be YYYY-MM-DD")
    else:
        d = date.today()

    logs_dir = ensure_logs_dir()
    file_path = os.path.join(logs_dir, get_file_name_for_date(d))
    return verify_file_chain(file_path)


@app.get("/admin/logs/verify_all")
def admin_verify_all(user=Depends(require_roles_db("admin"))):
    """Verify all JSONL log files in the logs directory."""
    return integrity_check.verify_all_logs()


@app.post("/admin/logs/seal")
def admin_seal_logs(
    target_date: str | None = None,
    user=Depends(require_roles_db("admin")),
):
    """Seal a day’s log after verifying it."""
    if target_date:
        try:
            tdate = date.fromisoformat(target_date)
        except ValueError:
            raise HTTPException(status_code=400, detail="target_date must be YYYY-MM-DD")
    else:
        tdate = date.today()

    li = seal_and_record(target_date=tdate)
    if li is None:
        return {"ok": False, "detail": "No logs found or verification failed/already sealed."}
    return {"ok": True, "file_date": str(li.file_date), "final_hash": li.final_hash}


@app.get("/admin/logs/integrity")
def admin_list_integrity(user=Depends(require_roles_db("admin")), db: Session = Depends(get_db)):
    """List recorded integrity hashes."""
    entries = db.query(models.LogIntegrity).order_by(models.LogIntegrity.file_date.desc()).all()
    return [schemas.LogIntegrityOut.model_validate(e) for e in entries]


# --------------------------------------------------
# BACKGROUND DAILY SEAL LOOP (AUTO-SEAL)
# --------------------------------------------------
DAILY_SEAL_HOUR = int(os.getenv("DAILY_SEAL_HOUR", "0"))   # default midnight
DAILY_SEAL_MINUTE = int(os.getenv("DAILY_SEAL_MINUTE", "5"))  # default 00:05

async def _daily_seal_loop():
    """Background task: seals yesterday’s log daily at configured time."""
    await asyncio.sleep(2)
    while True:
        now = datetime.now()
        next_run = datetime.combine(now.date(), dt_time(DAILY_SEAL_HOUR, DAILY_SEAL_MINUTE))
        if next_run <= now:
            next_run += timedelta(days=1)
        wait_seconds = (next_run - now).total_seconds()
        await asyncio.sleep(wait_seconds)

        try:
            target = date.today() - timedelta(days=1)
            li = seal_and_record(target_date=target)
            if li:
                print(f"✅ Auto-sealed log for {target}: {li.final_hash[:10]}")
            else:
                print(f"⚠️ Skipped sealing {target} (already sealed or missing logs)")
        except Exception as e:
            print("❌ Auto-seal failed:", repr(e))

@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(_daily_seal_loop())


# --------------------------------------------------
# END OF FILE
# --------------------------------------------------