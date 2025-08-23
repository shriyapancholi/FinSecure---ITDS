from typing import Annotated, List
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Header, status, Body
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app import models, database, schemas
from app.utils.security import hash_password, verify_password, create_access_token, decode_token

app = FastAPI(title="Insider Threat System API", version="0.1.0")

bearer_scheme = HTTPBearer(description="Paste JWT from /auth/login")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten for your frontend later
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,       # optional; useful if you ever use cookies
)

# ----- DB -----
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----- Misc -----
@app.get("/")
def home():
    return {"message": "Insider Threat System running... 🚀"}

@app.get("/health")
def health():
    return {"ok": True}

# ----- USERS -----
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
        password_hash=hash_password(user.password),
        role=user.role,
        status="active",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Fallback in case DB default isn't set yet (prevents 500 on response)
    if getattr(new_user, "created_at", None) is None:
        new_user.created_at = datetime.utcnow()

    return schemas.UserResponse.model_validate(new_user)

@app.get("/users/", response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    # validate eagerly to avoid lazy-load issues
    return [schemas.UserResponse.model_validate(u) for u in users]

# ----- AUTH -----
@app.post("/auth/login", response_model=schemas.Token)
def login(
    form: Annotated[schemas.LoginRequest, Body(...)],
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token({"sub": user.username, "role": user.role, "uid": user.id})
    return {"access_token": token, "token_type": "bearer"}

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_roles(*roles):
    def guard(user = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return guard

@app.get("/me")
def me(user = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

@app.get("/admin/ping")
def admin_ping(user = Depends(require_roles("admin"))):
    return {"ok": True, "by": user.username}