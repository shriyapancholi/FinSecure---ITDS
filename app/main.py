from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from app import models, database, schemas

app = FastAPI()

# DB session dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def home():
    return {"message": "Insider Threat System running... 🚀"}

# Create user (plain password for now; we’ll hash later)
@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    new_user = models.User(
        username=user.username,
        password_hash=user.password,   # TODO: replace with hashed password later
        role=user.role,
        status="active",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# List users
@app.get("/users/", response_model=list[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()
