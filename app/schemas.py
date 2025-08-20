# app/schemas.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    status: Optional[str] = "active"
    created_at: Optional[datetime]

    class Config:
        from_attributes = True