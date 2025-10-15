from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
from datetime import datetime

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: Literal["admin", "analyst", "user"]
    model_config = {
        "json_schema_extra": {
            "example": {"username": "test_user_545", "password": "test123", "role": "admin"}
        }
    }

class UserResponse(BaseModel):
    id: int
    username: str
    role: Literal["admin", "analyst", "user"]
    status: Literal["active", "restricted", "suspended", "locked"]
    created_at: datetime

    # 👇 lets Pydantic read attributes from a SQLAlchemy model instance
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str
    # FILE: app/schemas.py

class LogCreate(BaseModel):
    user_id: int
    action: str


class LogOut(BaseModel):
    id: int
    user_id: int
    action: str
    timestamp: datetime
    hash: str

    class Config:
        orm_mode = True


class LogIntegrityOut(BaseModel):
    id: int
    file_date: date
    final_hash: str
    verified_at: datetime

    class Config:
        orm_mode = True
