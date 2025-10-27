from pydantic import BaseModel, Field, ConfigDict
from typing import Literal
from datetime import datetime, date

# ----- USER -----
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=64)
    role: Literal["admin", "analyst", "user"]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "test_user_545",
                "password": "test123",
                "role": "admin"
            }
        }
    )

class UserResponse(BaseModel):
    id: int
    username: str
    role: Literal["admin", "analyst", "user"]
    status: Literal["active", "restricted", "suspended", "locked"]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ----- AUTH -----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str


# ----- LOGGING -----
class LogCreate(BaseModel):
    user_id: int
    action: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"user_id": 1, "action": "LOGIN_SUCCESS"}
        }
    )

class LogResponse(BaseModel):  # renamed from LogOut
    id: int
    user_id: int
    action: str
    timestamp: datetime
    hash: str

    model_config = ConfigDict(from_attributes=True)


# ----- INTEGRITY -----
class LogIntegrityOut(BaseModel):
    id: int
    file_date: date
    final_hash: str
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)