# app/schemas.py

from pydantic import BaseModel, Field, ConfigDict
from typing import Literal, Optional
from datetime import datetime, date


# ==========================================================
# USERS
# ==========================================================
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=64)
    role: Literal["admin", "analyst", "user"]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "alice_admin",
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


# ==========================================================
# AUTHENTICATION
# ==========================================================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


# ==========================================================
# LOGGING
# ==========================================================
class LogCreate(BaseModel):
    user_id: int
    action: str
    details: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": 1,
                "action": "LOGIN_SUCCESS",
                "details": "User logged in successfully"
            }
        }
    )


class LogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    details: Optional[str]
    timestamp: datetime
    prev_hash: Optional[str]
    hash: str

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# LOG INTEGRITY
# ==========================================================
class LogIntegrityOut(BaseModel):
    id: int
    file_date: date
    final_hash: str
    verified_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# ANOMALIES (Daemon or ML)
# ==========================================================
class AnomalyBase(BaseModel):
    source: Optional[str] = Field(None, description="Source: daemon, financial_engine, ml_model, etc.")
    user_id: Optional[int] = None
    score: Optional[float] = None
    severity: Literal["low", "medium", "high"] = "medium"
    details: Optional[str] = None
    metric_json: Optional[str] = None


class AnomalyCreate(AnomalyBase):
    pass


class AnomalyResponse(AnomalyBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# RESPONSES (Rule Engine)
# ==========================================================
class ResponseBase(BaseModel):
    anomaly_id: Optional[int] = None
    action_taken: str
    target_user_id: Optional[int] = None
    details: Optional[str] = None


class ResponseCreate(ResponseBase):
    pass


class ResponseOut(ResponseBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


# ==========================================================
# SYSTEM METRICS (Daemon)
# ==========================================================
class SystemMetricBase(BaseModel):
    cpu: float
    memory: float


class SystemMetricCreate(SystemMetricBase):
    pass


class SystemMetricOut(SystemMetricBase):
    id: int
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)