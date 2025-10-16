# app/models.py (fixed)

from datetime import datetime
from sqlalchemy import Column, Integer, String, Enum, DateTime, Date, text
from app.database import Base

STATUS_VALUES = ("active", "restricted", "suspended", "locked")
ROLE_VALUES = ("admin", "analyst", "user")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    role = Column(Enum(*ROLE_VALUES, name="role_enum"), nullable=False)

    status = Column(
        Enum(*STATUS_VALUES, name="status_enum"),
        nullable=False,
        server_default=text("'active'"),
    )

    created_at = Column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    hash = Column(String(255), nullable=False)

class LogIntegrity(Base):
    __tablename__ = "log_integrity"

    id = Column(Integer, primary_key=True, index=True)
    file_date = Column(Date, unique=True, nullable=False)
    final_hash = Column(String(255), nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow)