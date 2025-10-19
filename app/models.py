# app/models.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, Enum, DateTime, Date, ForeignKey, text, Index
from sqlalchemy.orm import relationship
from app.database import Base

STATUS_VALUES = ("active", "restricted", "suspended", "locked")
ROLE_VALUES = ("admin", "analyst", "user")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    # renamed to match auth code naming used elsewhere: "hashed_password"
    hashed_password = Column(String(255), nullable=False)

    # enum names should match any existing DB enum names (role_enum, status_enum)
    role = Column(Enum(*ROLE_VALUES, name="role_enum"), nullable=False)

    status = Column(
        Enum(*STATUS_VALUES, name="status_enum"),
        nullable=False,
        server_default=text("'active'"),
    )

    created_at = Column(
        DateTime(timezone=False),           # MySQL DATETIME (no timezone)
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )

    # relationship for convenience (optional)
    logs = relationship("Log", back_populates="user", cascade="all, delete-orphan")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    # foreign key to users table for integrity
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    action = Column(String(255), nullable=False)
    # store timestamp with DB default to avoid mismatches
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    # SHA-256 hex is 64 chars
    # Note: name 'hash' is okay but shadows builtin 'hash' — keep if other code expects this column name.
    hash = Column(String(64), nullable=False, index=True)

    # optional relationship back to User
    user = relationship("User", back_populates="logs")


class LogIntegrity(Base):
    __tablename__ = "log_integrity"

    id = Column(Integer, primary_key=True, index=True)
    file_date = Column(Date, unique=True, nullable=False, index=True)
    final_hash = Column(String(64), nullable=False)
    verified_at = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


# Extra indexes (if helpful)
Index("ix_logs_user_timestamp", Log.user_id, Log.timestamp)