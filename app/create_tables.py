# app/models.py
from datetime import datetime
import json
from sqlalchemy import (
    Column,
    Integer,
    String,
    Enum,
    DateTime,
    Date,
    ForeignKey,
    Text,
    Float,        # <-- imported Float
    text,
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base

STATUS_VALUES = ("active", "restricted", "suspended", "locked")
ROLE_VALUES = ("admin", "analyst", "user")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

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

    logs = relationship("Log", back_populates="user", cascade="all, delete-orphan")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(255), nullable=False)
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    hash = Column(String(64), nullable=False, index=True)

    user = relationship("User", back_populates="logs")


class LogIntegrity(Base):
    __tablename__ = "log_integrity"

    id = Column(Integer, primary_key=True, index=True)
    file_date = Column(Date, unique=True, nullable=False, index=True)
    final_hash = Column(String(64), nullable=False)
    verified_at = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class ResponseModel(Base):
    """
    Rule-engine responses / automated actions table.
    Stored as JSON-text in `details` for compatibility.
    """
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(128), nullable=False, index=True)
    rule = Column(String(128), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    details = Column(Text, nullable=True)

    def to_dict(self):
        try:
            details = json.loads(self.details) if self.details else {}
        except Exception:
            details = {"raw": self.details}
        return {
            "id": self.id,
            "user_id": self.user_id,
            "rule": self.rule,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": details,
        }


class Anomaly(Base):
    __tablename__ = "anomalies"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(128), nullable=False, index=True)
    score = Column(Float, nullable=False)                # <- use Float
    severity = Column(String(32), nullable=False)
    features = Column(Text)   # store JSON string
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


Index("ix_logs_user_timestamp", Log.user_id, Log.timestamp)