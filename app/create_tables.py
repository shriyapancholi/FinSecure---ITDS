# app/models.py
from datetime import datetime, date
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
    Float,
    text,
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base

# enum choices
STATUS_VALUES = ("active", "restricted", "suspended", "locked")
ROLE_VALUES = ("admin", "analyst", "user")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)   # standardized name
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
    anomalies = relationship("Anomaly", back_populates="user", cascade="all, delete-orphan")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=False, index=True)

    user = relationship("User", back_populates="logs")


class LogIntegrity(Base):
    __tablename__ = "log_integrity"

    id = Column(Integer, primary_key=True, index=True)
    file_date = Column(Date, unique=True, nullable=False, index=True)
    final_hash = Column(String(64), nullable=False)
    verified_at = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


class Response(Base):
    __tablename__ = "responses"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"), nullable=True, index=True)
    action_taken = Column(String(255), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))

    # relationships (optional)
    # anomaly = relationship("Anomaly", back_populates="responses")
    # target_user = relationship("User")


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(64), nullable=True)            # e.g. "daemon", "financial_engine", "ml_model"
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    score = Column(Float, nullable=True)                  # ML score if available
    severity = Column(String(32), nullable=False, server_default=text("'medium'"))
    details = Column(Text, nullable=True)                 # human readable details
    metric_json = Column(Text, nullable=True)             # raw JSON of metrics
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))

    user = relationship("User", back_populates="anomalies")
    # responses = relationship("Response", back_populates="anomaly")


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    cpu = Column(Float, nullable=False)
    memory = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))


# Useful index for querying logs by user + time
Index("ix_logs_user_timestamp", Log.user_id, Log.timestamp)
