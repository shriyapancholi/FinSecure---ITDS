# models/audit.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id          = Column(Integer, primary_key=True, index=True)
    action      = Column(String(64), nullable=False)            # e.g., 'resume_user', 'delete_user'
    actor       = Column(String(128), nullable=False)           # who performed the action
    target_user = Column(String(128), nullable=True)            # affected username or user_id
    reason      = Column(Text, nullable=True)
    ip          = Column(String(64), nullable=True)
    user_agent  = Column(Text, nullable=True)
    extra       = Column(JSON, nullable=True)                   # any additional payload
    created_at  = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)