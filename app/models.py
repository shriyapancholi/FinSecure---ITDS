from sqlalchemy import Column, Integer, String, DateTime, Enum
from app.database import Base
from datetime import datetime
import enum

class UserStatus(enum.Enum):
    active = "active"
    restricted = "restricted"
    suspended = "suspended"
    locked = "locked"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.active)
    created_at = Column(DateTime, default=datetime.utcnow)