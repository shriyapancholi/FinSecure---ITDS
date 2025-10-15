from sqlalchemy import Column, Integer, String, Enum, DateTime, text
from app.database import Base

STATUS_VALUES = ("active", "restricted", "suspended", "locked")
ROLE_VALUES = ("admin", "analyst", "user")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # enum names should match what’s already in the DB (role_enum, status_enum)
    role = Column(Enum(*ROLE_VALUES, name="role_enum"), nullable=False)

    status = Column(
        Enum(*STATUS_VALUES, name="status_enum"),
        nullable=False,
        server_default=text("'active'"),    # aligns with DB default
    )

    created_at = Column(
        DateTime(timezone=False),           # MySQL DATETIME (no timezone)
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),  # aligns with DB default
    )
    # FILE: app/models.py

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    hash = Column(String, nullable=False)


class LogIntegrity(Base):
    __tablename__ = "log_integrity"

    id = Column(Integer, primary_key=True, index=True)
    file_date = Column(Date, unique=True, nullable=False)
    final_hash = Column(String, nullable=False)
    verified_at = Column(DateTime, default=datetime.utcnow)
