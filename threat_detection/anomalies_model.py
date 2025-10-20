# threat_detection/anomalies_model.py
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, text
from datetime import datetime
from app.database import Base

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    # keep user id flexible (string)
    user_id = Column(String(128), nullable=True, index=True)
    score = Column(Float, nullable=False)   # IsolationForest score (lower => more anomalous)
    severity = Column(String(32), nullable=False)  # "low"/"medium"/"high"
    features = Column(JSON, nullable=True)  # store features snapshot
    timestamp = Column(DateTime(timezone=False), nullable=False, server_default=text("CURRENT_TIMESTAMP"))

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "score": self.score,
            "severity": self.severity,
            "features": self.features,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }