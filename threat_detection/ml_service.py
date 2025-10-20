# threat_detection/ml_service.py
import json
from sqlalchemy.orm import Session
from .anomalies_model import Anomaly
from .ml_model import score_record

def persist_anomaly(db: Session, user_id: str, score: float, features: dict, severity: str = "medium"):
    a = Anomaly(
        user_id=str(user_id) if user_id is not None else None,
        score=float(score),
        severity=severity,
        features=features
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return a

def score_and_persist_if_needed(db: Session, record: dict, user_field="user_id"):
    """
    Score a single log record; if anomalous, persist and return the anomaly object, else None.
    """
    res = score_record(record)
    if res.get("is_anomaly"):
        score = res["score"]
        features = res.get("features", {})
        user_id = record.get(user_field)
        # severity mapping from score (simple)
        if score > 1.0:
            sev = "high"
        elif score > 0.3:
            sev = "medium"
        else:
            sev = "low"
        return persist_anomaly(db, user_id=user_id, score=score, features=features, severity=sev)
    return None