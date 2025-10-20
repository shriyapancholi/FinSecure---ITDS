# threat_detection/ml_routes.py
import os
import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import joblib
import numpy as np
from datetime import datetime

from app.database import get_db
from app import models
from logging_module.logger import ensure_logs_dir, get_file_name_for_date, _read_last_jsonl_line

router = APIRouter(prefix="/ml", tags=["ML"])

MODEL_FILE = os.path.join(os.path.dirname(__file__), "model.joblib")

def load_model():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError("ML model not found; run threat_detection/ml_model.py to train.")
    obj = joblib.load(MODEL_FILE)
    return obj["model"], obj["columns"]

def extract_features_from_record(rec: Dict[str, Any]) -> Dict[str, float]:
    # Conservative extraction: pick fields and sane defaults
    return {
        "actions_per_min": float(rec.get("actions_per_min") or rec.get("apm") or 0.0),
        "txn_amount": float(rec.get("details", {}).get("amount") or 0.0),
        "ip_entropy": float(rec.get("details", {}).get("ip_entropy") or 0.0),
        "cpu_z": float(rec.get("details", {}).get("cpu_z") or 0.0),
        "mem_z": float(rec.get("details", {}).get("mem_z") or 0.0),
    }

@router.post("/analyze_recent")
def analyze_recent_logs(n: int = 100, db: Session = Depends(get_db)):
    """
    Read last N lines of today's JSONL log file, extract features, score with IsolationForest,
    and save anomalies (score < 0) into anomalies table. Returns saved anomaly rows.
    """
    # load model
    try:
        model, columns = load_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    logs_dir = ensure_logs_dir()
    file_path = os.path.join(logs_dir, get_file_name_for_date())
    # read whole file safely
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="No log file for today")

    # read lines and take last n
    with open(file_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip()]
    if not lines:
        return {"ok": True, "anomalies_saved": 0}

    tail = lines[-n:]
    records = []
    for line in tail:
        try:
            records.append(json.loads(line))
        except Exception:
            continue

    feats = []
    ids = []
    for rec in records:
        feats.append([extract_features_from_record(rec)[c] for c in columns])
        ids.append(rec.get("user_id"))

    X = np.array(feats, dtype=float)
    preds = model.decision_function(X)  # higher -> more normal, lower -> more anomalous
    is_anom = model.predict(X)  # -1 anomaly, 1 normal

    saved = []
    for i in range(len(records)):
        if is_anom[i] == -1:
            score = float(preds[i])
            user_id = str(ids[i]) if ids[i] is not None else "unknown"
            # severity decision: more negative score -> higher severity
            severity = "soft_alert"
            if score < -0.2:
                severity = "restrict"
            if score < -0.5:
                severity = "suspend"
            if score < -1.0:
                severity = "lock_account"

            # persist to anomalies table
            from app.models import Anomaly  # import here to avoid circular import at startup
            a = Anomaly(
                user_id=user_id,
                score=score,
                severity=severity,
                features=json.dumps({col: float(val) for col, val in zip(columns, feats[i])}),
                timestamp=datetime.utcnow(),
            )
            db.add(a)
            db.commit()
            db.refresh(a)
            saved.append({
                "id": a.id,
                "user_id": a.user_id,
                "score": a.score,
                "severity": a.severity,
                "timestamp": a.timestamp.isoformat(),
            })

    return {"ok": True, "anomalies_saved": len(saved), "saved": saved}