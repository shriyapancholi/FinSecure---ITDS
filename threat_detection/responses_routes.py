# threat_detection/responses_routes.py
import json
import joblib
from datetime import datetime
from typing import Optional, List, Sequence

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Anomaly as AnomalyModel

from .responses_service import list_responses, create_response, apply_response_action
from .responses_schema import ResponseOut
from .rule_engine import RuleEngine
from .test_logs import sample_logs

router = APIRouter(prefix="/threats", tags=["Threat Detection"])


# ----------- ML request schema -----------

class AnomalyRequest(BaseModel):
    user_id: str
    actions_per_min: Optional[float] = 0.0
    txn_amount: Optional[float] = 0.0
    ip_entropy: Optional[float] = 0.0
    cpu_z: Optional[float] = 0.0
    mem_z: Optional[float] = 0.0

    class Config:
        extra = "allow"


# ----------- Load IsolationForest model (once) -----------
_MODEL = None
_MODEL_COLUMNS: List[str] = []

try:
    loaded = joblib.load("threat_detection/model.joblib")
    # support both plain model and dict-wrapped model saved during training
    if isinstance(loaded, dict):
        # expected structure: {"model": <sklearn model>, "columns": [...]} or similar
        _MODEL = loaded.get("model") or loaded.get("estimator") or None
        cols = loaded.get("columns") or loaded.get("feature_names") or []
        if isinstance(cols, (list, tuple)):
            _MODEL_COLUMNS = list(cols)
        else:
            _MODEL_COLUMNS = []
    else:
        _MODEL = loaded
        _MODEL_COLUMNS = []
except Exception:
    _MODEL = None
    _MODEL_COLUMNS = []


# ----------- Existing endpoints -----------

@router.get("/responses", response_model=list[ResponseOut])
def get_all_responses(db: Session = Depends(get_db)):
    """Fetch the latest rule-engine responses."""
    return list_responses(db)


@router.post("/run_rules", response_model=list[ResponseOut])
def run_rules(db: Session = Depends(get_db)):
    """
    Run rule engine on sample logs (demo endpoint).
    Simulates integrity break + records detections into the responses table.
    """
    # Simulate integrity check failure (for demo)
    def fake_integrity_check():
        return False

    engine = RuleEngine(integrity_check_fn=fake_integrity_check)
    detections = engine.run(sample_logs())

    saved = []
    for d in detections:
        resp_dict = create_response(db, d.to_dict())   # save once
        saved.append(resp_dict)
        # apply response action (escalate user status if applicable)
        try:
            apply_response_action(db, resp_dict)
        except Exception:
            # keep endpoint robust — don't fail entirely if escalation fails
            pass

    return saved


# ----------- New: score_anomaly endpoint -----------

def _build_feature_vector_from_payload(payload: AnomalyRequest, columns: Sequence[str]) -> List[float]:
    """
    Build feature vector in the exact order expected by the model.
    If `columns` is empty, fall back to the default order used when training.
    """
    # default column order used during training (must match your training script)
    default_order = ["actions_per_min", "txn_amount", "ip_entropy", "cpu_z", "mem_z"]

    order = list(columns) if columns else default_order

    vec = []
    for col in order:
        val = getattr(payload, col, None)
        if val is None:
            # coerce absent numeric to 0.0
            try:
                val = float(payload.dict().get(col, 0.0))
            except Exception:
                val = 0.0
        vec.append(float(val))
    return vec


@router.post("/score_anomaly")
def score_anomaly(payload: AnomalyRequest, db: Session = Depends(get_db)):
    """
    Score the incoming feature vector with the trained IsolationForest (or similar)
    and store anomalies in the `anomalies` table.

    Returns saved anomaly record as JSON. If the ML severity is medium/high,
    create a response (rule "ml_anomaly") and attempt escalation using the
    same apply_response_action() used by the rule engine.
    """
    if _MODEL is None:
        raise HTTPException(status_code=500, detail="ML model not loaded (expected threat_detection/model.joblib)")

    # Build feature vector using columns if available (keeps training/serving order consistent)
    try:
        features = _build_feature_vector_from_payload(payload, _MODEL_COLUMNS)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid feature payload: {e}")

    # model scoring: prefer decision_function (IsolationForest), fallback to score_samples
    try:
        # sklearn's decision_function: higher = more normal -> invert to make larger = more anomalous
        if hasattr(_MODEL, "decision_function"):
            df = _MODEL.decision_function([features])
            score = float(-df[0])
        elif hasattr(_MODEL, "score_samples"):
            ss = _MODEL.score_samples([features])
            score = float(-ss[0])
        else:
            # Some custom wrappers may expose a predict_proba-like interface
            raise RuntimeError("Loaded model has no decision_function or score_samples method")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scoring failed: {e}")

    # Simple severity bucketing (tune these thresholds for your data)
    if score < 0.1:
        severity = "low"
    elif score < 0.15:
        everity = "medium"
    else:
        severity = "high"

    # Persist anomaly record to DB (features stored as JSON object)
    try:
        features_obj = {
            "user_id": payload.user_id,
            "actions_per_min": float(payload.actions_per_min or 0.0),
            "txn_amount": float(payload.txn_amount or 0.0),
            "ip_entropy": float(payload.ip_entropy or 0.0),
            "cpu_z": float(payload.cpu_z or 0.0),
            "mem_z": float(payload.mem_z or 0.0),
        }

        row = AnomalyModel(
            user_id=str(payload.user_id),
            score=float(score),
            severity=severity,
            features=json.dumps(features_obj, default=str, ensure_ascii=False),
            timestamp=datetime.utcnow()
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save anomaly: {e}")

    # ---- Auto-create response + attempt escalation for medium/high ----
    escalation_result = None
    try:
        if severity in ("medium", "high"):
            # map ML severity -> response severity (tunable)
            resp_severity = "restrict" if severity == "medium" else "suspend"
            resp = {
                "user_id": payload.user_id,
                "rule": "ml_anomaly",
                "severity": resp_severity,
                "timestamp": datetime.utcnow().isoformat(),
                "details": {"score": score, "ml_severity": severity},
            }
            saved_resp = create_response(db, resp)
            # try apply escalation (safe - it will ignore admins/unknown users)
            escalation_result = apply_response_action(db, saved_resp)
    except Exception:
        # don't fail scoring; just continue and return anomaly result
        escalation_result = None

    return {
        "id": row.id,
        "user_id": row.user_id,
        "score": row.score,
        "severity": row.severity,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "features": features_obj,
        "escalation": escalation_result,
    }