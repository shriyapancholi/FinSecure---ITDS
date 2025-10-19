# threat_detection/responses_service.py
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models import ResponseModel

def _ensure_details_dict(d: Optional[Any]) -> Dict[str, Any]:
    """
    Ensure we persist a JSON-serializable dict.
    If caller passed a dict -> keep it.
    If caller passed None -> empty dict.
    Otherwise stringify into {"value": "..."}.
    """
    if d is None:
        return {}
    if isinstance(d, dict):
        return d
    # if it's already JSON text
    if isinstance(d, str):
        try:
            parsed = json.loads(d)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    # fallback: wrap non-dict into value
    return {"value": str(d)}

def create_response(db: Session, data: dict) -> dict:
    """
    Persist a response and return a JSON-serializable dict suitable
    for the ResponseOut schema (details as a dict).
    """
    details = _ensure_details_dict(data.get("details"))
    # store details as JSON text in DB
    resp_row = ResponseModel(
        user_id=str(data.get("user_id", "")),
        rule=str(data.get("rule", "")),
        severity=str(data.get("severity", "")),
        # allow caller to pass timestamp; ResponseModel has server_default but accept explicit timestamp
        timestamp=data.get("timestamp"),
        details=json.dumps(details, default=str, ensure_ascii=False),
    )
    db.add(resp_row)
    db.commit()
    db.refresh(resp_row)
    # return dict (ResponseModel.to_dict gives parsed details)
    return resp_row.to_dict()

def list_responses(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return recent responses as list of dicts (each dict matches ResponseOut).
    """
    rows = db.query(ResponseModel).order_by(ResponseModel.timestamp.desc()).limit(limit).all()
    return [row.to_dict() for row in rows]
