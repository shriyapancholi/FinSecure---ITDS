# threat_detection/responses_service.py
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime

from app.models import ResponseModel, User

# ------------------ helpers ------------------
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
    if isinstance(d, str):
        try:
            parsed = json.loads(d)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {"value": str(d)}


# ------------------ core CRUD ------------------
def create_response(db: Session, data: dict) -> dict:
    """
    Persist a response and return a JSON-serializable dict suitable
    for the ResponseOut schema (details as a dict).
    """
    details = _ensure_details_dict(data.get("details"))

    # Timestamp (use explicit if given, else now)
    ts = data.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.utcnow()
    elif ts is None:
        ts = datetime.utcnow()

    resp_row = ResponseModel(
        user_id=str(data.get("user_id", "")),
        rule=str(data.get("rule", "")),
        severity=str(data.get("severity", "")),
        timestamp=ts,
        details=json.dumps(details, default=str, ensure_ascii=False),
    )

    db.add(resp_row)
    db.commit()
    db.refresh(resp_row)
    return resp_row.to_dict()


def list_responses(db: Session, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return recent responses as list of dicts (each dict matches ResponseOut).
    """
    rows = db.query(ResponseModel).order_by(ResponseModel.timestamp.desc()).limit(limit).all()
    return [row.to_dict() for row in rows]


# ------------------ new: apply escalation ------------------
def apply_response_action(db: Session, resp: dict) -> Optional[Dict[str, str]]:
    """
    Update user status according to severity ladder:
        soft_alert -> no change
        restrict   -> restricted
        suspend    -> suspended
        lock       -> locked

    Safe: will skip admins and unknown users.
    Matches user either by numeric ID or username.
    Returns a dict with applied change or None.
    """
    if not resp:
        return None

    severity = (resp.get("severity") or "").strip().lower()
    user_identifier = str(resp.get("user_id", "")).strip()

    severity_to_status = {
        "soft_alert": None,
        "restrict": "restricted",
        "suspend": "suspended",
        "lock": "locked",
        "lock_account": "locked",
        # allow rule-engine "low/medium/high" mapping if used
        "high": "locked",
        "medium": "restricted",
        "low": None,
    }
    new_status = severity_to_status.get(severity)

    # nothing to do for unmapped severities
    if not new_status:
        return None

    try:
        user = None

        # Try numeric id first
        if user_identifier.isdigit():
            try:
                user = db.query(User).filter(User.id == int(user_identifier)).first()
            except Exception:
                user = None

        # fallback by username (common, e.g., U02)
        if not user:
            user = db.query(User).filter(User.username == user_identifier).first()

        if not user:
            # Unknown/system users skipped
            # (we still return an informative dict for logs)
            return {"skipped": user_identifier, "reason": "user_not_found"}

        # Don’t modify admins
        if getattr(user, "role", "") == "admin":
            return {"skipped": user.username, "reason": "is_admin"}

        # Only update if status actually changes
        if user.status != new_status:
            old = user.status
            user.status = new_status
            db.add(user)
            db.commit()
            db.refresh(user)
            return {"user": user.username, "old_status": old, "new_status": user.status}
        else:
            return {"user": user.username, "old_status": user.status, "new_status": user.status, "note": "no_change"}
    except Exception as e:
        # Ensure we don't leave open transactions
        try:
            db.rollback()
        except Exception:
            pass
        # bubble up minimal info (caller can log)
        return {"error": str(e), "user_id": user_identifier}
