# logging_module/logger.py
"""Logging + file append + SHA-256 chaining + DB insertion helpers.

Usage:
    from logging_module.logger import create_db_log, seal_log_file
"""

import os
import json
import hashlib
from datetime import datetime, date
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Log, LogIntegrity

# directory where per-day JSONL log files are written
DEFAULT_LOGS_DIR = os.getenv("LOGS_DIR", "logs")  # relative to project root

# helper utils -----------------------------------------------------------------


def ensure_logs_dir(logs_dir: Optional[str] = None) -> str:
    """
    Ensure the logs directory exists; return its absolute path.
    If logs_dir is None, use DEFAULT_LOGS_DIR.
    """
    logs_dir = logs_dir or DEFAULT_LOGS_DIR
    os.makedirs(logs_dir, exist_ok=True)
    return os.path.abspath(logs_dir)


def get_file_name_for_date(target_date: Optional[date] = None) -> str:
    if target_date is None:
        target_date = date.today()
    return f"logs_{target_date.isoformat()}.jsonl"


def get_file_path_for_date(logs_dir: str, target_date: Optional[date] = None) -> str:
    file_name = get_file_name_for_date(target_date)
    return os.path.join(logs_dir, file_name)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# JSONL file helpers ----------------------------------------------------------


def append_line_to_file(file_path: str, obj: Dict[str, Any]) -> None:
    """Append a JSON line to file_path (creates file if not exists)."""
    line = json.dumps(obj, default=str, ensure_ascii=False)
    # ensure parent dir exists
    parent = os.path.dirname(file_path) or "."
    os.makedirs(parent, exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _read_last_jsonl_line(file_path: str) -> Optional[Dict[str, Any]]:
    """Return the last non-empty JSON-decoded line from file_path or None if not found."""
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, "rb") as f:
            # read from end in chunks until we find a newline
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            if file_size == 0:
                return None
            chunk_size = 1024
            data = b""
            pos = file_size
            while pos > 0:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                data = f.read(read_size) + data
                # find last newline
                if b"\n" in data:
                    break
            # split lines and pick last non-empty
            lines = data.splitlines()
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line.decode("utf-8"))
                except Exception:
                    # fall back to trying in text mode reading the whole file
                    break
        # fallback: read file in text mode (safe for small files)
        with open(file_path, "r", encoding="utf-8") as f:
            for line in reversed(f.readlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except Exception:
                    continue
    except Exception:
        return None
    return None


# sanitization helpers -------------------------------------------------------


def _safe_val(v: Any) -> Any:
    """
    Ensure only safe, JSON-serializable primitive-ish values are returned.
    - int/float/str/bool/None pass through.
    - objects with attribute 'id' will return that id.
    - otherwise return a short tag string describing the object.
    """
    if v is None:
        return None
    if isinstance(v, (int, float, str, bool)):
        return v
    # if object has 'id' attribute (e.g., SQLAlchemy model instance), return it
    try:
        if hasattr(v, "id"):
            maybe = getattr(v, "id")
            if isinstance(maybe, (int, str)):
                return maybe
    except Exception:
        pass
    # fallback: give a compact tag so logs are still readable but safe
    try:
        cls_name = getattr(v, "__class__", type(v)).__name__
        text = str(v)
        # truncate to avoid huge blobs
        if len(text) > 200:
            text = text[:200] + "..."
        return f"<{cls_name}:{text}>"
    except Exception:
        return f"<{type(v).__name__}>"


def _normalize_details(d: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a details dict with safe values."""
    if d is None:
        return {}
    if not isinstance(d, dict):
        # if caller passed a non-dict details, stringify safely
        return {"value": _safe_val(d)}
    return {k: _safe_val(v) for k, v in d.items()}


def _extract_user_id(user_id: Any) -> Optional[int]:
    """
    Try to produce an integer user_id that can be stored in DB.
    If not possible, return None. (We still store the sanitized user_id
    in the file for auditability.)
    """
    if user_id is None:
        return None
    if isinstance(user_id, int):
        return user_id
    # if string of digits
    if isinstance(user_id, str) and user_id.isdigit():
        try:
            return int(user_id)
        except Exception:
            return None
    # if object with .id attribute
    try:
        if hasattr(user_id, "id"):
            candidate = getattr(user_id, "id")
            if isinstance(candidate, int):
                return candidate
            if isinstance(candidate, str) and candidate.isdigit():
                return int(candidate)
    except Exception:
        pass
    return None


# core create log --------------------------------------------------------------


def create_log(
    db: Session,
    user_id: Optional[Any],
    action: str,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    logs_dir: Optional[str] = None,
) -> Log:
    """
    Create a log row and append to the per-day JSONL file using per-file hash chain.
    This function expects a live SQLAlchemy Session (caller is responsible for opening/closing).
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(date.today())
    file_path = os.path.join(logs_dir, file_name)

    sanitized_user_id = _safe_val(user_id)
    numeric_user_id = _extract_user_id(user_id)

    safe_details = _normalize_details(details)

    timestamp = datetime.utcnow()

    # Fetch previous hash from last line of today's file (per-file chain).
    previous_hash = None
    last_file_obj = _read_last_jsonl_line(file_path)
    if last_file_obj and isinstance(last_file_obj, dict):
        previous_hash = last_file_obj.get("hash")

    # Build the JSON object we will append to file (use sanitized values)
    file_obj = {
        "user_id": sanitized_user_id,
        "action": action,
        "timestamp": timestamp.isoformat(),
        "ip_address": ip_address,
        "details": safe_details,
        "previous_hash": previous_hash,
    }

    # Compute current hash = SHA256(previous_hash || json(payload))
    prev = previous_hash or ""
    # ensure deterministic serialization
    current_hash = sha256_hex(prev + json.dumps(file_obj, sort_keys=True, default=str, ensure_ascii=False))

    # Add computed hash and file metadata to file object
    file_obj["hash"] = current_hash
    file_obj["file_name"] = file_name

    # Create DB object (use attribute name 'hash' to match your model)
    new_log = Log(
        user_id=numeric_user_id,
        action=action,
        timestamp=timestamp,
        hash=current_hash,
    )

    # Append to file first, then commit DB; if DB commit fails we append a compensating record so everything stays auditable.
    try:
        append_line_to_file(file_path, file_obj)
        db.add(new_log)
        db.flush()   # assign id (in-session)
        db.commit()
    except Exception as e:
        db.rollback()
        # Append a compensating audit record to the same JSONL file describing the DB failure.
        compensating = {
            "compensating": True,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
            "original": file_obj,
        }
        try:
            append_line_to_file(file_path, compensating)
        except Exception:
            # if even writing the compensating record fails, raise original exception
            pass
        raise

    # ----------------------- ML scoring & anomaly persistence -----------------------
    # Non-blocking, defensive: if ML module/model not available, this will quietly no-op.
    try:
        # import scorer (user's ML module). It must expose score_record(record: dict) -> dict
        from threat_detection.ml_model import score_record  # type: ignore
    except Exception:
        score_record = None

    if score_record:
        try:
            # score_record expects a JSON-serializable dict of features — use file_obj
            ml_res = score_record(file_obj)
        except Exception as e:
            # scoring failed — don't block logging; print debug and continue
            print("ML scoring failed:", repr(e))
            ml_res = {"score": 0.0, "is_anomaly": False, "severity": "low"}

        if bool(ml_res.get("is_anomaly")):
            # try to persist to an anomalies table if present, otherwise write into ResponseModel as fallback
            try:
                # try to import Anomaly model (if you created it), and ResponseModel as a fallback
                try:
                    from app.models import Anomaly  # type: ignore
                except Exception:
                    Anomaly = None
                try:
                    from app.models import ResponseModel  # type: ignore
                except Exception:
                    ResponseModel = None

                features_json = json.dumps(file_obj, default=str, ensure_ascii=False)

                if Anomaly is not None:
                    a_row = Anomaly(
                        user_id=str(sanitized_user_id or "system"),
                        score=float(ml_res.get("score", 0.0)),
                        severity=str(ml_res.get("severity", "medium")),
                        features=features_json,
                    )
                    db.add(a_row)
                    db.commit()
                elif ResponseModel is not None:
                    # store as a system response fallback
                    r_row = ResponseModel(
                        user_id="system",
                        rule="ml_anomaly",
                        severity=str(ml_res.get("severity", "medium")),
                        details=json.dumps({"score": ml_res.get("score"), "features": file_obj}, default=str, ensure_ascii=False)
                    )
                    db.add(r_row)
                    db.commit()
                else:
                    # nothing to persist to DB; log to stdout for visibility
                    print("ML anomaly detected but no persistence model available:", ml_res)
            except Exception as e:
                try:
                    db.rollback()
                except Exception:
                    pass
                print("Failed to persist ML anomaly:", repr(e))

    # ------------------------------------------------------------------------------

    return new_log


# public helper that opens/closes session -------------------------------------


def create_db_log(
    user_id: Optional[Any],
    action: str,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    logs_dir: Optional[str] = None,
) -> Log:
    """
    Open a short-lived DB session, write the log, close session, and return the persisted Log.
    Accepts positional arguments so it is compatible with run_in_threadpool(create_db_log, arg1, arg2, ...).
    """
    db = SessionLocal()
    try:
        return create_log(
            db,
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            details=details,
            logs_dir=logs_dir,
        )
    finally:
        db.close()


# seal file -> record final hash in log_integrity ------------------------------


def seal_log_file(db: Session, target_date: Optional[date] = None, logs_dir: Optional[str] = None) -> Optional[LogIntegrity]:
    """
    Seal a per-day log file by recording its final hash in log_integrity table.
    The final hash is taken from the last JSONL line for that file (if any).
    Returns the created LogIntegrity row or None if no logs exist for that date.
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(target_date)
    file_path = os.path.join(logs_dir, file_name)

    last_file_obj = _read_last_jsonl_line(file_path)
    if not last_file_obj:
        return None

    final_hash = last_file_obj.get("hash")
    if final_hash is None:
        return None

    # ensure we don't create duplicate integrity entries for same date+hash
    existing = db.query(LogIntegrity).filter(LogIntegrity.file_date == (target_date or date.today())).first()
    if existing:
        # already sealed for this date
        return None

    li = LogIntegrity(file_date=(target_date or date.today()), final_hash=final_hash, verified_at=datetime.utcnow())
    db.add(li)
    db.commit()
    return li