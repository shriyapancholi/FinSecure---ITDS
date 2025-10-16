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

def ensure_logs_dir(logs_dir: Optional[str]) -> str:
    logs_dir = logs_dir or DEFAULT_LOGS_DIR
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir

def get_file_name_for_date(target_date: Optional[date] = None) -> str:
    if target_date is None:
        target_date = date.today()
    return f"logs_{target_date.isoformat()}.jsonl"

def get_file_path_for_date(logs_dir: str, target_date: Optional[date] = None) -> str:
    file_name = get_file_name_for_date(target_date)
    return os.path.join(logs_dir, file_name)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# file append ------------------------------------------------------------------

def append_line_to_file(file_path: str, obj: Dict[str, Any]) -> None:
    """Append a JSON line to file_path (creates file if not exists)."""
    line = json.dumps(obj, default=str)
    # ensure parent dir exists
    parent = os.path.dirname(file_path) or "."
    os.makedirs(parent, exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# core create log --------------------------------------------------------------

def create_log(
    db: Session,
    user_id: Optional[int],
    action: str,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    logs_dir: Optional[str] = None,
) -> Log:
    """
    Create a log row and append to the per-day JSONL file using hash chain.
    This function expects a live SQLAlchemy Session (caller is responsible for opening/closing).
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(date.today())
    file_path = os.path.join(logs_dir, file_name)

    if details is None:
        details = {}

    timestamp = datetime.utcnow()

    # Fetch previous hash (global last log). If you want per-file chaining, change this to filter by file_name.
    previous_hash = None
    last = db.query(Log).order_by(Log.id.desc()).first()
    if last:
        previous_hash = getattr(last, "hash", None)

    # Build the JSON object we will append to file
    file_obj = {
        "user_id": user_id,
        "action": action,
        "timestamp": timestamp.isoformat(),
        "ip_address": ip_address,
        "details": details,
        "previous_hash": previous_hash,
    }

    # Compute current hash = SHA256(previous_hash || json(payload))
    prev = previous_hash or ""
    current_hash = sha256_hex(prev + json.dumps(file_obj, sort_keys=True, default=str))

    # Add computed hash and file metadata to file object
    file_obj["hash"] = current_hash
    file_obj["file_name"] = file_name

    # Create DB object (use attribute name 'hash' to match your model)
    new_log = Log(
        user_id=user_id,
        action=action,
        timestamp=timestamp,
        hash=current_hash,
    )

    # Append to file first, then commit DB; rollback if DB commit fails
    try:
        append_line_to_file(file_path, file_obj)
        db.add(new_log)
        db.flush()   # assign id
        db.commit()
    except Exception:
        db.rollback()
        raise

    return new_log

# public helper that opens/closes session -------------------------------------

def create_db_log(
    *,
    user_id: Optional[int],
    action: str,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    logs_dir: Optional[str] = None,
) -> Log:
    """
    Open a short-lived DB session, write the log, close session, and return the persisted Log.
    Useful for middleware/background tasks.
    """
    db = SessionLocal()
    try:
        return create_log(db, user_id=user_id, action=action, ip_address=ip_address, details=details, logs_dir=logs_dir)
    finally:
        db.close()

# seal file -> record final hash in log_integrity ------------------------------

def seal_log_file(db: Session, target_date: Optional[date] = None, logs_dir: Optional[str] = None) -> Optional[LogIntegrity]:
    """
    Seal a per-day log file by recording its final hash in log_integrity table.
    The final hash is taken from the last log row's hash for that date (if any).
    Returns the created LogIntegrity row or None if no logs exist for that date.
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(target_date)

    # find last log (global). If you want per-file, add a file_name column in Log and filter on it.
    last_log = db.query(Log).order_by(Log.id.desc()).first()
    if not last_log:
        return None

    final_hash = getattr(last_log, "hash", None)
    li = LogIntegrity(file_date=target_date or date.today(), final_hash=final_hash, verified_at=datetime.utcnow())
    db.add(li)
    db.commit()
    return li
