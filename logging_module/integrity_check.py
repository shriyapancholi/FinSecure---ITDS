# logging_module/integrity_check.py
"""Verify per-day JSONL log files' SHA-256 hash chains."""

import os
import json
from typing import Dict, Any, Optional
from app.database import SessionLocal
from app.models import LogIntegrity
from datetime import datetime, date

from logging_module.logger import ensure_logs_dir, sha256_hex, get_file_name_for_date

def compute_hash(previous_hash: str, record: Dict[str, Any]) -> str:
    """Recompute the hash for a record exactly as logger.create_log did."""
    prev = previous_hash or ""

    # Recreate the original payload structure used for hashing in logger.create_log
    payload = {
        "user_id": record.get("user_id"),
        "action": record.get("action"),
        "timestamp": record.get("timestamp"),
        "ip_address": record.get("ip_address"),
        "details": record.get("details"),
        "previous_hash": record.get("previous_hash"),
    }

    canonical = json.dumps(payload, sort_keys=True, default=str)
    return sha256_hex(prev + canonical)

def verify_file_chain(file_path: str) -> Dict[str, Any]:
    """
    Verify a single JSON-lines (jsonl) log file's hash chain.

    Returns: {"ok": bool, "issues": list}
    Each issue is a dict describing the mismatch or parse error.
    """
    issues = []
    prev_hash = ""

    if not os.path.exists(file_path):
        return {"ok": False, "issues": [{"error": "file_not_found", "file": file_path}]}

    with open(file_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                issues.append({"line": line_no, "error": "invalid_json", "detail": str(e)})
                continue

            recomputed = compute_hash(prev_hash, rec)
            expected = rec.get("hash")
            if recomputed != expected:
                issues.append({
                    "line": line_no,
                    "error": "hash_mismatch",
                    "expected": expected,
                    "recomputed": recomputed,
                    "record": rec,
                })

            prev_hash = rec.get("hash") or prev_hash

    return {"ok": len(issues) == 0, "issues": issues}

def verify_all_logs(logs_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify all log files in logs_dir. Returns a dict mapping filename -> verification result.
    Looks for files named *.jsonl (the same format produced by logger.append_line_to_file).
    """
    logs_dir = ensure_logs_dir(logs_dir)
    files = sorted([p for p in os.listdir(logs_dir) if p.endswith('.jsonl')])
    report: Dict[str, Any] = {}
    for fn in files:
        path = os.path.join(logs_dir, fn)
        report[fn] = verify_file_chain(path)
    return report

def seal_and_record(target_date: Optional[date] = None, logs_dir: Optional[str] = None):
    """
    Verify a log file, and if it's valid, record its final hash
    into the log_integrity table.
    """
    from logging_module.logger import get_file_name_for_date
    result = verify_all_logs(logs_dir)
    file_name = get_file_name_for_date(target_date)
    entry = result.get(file_name)
    if not entry or not entry.get("ok"):
        print("❌ Verification failed — not sealing")
        return None

    # extract last hash from the verified file
    logs_dir = ensure_logs_dir(logs_dir)
    file_path = os.path.join(logs_dir, file_name)
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if not lines:
        print("⚠️ Empty log file")
        return None

    last_line = json.loads(lines[-1])
    final_hash = last_line.get("hash")

    db = SessionLocal()
    li = LogIntegrity(file_date=target_date or date.today(),
                      final_hash=final_hash,
                      verified_at=datetime.utcnow())
    db.add(li)
    db.commit()
    db.close()

    print(f"✅ Sealed and recorded {file_name} with final hash {final_hash[:10]}...")
    return li