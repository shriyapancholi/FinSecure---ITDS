"""Verify per-day JSONL log files' SHA-256 hash chains and optionally seal them
into the log_integrity DB table.
"""

import os
import json
from typing import Dict, Any, Optional
from datetime import datetime, date

from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import LogIntegrity

# helpers from logger (must exist)
from logging_module.logger import (
    ensure_logs_dir,
    sha256_hex,
    get_file_name_for_date,
)

# --- Verification utilities -----------------------------------------------------------------

def compute_hash(previous_hash: str, record: Dict[str, Any]) -> str:
    """
    Recompute the hash for a record in the same way logs were written.

    previous_hash: the previous record hash (empty string for first record)
    record: dict containing keys used in original hashing:
        "user_id", "action", "timestamp", "ip_address", "details", "previous_hash"
    Returns: hex string
    """
    prev = previous_hash or ""

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

    Returns:
      {
        "ok": bool,
        "issues": [ ... ],
        "lines_verified": int,
        "final_hash": Optional[str]
      }

    Each issue is a dict with {line, error, ...}
    """
    issues = []
    prev_hash = ""
    lines_verified = 0
    final_hash: Optional[str] = None

    if not os.path.exists(file_path):
        return {"ok": False, "issues": [{"error": "file_not_found", "file": file_path}], "lines_verified": 0, "final_hash": None}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    # skip blank lines
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    issues.append({"line": line_no, "error": "invalid_json", "detail": str(e), "text": line[:200]})
                    continue

                # skip compensating audit records (these are not part of the valid chain)
                if rec.get("compensating"):
                    # treat as informational; do not mark file as invalid because of compensating records
                    continue

                expected = rec.get("hash")
                if not expected:
                    # missing hash on a normal record — report as an issue but keep going
                    issues.append({"line": line_no, "error": "missing_hash", "record_preview": {k: rec.get(k) for k in ("user_id", "action", "timestamp")}})
                    # advance prev_hash defensively if record supplies one
                    prev_hash = rec.get("previous_hash") or prev_hash
                    continue

                # recompute in a safe wrapper to avoid exceptions killing the whole verification run
                try:
                    recomputed = compute_hash(prev_hash, rec)
                except Exception as e:
                    issues.append({"line": line_no, "error": "recompute_failed", "detail": str(e), "record": rec})
                    # still advance to keep parsing remaining lines
                    prev_hash = expected
                    final_hash = expected
                    lines_verified += 1
                    continue

                if recomputed != expected:
                    issues.append({
                        "line": line_no,
                        "error": "hash_mismatch",
                        "expected": expected,
                        "recomputed": recomputed,
                        "record_preview": {k: rec.get(k) for k in ("user_id", "action", "timestamp")},
                    })

                # advance
                prev_hash = expected
                final_hash = expected
                lines_verified += 1

    except Exception as e:
        # file read error
        issues.append({"error": "file_read_error", "detail": str(e)})

    return {"ok": len(issues) == 0, "issues": issues, "lines_verified": lines_verified, "final_hash": final_hash}


def verify_all_logs(logs_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify all .jsonl log files in logs_dir (or default log dir).
    Returns mapping: filename -> verify_file_chain(...) result
    """
    logs_dir = ensure_logs_dir(logs_dir)
    try:
        files = sorted([p for p in os.listdir(logs_dir) if p.endswith('.jsonl')])
    except FileNotFoundError:
        return {"error": "logs_dir_not_found", "logs_dir": logs_dir}

    report: Dict[str, Any] = {}
    for fn in files:
        path = os.path.join(logs_dir, fn)
        report[fn] = verify_file_chain(path)
    return report


def seal_and_record(target_date: Optional[date] = None, logs_dir: Optional[str] = None) -> Optional[LogIntegrity]:
    """
    Verify the log file for `target_date` (or today's file if None), and if valid record its
    final hash into the log_integrity DB table.

    Returns the created LogIntegrity object on success, or None on failure.
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(target_date)

    file_path = os.path.join(logs_dir, file_name)
    if not os.path.exists(file_path):
        print(f"❌ Log file for sealing not found: {file_path}")
        return None

    result = verify_file_chain(file_path)
    if not result.get("ok"):
        print(f"❌ Verification failed for {file_name}:")
        for issue in result.get("issues", [])[:5]:
            print("  -", issue)
        return None

    final_hash = result.get("final_hash")
    if not final_hash:
        print("⚠️ No final hash computed (empty file?) — aborting seal")
        return None

    db = SessionLocal()
    try:
        li = LogIntegrity(
            file_date=target_date or date.today(),
            final_hash=final_hash,
            verified_at=datetime.utcnow()
        )
        db.add(li)
        db.commit()
        print(f"✅ Sealed and recorded {file_name} with final hash {final_hash[:10]}...")
        return li
    except IntegrityError:
        db.rollback()
        print(f"⚠️ LogIntegrity entry for {file_name} already exists (unique constraint).")
        return None
    except Exception as e:
        db.rollback()
        print("❌ Failed to write LogIntegrity:", str(e))
        return None
    finally:
        db.close()