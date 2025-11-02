# logging_module/integrity_check.py
"""
Verify per-day JSONL log files' SHA-256 hash chains and optionally seal them
into the log_integrity DB table.

Compatible with JSONL entries that use either:
  - "prev_hash" + "hash"
  - "previous_hash" + "hash"

Place this file at logging_module/integrity_check.py and restart FastAPI/Uvicorn.
"""

import os
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, date
import hashlib

from sqlalchemy.exc import IntegrityError

from app.database import SessionLocal
from app.models import LogIntegrity

# try importing helpers from logger; otherwise provide fallback implementations
try:
    from logging_module.logger import (
        ensure_logs_dir,
        sha256_hex,
        get_file_name_for_date,
        get_file_path_for_date,
    )
except Exception:
    # fallback implementations
    def ensure_logs_dir(logs_dir: Optional[str] = None) -> str:
        base = logs_dir or os.path.join(os.path.dirname(__file__), "logs")
        os.makedirs(base, exist_ok=True)
        return base

    def sha256_hex(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def get_file_name_for_date(d: Optional[date] = None) -> str:
        d = d or date.today()
        return f"logs_{d.isoformat()}.jsonl"

    def get_file_path_for_date(d: Optional[date] = None, logs_dir: Optional[str] = None) -> str:
        ld = ensure_logs_dir(logs_dir)
        return os.path.join(ld, get_file_name_for_date(d))


# --- small helper ---------------------------------------------------------------
def _safe_preview(obj: Dict[str, Any], keys=None) -> Dict[str, str]:
    """Return a sanitized preview mapping (stringified values) for diagnostics."""
    if keys is None:
        keys = ("user_id", "action", "timestamp", "ip_address")
    preview = {}
    for k in keys:
        v = obj.get(k)
        try:
            preview[k] = json.loads(json.dumps(v, default=str, ensure_ascii=False))
        except Exception:
            preview[k] = str(v)
    return preview


# --- compute hash exactly like logger.create_log ---------------------------------
def _canonical_record_for_hash(previous_hash: str, record: Dict[str, Any]) -> str:
    """
    Build the canonical string used for hashing:
    - Follow deterministic JSON canonicalization: sorted keys, default=str
    - Include the previous_hash (empty string if None)
    - The logger's compute was typically prev + canonical(record)
    """
    prev = previous_hash or ""
    # map record into canonical payload used by logger
    payload = {
        # include both common keys; logger may have used user_id or username
        "user_id": record.get("user_id"),
        "username": record.get("username"),
        "action": record.get("action"),
        "timestamp": record.get("timestamp"),
        "ip_address": record.get("ip_address"),
        "details": record.get("details", record.get("detail", "")),
    }
    canonical = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return prev + canonical


def compute_hash(previous_hash: str, record: Dict[str, Any]) -> str:
    """
    Recompute the hash for a record in the same way logs were written.
    Accepts records that use either 'prev_hash' or 'previous_hash' as the previous pointer.
    """
    try:
        s = _canonical_record_for_hash(previous_hash, record)
        return sha256_hex(s)
    except Exception as e:
        # bubble up detailed info to caller
        raise RuntimeError(f"compute_hash failed: {e}")


# --- reading/parsing ----------------------------------------------------------------
def _read_jsonl(file_path: str) -> List[Dict[str, Any]]:
    """Read a JSONL file and return list-of-dicts; invalid lines are returned as dicts with __invalid__ key."""
    out = []
    with open(file_path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            try:
                out.append(json.loads(raw))
            except Exception as e:
                out.append({"__invalid__": raw, "__invalid_err__": str(e)})
    return out


# --- verify single file ----------------------------------------------------------
def verify_file_chain(file_path: str) -> Dict[str, Any]:
    """
    Verify a JSONL log file's internal SHA-256 chaining.

    Returns:
      {
        "ok": bool,
        "issues": [ {line, error, ...}, ... ],
        "lines_verified": int,
        "final_hash": Optional[str]
      }
    """
    issues: List[Dict[str, Any]] = []
    lines_verified = 0
    prev_hash = ""   # the running canonical chain we compute so far
    final_hash: Optional[str] = None

    if not os.path.exists(file_path):
        return {"ok": False, "issues": [{"error": "file_not_found", "file": file_path}], "lines_verified": 0, "final_hash": None}

    try:
        records = _read_jsonl(file_path)
    except Exception as e:
        return {"ok": False, "issues": [{"error": "file_read_failed", "detail": str(e)}], "lines_verified": 0, "final_hash": None}

    for idx, rec in enumerate(records, start=1):
        # invalid json line?
        if "__invalid__" in rec:
            issues.append({"line": idx, "error": "invalid_json", "detail": rec.get("__invalid_err__"), "text_preview": rec.get("__invalid__")[:400]})
            continue

        # skip compensating audit records
        if rec.get("compensating"):
            issues.append({"line": idx, "error": "compensating_record_ignored", "record_preview": _safe_preview(rec)})
            continue

        # Normalize prev key names (support both prev_hash and previous_hash)
        listed_prev = rec.get("prev_hash") if rec.get("prev_hash") is not None else rec.get("previous_hash", "")
        listed_hash = rec.get("hash") or rec.get("record_hash") or ""

        # If the file lists a previous_hash that doesn't match the canonical chain we computed so far -> report
        if listed_prev != prev_hash:
            issues.append({
                "line": idx,
                "error": "previous_hash_mismatch",
                "listed_previous": listed_prev,
                "expected_previous": prev_hash,
                "record_preview": _safe_preview(rec),
            })

        if not listed_hash:
            issues.append({"line": idx, "error": "missing_hash", "record_preview": _safe_preview(rec)})
            prev_hash = listed_prev or prev_hash
            continue

        # Try recomputations
        recomputed_by_canonical = None
        recomputed_by_listed = None
        try:
            recomputed_by_canonical = compute_hash(prev_hash, rec)
        except Exception as e:
            issues.append({"line": idx, "error": "recompute_failed_canonical", "detail": str(e), "record_preview": _safe_preview(rec)})
        try:
            recomputed_by_listed = compute_hash(listed_prev, rec)
        except Exception as e:
            issues.append({"line": idx, "error": "recompute_failed_listed", "detail": str(e), "record_preview": _safe_preview(rec)})

        matches_listed = (recomputed_by_listed is not None and recomputed_by_listed == listed_hash)
        matches_canonical = (recomputed_by_canonical is not None and recomputed_by_canonical == listed_hash)

        if not matches_canonical and not matches_listed:
            issues.append({
                "line": idx,
                "error": "hash_mismatch",
                "expected": listed_hash,
                "recomputed_by_canonical": recomputed_by_canonical,
                "recomputed_by_listed": recomputed_by_listed,
                "record_preview": _safe_preview(rec),
            })

        # Advance chain using the file's stated hash (so subsequent checks follow file order)
        prev_hash = listed_hash
        final_hash = listed_hash
        lines_verified += 1

    return {"ok": len(issues) == 0, "issues": issues, "lines_verified": lines_verified, "final_hash": final_hash}


# --- verify directory ------------------------------------------------------------
def verify_all_logs(logs_dir: Optional[str] = None) -> Dict[str, Any]:
    logs_dir = ensure_logs_dir(logs_dir)
    try:
        files = sorted([p for p in os.listdir(logs_dir) if p.endswith(".jsonl")])
    except FileNotFoundError:
        return {"error": "logs_dir_not_found", "logs_dir": logs_dir}

    report: Dict[str, Any] = {}
    for fn in files:
        path = os.path.join(logs_dir, fn)
        report[fn] = verify_file_chain(path)
    return report


# --- seal & record ----------------------------------------------------------------
def seal_and_record(target_date: Optional[date] = None, logs_dir: Optional[str] = None) -> Optional[LogIntegrity]:
    """
    Verify the log file and record final_hash into log_integrity if verification passes.
    Returns created LogIntegrity ORM object on success, otherwise None.
    """
    logs_dir = ensure_logs_dir(logs_dir)
    file_name = get_file_name_for_date(target_date)
    file_path = os.path.join(logs_dir, file_name)

    if not os.path.exists(file_path):
        print(f"seal_and_record: file not found {file_path}")
        return None

    res = verify_file_chain(file_path)
    if not res.get("ok"):
        print(f"seal_and_record: verification failed for {file_name}; issues={len(res.get('issues',[]))}")
        for issue in res.get("issues", [])[:5]:
            print("  -", issue)
        return None

    final_hash = res.get("final_hash")
    if not final_hash:
        print("seal_and_record: no final hash computed (empty file?)")
        return None

    db = SessionLocal()
    try:
        li = LogIntegrity(file_date=(target_date or date.today()), final_hash=final_hash, verified_at=datetime.utcnow())
        db.add(li)
        db.commit()
        db.refresh(li)
        print(f"seal_and_record: recorded LogIntegrity for {file_name} hash={final_hash[:12]}...")
        return li
    except IntegrityError:
        db.rollback()
        print("seal_and_record: LogIntegrity entry already exists (unique constraint).")
        return None
    except Exception as e:
        db.rollback()
        print("seal_and_record: DB error:", str(e))
        return None
    finally:
        db.close()