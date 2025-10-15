import os
db.flush()


# Prepare JSON line (includes DB id so file and DB can be cross-checked)
file_obj = {
"id": new_log.id,
"user_id": payload["user_id"],
"action": payload["action"],
"timestamp": payload["timestamp"],
"ip_address": payload["ip_address"],
"details": payload["details"],
"previous_hash": previous_hash,
"hash": current_hash,
"file_name": file_name,
}


try:
append_line_to_file(file_path, file_obj)
# only commit after file append succeeds
db.commit()
except Exception:
db.rollback()
raise


return new_log




def seal_log_file(db: Session, target_date: Optional[date] = None, logs_dir: Optional[str] = None) -> Optional[LogIntegrity]:
"""Seal a per-day log file by recording its final hash in log_integrity table.


The final hash is the last log's `hash` value for that file. If no logs exist for that date,
the function returns None.
"""
logs_dir = ensure_logs_dir(logs_dir)
file_name = get_file_name_for_date(target_date)


last_log = db.query(Log).filter(Log.file_name == file_name).order_by(Log.id.desc()).first()
if not last_log:
return None


final_hash = last_log.hash
li = LogIntegrity(file_name=file_name, final_hash=final_hash)
db.add(li)
db.commit()
return li




# Convenience helper used by middleware or scripts
def create_db_log(*, user_id: Optional[int], action: str, ip_address: Optional[str] = None, details: Optional[Dict[str, Any]] = None, logs_dir: Optional[str] = None):
"""Open a short-lived DB session, write the log and close session. Useful for middleware/background tasks."""
db = SessionLocal()
try:
return create_log(db, user_id=user_id, action=action, ip_address=ip_address, details=details, logs_dir=logs_dir)
finally:
db.close()