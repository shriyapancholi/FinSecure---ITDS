# repair_logs.py
import sqlite3, json, hashlib
from datetime import datetime

DB = "finsecure.db"

def _compute_hash(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def repair():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, user_id, username, action, details, ip, user_agent, timestamp FROM logs ORDER BY id ASC;")
    rows = cur.fetchall()
    last_hash = ""
    updates = 0
    for r in rows:
        details_text = r['details'] if r['details'] is not None else ""
        to_hash = f"{r['timestamp']}|{r['user_id'] or ''}|{r['username'] or ''}|{r['action'] or ''}|{details_text or ''}|{r['ip'] or ''}|{r['user_agent'] or ''}|{last_hash}"
        computed = _compute_hash(to_hash)
        # update prev_hash and hash to match computed chain
        cur.execute("UPDATE logs SET prev_hash = ?, hash = ? WHERE id = ?", (last_hash, computed, r['id']))
        last_hash = computed
        updates += 1
    conn.commit()
    conn.close()
    print("Repaired", updates, "rows (prev_hash and hash recalculated).")

if __name__ == "__main__":
    repair()