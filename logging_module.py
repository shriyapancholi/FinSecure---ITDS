# logging_module.py — project-aligned logger + integrity checkpoint
import hashlib
import sqlite3
import os
from datetime import datetime, date

DB_PATH = os.getenv("FINSEC_DB", os.path.join(os.path.dirname(__file__), "finsecure.db"))

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def _get_last_log_hash(conn):
    cur = conn.cursor()
    cur.execute("SELECT hash FROM logs ORDER BY id DESC LIMIT 1")
    r = cur.fetchone()
    return r["hash"] if r else None

def _compute_hash(prev_hash, user_id, action, details, timestamp):
    payload = f"{prev_hash or ''}|{user_id or ''}|{action}|{details or ''}|{timestamp}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def _ensure_tables(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        prev_hash TEXT,
        hash TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS log_integrity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE,
        last_hash TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()

def _upsert_log_integrity(conn, last_hash):
    """Upsert today's last_hash into log_integrity (date unique)."""
    d = date.today().isoformat()
    cur = conn.cursor()
    cur.execute("SELECT id FROM log_integrity WHERE date = ?", (d,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE log_integrity SET last_hash = ?, created_at = ? WHERE date = ?",
                    (last_hash, datetime.utcnow().isoformat(), d))
    else:
        cur.execute("INSERT INTO log_integrity (date, last_hash, created_at) VALUES (?, ?, ?)",
                    (d, last_hash, datetime.utcnow().isoformat()))
    conn.commit()

def log_event(username_or_id, action, details=""):
    """
    Append-only secure log entry.
    - username_or_id: either username (str) or user_id (int). If str, we try to resolve id.
    - action: short action string
    - details: text details
    """
    conn = None
    try:
        conn = get_conn()
        _ensure_tables(conn)
        cur = conn.cursor()

        # Resolve user_id if username string is passed
        user_id = None
        if isinstance(username_or_id, int):
            user_id = username_or_id
        elif isinstance(username_or_id, str) and username_or_id.strip():
            try:
                cur.execute("SELECT id FROM users WHERE username = ?", (username_or_id.strip(),))
                r = cur.fetchone()
                if r:
                    user_id = r["id"]
            except sqlite3.Error:
                user_id = None

        # Compute chain
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        prev_hash = _get_last_log_hash(conn)
        entry_hash = _compute_hash(prev_hash, user_id, action, details, timestamp)

        # Insert into logs
        cur.execute("""
            INSERT INTO logs (user_id, action, details, timestamp, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action, details, timestamp, prev_hash, entry_hash))
        conn.commit()

        # Update daily integrity table
        _upsert_log_integrity(conn, entry_hash)

        print(f"[LOG] user_id={user_id or username_or_id} action={action} ts={timestamp}")
        return True
    except Exception as e:
        print("[LOGGING ERROR]", e)
        return False
    finally:
        if conn:
            conn.close()
