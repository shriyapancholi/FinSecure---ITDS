import sqlite3
import json
import hashlib
from datetime import datetime
import os

# --- File paths ---
LOG_FILE = "security_logs.jsonl"
DB_FILE = os.path.join(os.path.dirname(__file__), "security.db")

# --- Ensure logs table exists ---
def ensure_logs_table():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            timestamp TEXT,
            prev_hash TEXT,
            hash TEXT
        )
    """)
    conn.commit()
    conn.close()

# Call once when module loads
ensure_logs_table()

# --- DB connection helper ---
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Logging core ---
def log_event(username, action, details):
    """
    Logs a security event in both the database and JSONL file.
    Adds hash chaining for integrity.
    Safe for missing users or schema differences.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Optional user lookup
        user_id = None
        try:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row:
                user_id = row["id"]
        except sqlite3.Error:
            user_id = None

        # Get previous hash (chain)
        try:
            cursor.execute("SELECT hash FROM logs ORDER BY id DESC LIMIT 1")
            prev_row = cursor.fetchone()
            prev_hash = prev_row["hash"] if prev_row else "0"
        except sqlite3.Error:
            prev_hash = "0"

        # Compute new hash
        content = f"{username}|{action}|{details}|{timestamp}|{prev_hash}"
        current_hash = hashlib.sha256(content.encode()).hexdigest()

        # Insert log record
        try:
            cursor.execute(
                """INSERT INTO logs (user_id, action, details, timestamp, prev_hash, hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, action, details, timestamp, prev_hash, current_hash)
            )
            conn.commit()
        except sqlite3.Error as e:
            print(f"[DB LOGGING ERROR] {e}")

        # JSONL append
        entry = {
            "username": username,
            "action": action,
            "details": details,
            "timestamp": timestamp,
            "hash": current_hash,
            "prev_hash": prev_hash,
        }

        if not os.path.exists(LOG_FILE):
            open(LOG_FILE, "w").close()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"[LOG] {username} | {action} | {details}")

    except Exception as e:
        print(f"[LOGGING FAILURE] {e}")
    finally:
        if 'conn' in locals():
            conn.close()
