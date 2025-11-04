# init_db.py
"""
Idempotent DB initializer / light migrator for FinSecure project.
Creates / updates tables: users, logs, anomalies, responses.
Use:
    python init_db.py
    OR from python import init_db; init_db()
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    try:
        cur = conn.execute(f"PRAGMA table_info({table_name});")
        return [r["name"] for r in cur.fetchall()]
    except sqlite3.OperationalError:
        return []


def _add_column_if_missing(conn, table, column_def):
    """
    Add a column if it doesn't exist.
    Example column_def: 'user_id TEXT'
    """
    col_name = column_def.split()[0]
    cols = _table_columns(conn, table)
    if col_name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def};")
        print(f"  - Added column '{col_name}' to '{table}'.")


def ensure_users_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT,
        password_hash TEXT,
        role TEXT DEFAULT 'analyst' NOT NULL,
        suspended_until DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    _add_column_if_missing(conn, "users", "password TEXT")
    _add_column_if_missing(conn, "users", "password_hash TEXT")
    _add_column_if_missing(conn, "users", "role TEXT")
    _add_column_if_missing(conn, "users", "suspended_until DATETIME")
    _add_column_if_missing(conn, "users", "created_at DATETIME")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);")


def ensure_logs_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NULL,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        prev_hash TEXT,
        hash TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    # ensure columns exist
    _add_column_if_missing(conn, "logs", "user_id INTEGER")
    _add_column_if_missing(conn, "logs", "username TEXT")
    _add_column_if_missing(conn, "logs", "action TEXT")
    _add_column_if_missing(conn, "logs", "details TEXT")
    _add_column_if_missing(conn, "logs", "ip TEXT")
    _add_column_if_missing(conn, "logs", "user_agent TEXT")
    _add_column_if_missing(conn, "logs", "timestamp DATETIME")
    _add_column_if_missing(conn, "logs", "prev_hash TEXT")
    _add_column_if_missing(conn, "logs", "hash TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_logs_username ON logs(username);")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_logs_action ON logs(action);")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_logs_timestamp ON logs(timestamp);")


def ensure_anomalies_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NULL,
        score REAL,
        details TEXT,
        severity TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    _add_column_if_missing(conn, "anomalies", "user_id TEXT")
    _add_column_if_missing(conn, "anomalies", "score REAL")
    _add_column_if_missing(conn, "anomalies", "details TEXT")
    _add_column_if_missing(conn, "anomalies", "severity TEXT")
    _add_column_if_missing(conn, "anomalies", "created_at DATETIME")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_anomalies_created_at ON anomalies(created_at);")


def ensure_responses_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(anomaly_id) REFERENCES anomalies(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    _add_column_if_missing(conn, "responses", "anomaly_id INTEGER")
    _add_column_if_missing(conn, "responses", "user_id INTEGER")
    _add_column_if_missing(conn, "responses", "action TEXT")
    _add_column_if_missing(conn, "responses", "details TEXT")
    _add_column_if_missing(conn, "responses", "created_at DATETIME")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_responses_anomaly_id ON responses(anomaly_id);")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = _connect()
    try:
        ensure_users_table(conn)
        ensure_logs_table(conn)
        ensure_anomalies_table(conn)
        ensure_responses_table(conn)
        conn.commit()
    finally:
        conn.close()

    # print summary
    conn = _connect()
    print("✅ Database initialized (or already existed):", DB_PATH)
    print("\nCurrent schema (tables and columns):")
    for t in ["users", "logs", "anomalies", "responses"]:
        cols = _table_columns(conn, t)
        print(f" - {t}: {', '.join(cols) if cols else '(missing)'}")
    conn.close()


if __name__ == "__main__":
    init_db()