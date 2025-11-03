# init_db.py
"""
Idempotent DB initializer / light migrator for FinSecure project.
Creates tables: users, logs, anomalies, responses.
If columns are missing from older DB, adds them (ALTER TABLE ADD COLUMN).
Use:
    python init_db.py
    OR from python import init_db; init_db()
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn, table_name):
    cur = conn.execute(f"PRAGMA table_info({table_name});")
    return [r["name"] for r in cur.fetchall()]


def _add_column_if_missing(conn, table, column_def):
    """
    column_def example: 'password_hash TEXT'
    Only runs ALTER TABLE if the column does not exist.
    """
    col_name = column_def.split()[0]
    cols = _table_columns(conn, table)
    if col_name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_def};")
        print(f"  - Added column '{col_name}' to '{table}'.")


def init_db():
    # ensure folder exists (usually not needed)
    db_dir = os.path.dirname(DB_PATH) or "."
    os.makedirs(db_dir, exist_ok=True)

    conn = _connect()
    cur = conn.cursor()

    # USERS table (compatible with older / newer versions)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT,
        password_hash TEXT,
        role TEXT DEFAULT 'analyst' NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Make sure the columns exist (for older DB files)
    _add_column_if_missing(conn, "users", "password TEXT")
    _add_column_if_missing(conn, "users", "password_hash TEXT")
    _add_column_if_missing(conn, "users", "role TEXT")
    _add_column_if_missing(conn, "users", "created_at DATETIME")

    # Create index after columns exist
    cur.execute("CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);")

    # LOGS table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NULL,
        action TEXT NOT NULL,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        prev_hash TEXT,
        hash TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS ix_logs_user_id ON logs(user_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_logs_timestamp ON logs(timestamp);")

    # ANOMALIES table
    # Older DB might not have 'created_at' — we'll ensure column exists before adding index
    cur.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NULL,
        score REAL NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # If anomalies existed without created_at, add it
    _add_column_if_missing(conn, "anomalies", "details TEXT")
    _add_column_if_missing(conn, "anomalies", "created_at DATETIME")

    # Now safe to create index on created_at
    cur.execute("CREATE INDEX IF NOT EXISTS ix_anomalies_created_at ON anomalies(created_at);")

    # RESPONSES table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(anomaly_id) REFERENCES anomalies(id)
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS ix_responses_anomaly_id ON responses(anomaly_id);")

    conn.commit()
    conn.close()

    # Print simple verification
    conn = _connect()
    print("✅ Database initialized (or already existed):", DB_PATH)
    print("\nCurrent schema (tables and columns):")
    for t in ["users", "logs", "anomalies", "responses"]:
        cols = _table_columns(conn, t)
        print(f" - {t}: {', '.join(cols) if cols else '(missing)'}")
    conn.close()


if __name__ == "__main__":
    init_db()
