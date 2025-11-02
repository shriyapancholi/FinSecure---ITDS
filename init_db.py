import sqlite3
import os

# --- make sure this matches what your Flask app uses ---
DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# --- create tables ---
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    prev_hash TEXT,
    hash TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
""")

conn.commit()
conn.close()

print("✅ Database initialized successfully:", DB_PATH)
