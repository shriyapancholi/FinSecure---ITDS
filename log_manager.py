import sqlite3
from datetime import datetime

DB_PATH = "finsecure.db"

def log_event(username, action, status, message=None):
    """Insert log entry into the logs table"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                status TEXT,
                message TEXT,
                timestamp TEXT
            )
        ''')

        cursor.execute('''
            INSERT INTO logs (username, action, status, message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, action, status, message, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        conn.close()
        print(f"[LOG] {username} - {action} - {status}")
    except Exception as e:
        print("[LOGGING ERROR]", e)

