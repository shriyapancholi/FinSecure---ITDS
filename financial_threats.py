# financial_threats.py
import sqlite3
from datetime import datetime
import json
import os

# Path to your database
DB_PATH = "finsecure.db"

# Thresholds (can be tweaked later)
HIGH_VALUE_LIMIT = 100000
SMALL_TX_LIMIT = 100
DOMESTIC_CODE = "IN"

def _get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _compute_simple_hash(*parts):
    # placeholder hash for now (replace with proper SHA256 chain later)
    return "|".join(str(p) for p in parts) + "|" + datetime.utcnow().isoformat()

def log_threat(username, amount, reason, severity="HIGH"):
    """
    Inserts a detected threat into `logs` and `anomalies` tables.
    Works with DB schema that has `logs(user_id, action, details, prev_hash, hash, timestamp)` and `anomalies`.
    """
    details_text = f"{reason} | Amount: ₹{amount}"
    metric_json = json.dumps({"username": username, "amount": amount, "reason": reason})

    try:
        conn = _get_db_conn()
        cur = conn.cursor()

        # find user_id if username exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        user_id = row["id"] if row else None

        # compute a simple placeholder hash (replace with proper chain later)
        hash_value = _compute_simple_hash(username, amount, reason)
        prev_hash = None  # keep None for now; integrity module will fill/update if needed

        # Insert into logs table (match your DB schema)
        cur.execute(
            """
            INSERT INTO logs (user_id, action, details, prev_hash, hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, "threat_detection", details_text, prev_hash, hash_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

        # Insert also into anomalies table so the dashboard can show it
        cur.execute(
            """
            INSERT INTO anomalies (source, severity, details, metric_json, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("financial_engine", severity, details_text, metric_json, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

        conn.commit()
        print(f"[ALERT] {username} | {reason} | Amount: ₹{amount}")

    except sqlite3.Error as e:
        print(f"❌ Database Error while logging threat: {e}")
    finally:
        conn.close()


def detect_threats(transactions):
    """
    Rule-based financial threat detection engine.

    transactions: list of dicts like:
      [{"username":"user1","amount":150000,"location":"IN"}, ...]
    """
    detected_summary = []

    for tx in transactions:
        username = tx.get("username", "unknown")
        amount = tx.get("amount", 0)
        location = tx.get("location", DOMESTIC_CODE)

        # Rule 1: High-value
        if amount > HIGH_VALUE_LIMIT:
            reason = "⚠️ High-value transaction detected"
            log_threat(username, amount, reason, severity="HIGH")
            detected_summary.append((username, reason))

        # Rule 2: Foreign/unusual location
        if location != DOMESTIC_CODE:
            reason = "🌍 Transaction from unusual location"
            log_threat(username, amount, reason, severity="MEDIUM")
            detected_summary.append((username, reason))

        # Rule 3: Suspicious small transactions (example rule)
        if amount < SMALL_TX_LIMIT and username == "user1":
            reason = "💸 Multiple small transactions detected"
            log_threat(username, amount, reason, severity="LOW")
            detected_summary.append((username, reason))

    print("✅ Threat detection process completed.")
    return detected_summary


# Quick self-test when run directly
if __name__ == "__main__":
    sample_transactions = [
        {"username": "user1", "amount": 150000, "location": "IN"},
        {"username": "user1", "amount": 80, "location": "IN"},
        {"username": "analyst1", "amount": 50000, "location": "US"},
    ]
    print(detect_threats(sample_transactions))