# financial_threats.py
import sqlite3
from datetime import datetime

# Path to your database
DB_PATH = "finsecure.db"

# Thresholds (can be tweaked later)
HIGH_VALUE_LIMIT = 100000
SMALL_TX_LIMIT = 100
DOMESTIC_CODE = "IN"


def log_threat(username, amount, reason):
    """
    Inserts a detected threat into the logs table with a timestamp.
    Each threat is categorized as an alert-level event.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO logs (username, action, status, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                "threat_detection",
                "alert",
                f"{reason} | Amount: ₹{amount}",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
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

    Parameters:
        transactions (list of dicts):
            [
                {"username": "user1", "amount": 150000, "location": "IN"},
                {"username": "user2", "amount": 80, "location": "IN"},
                {"username": "analyst1", "amount": 50000, "location": "US"}
            ]

    Returns:
        List of detected threat messages for summary/reporting.
    """
    detected_summary = []

    for tx in transactions:
        username = tx.get("username")
        amount = tx.get("amount", 0)
        location = tx.get("location", DOMESTIC_CODE)

        # --- Rule 1: High-value transaction ---
        if amount > HIGH_VALUE_LIMIT:
            reason = "⚠️ High-value transaction detected"
            log_threat(username, amount, reason)
            detected_summary.append((username, reason))

        # --- Rule 2: Foreign or unusual location ---
        if location != DOMESTIC_CODE:
            reason = "🌍 Transaction from unusual location"
            log_threat(username, amount, reason)
            detected_summary.append((username, reason))

        # --- Rule 3: Suspicious small transactions ---
        if amount < SMALL_TX_LIMIT and username == "user1":  # sample rule
            reason = "💸 Multiple small transactions detected"
            log_threat(username, amount, reason)
            detected_summary.append((username, reason))

    print("✅ Threat detection process completed.")
    return detected_summary


# --- Example usage (for testing) ---
if __name__ == "__main__":
    sample_transactions = [
        {"username": "user1", "amount": 150000, "location": "IN"},
        {"username": "user1", "amount": 80, "location": "IN"},
        {"username": "analyst1", "amount": 50000, "location": "US"},
    ]

    summary = detect_threats(sample_transactions)
    print("\nSummary of detected threats:")
    for s in summary:
        print(f" - {s[0]}: {s[1]}")

