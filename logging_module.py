import hashlib, sqlite3, os, datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "security.db")

def log_event(user, action, details):
    """Logs an event and maintains hash chain for integrity."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 1️⃣ Get the last hash
    cursor.execute("SELECT hash FROM log_integrity ORDER BY id DESC LIMIT 1")
    last_hash = cursor.fetchone()
    prev_hash = last_hash[0] if last_hash else "0"*64

    # 2️⃣ Create new log record and its hash
    timestamp = datetime.datetime.utcnow().isoformat()
    record = f"{user}|{action}|{details}|{timestamp}|{prev_hash}"
    record_hash = hashlib.sha256(record.encode()).hexdigest()

    # 3️⃣ Insert into both tables
    cursor.execute(
        "INSERT INTO logs (user, action, details, timestamp) VALUES (?, ?, ?, ?)",
        (user, action, details, timestamp)
    )
    cursor.execute(
        "INSERT INTO log_integrity (hash, prev_hash, timestamp) VALUES (?, ?, ?)",
        (record_hash, prev_hash, timestamp)
    )

    conn.commit()
    conn.close()


