import sqlite3
import os
import bcrypt
import jwt
import datetime

# Secret key for JWT
SECRET_KEY = "supersecretkey123"  # You can change this for production

# Path to your DB
DB_PATH = os.path.join(os.path.dirname(__file__), "security.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------- USER CREATION -----------------
def create_user(username, password, role="analyst"):
    """Create a new user with hashed password."""
    conn = get_db_connection()
    cursor = conn.cursor()

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, status) VALUES (?, ?, ?, ?)",
            (username, hashed_pw.decode("utf-8"), role, "active"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        print("User already exists.")
    finally:
        conn.close()


# ----------------- USER VERIFICATION -----------------
def verify_user(username, password):
    """Verify username and password, return role if valid."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    conn.close()

    if row:
        stored_hash, role = row
        if bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            return role
    return None


# ----------------- JWT TOKEN FUNCTIONS -----------------
def generate_token(username, role):
    """Generate a JWT token with username and role."""
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    """Decode and verify JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
