from fastapi import FastAPI
import sqlite3
import os

app = FastAPI()

# Path to your database
DB_PATH = os.path.join(os.path.dirname(__file__), "security.db")

@app.get("/test-db")
def test_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [t[0] for t in cursor.fetchall()]
        conn.close()
        return {"status": "✅ Connected to DB", "tables": tables}
    except Exception as e:
        return {"status": "❌ Failed", "error": str(e)}

