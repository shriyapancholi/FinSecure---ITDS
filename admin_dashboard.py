from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import sqlite3

app = FastAPI()

def get_db():
    conn = sqlite3.connect("finsecure.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/admin/logs")
def get_all_logs():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, action, status, details, timestamp FROM logs ORDER BY id DESC")
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found")
    return JSONResponse(content={"logs": logs})
