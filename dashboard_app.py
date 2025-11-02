from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI(title="FinSecure Dashboard")

DB_PATH = "finsecure.db"


@app.get("/", response_class=HTMLResponse)
def show_dashboard():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cur.fetchall()
    conn.close()

    # Inline CSS for color-coded table
    html_content = """
    <html>
    <head>
        <title>FinSecure Admin Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f7fc; color: #333; padding: 20px; }
            h1 { text-align: center; color: #1f4e79; }
            table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #1f4e79; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .success { color: green; font-weight: bold; }
            .failed { color: red; font-weight: bold; }
            .alert { color: darkred; font-weight: bold; }
            .denied { color: orange; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>📊 FinSecure Activity & Threat Dashboard</h1>
        <table>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Action</th>
                <th>Status</th>
                <th>Details</th>
                <th>Timestamp</th>
            </tr>
    """

    for log in logs:
        status_class = log["status"].lower() if log["status"] else ""
        html_content += f"""
        <tr>
            <td>{log['id']}</td>
            <td>{log['username']}</td>
            <td>{log['action']}</td>
            <td class='{status_class}'>{log['status']}</td>
            <td>{log['details'] or '-'}</td>
            <td>{log['timestamp']}</td>
        </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    return html_content
