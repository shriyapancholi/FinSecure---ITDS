# app.py (only full file shown earlier — below is the corrected sections; replace your app.py with this)
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import json, os, time, subprocess, sys, threading
from datetime import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your-secret-key"

METRICS_FILE = 'metrics.json'
ALERTS_FILE = 'alerts_log.json'
DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")


def read_metrics():
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {'cpu_usage': '--', 'mem_usage': '--', 'is_spike': False}


def append_alert_to_file(payload):
    try:
        logs = []
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                logs = json.load(f)
        payload['received_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logs.append(payload)
        with open(ALERTS_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"[app] Warning: failed to save alert log: {e}")


def get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        conn = get_db_conn()
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("No such user", "error")
            return render_template('login.html', error="No such user")

        stored_hash = row['password_hash'] if 'password_hash' in row.keys() else None
        if not stored_hash:
            flash("User has no password hash stored. Please recreate account.", "error")
            return render_template('login.html', error="No password set for this user")

        if check_password_hash(stored_hash, password):
            flash("Login successful", "success")
            return redirect(url_for('dashboard', username=username))
        else:
            flash("Invalid password", "error")
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash("Provide username & password", "error")
            return render_template('signup.html')

        pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=12)

        try:
            conn = get_db_conn()
            cur = conn.cursor()
            # Ensure users table exists with compatible schema (do not overwrite a correct table)
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
            # Insert user - store hashed password into password_hash column.
            cur.execute("""
                INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, COALESCE((SELECT role FROM users WHERE username = ?), 'analyst'))
            """, (username, pw_hash, username))
            conn.commit()
            conn.close()
        except Exception as e:
            print("[signup] DB save warning:", e)

        flash("Account created (demo). Logging you in...", "success")
        return redirect(url_for('dashboard', username=username))

    return render_template('signup.html')


@app.route('/dashboard')
def dashboard():
    username = request.args.get('username', 'Admin')
    metrics = read_metrics()
    return render_template('dashboard.html', username=username, metrics=metrics)


@app.route('/alerts_detail')
def alerts_detail():
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
        except Exception:
            alerts = []
    else:
        alerts = []
    return render_template('alerts_detail.html', alerts=alerts)


@app.route('/user_management')
def user_management():
    users = [
        {'id': 101, 'name': 'JaneD', 'role': 'Analyst', 'status': 'Restricted', 'last_login': '2025-10-15'},
        {'id': 102, 'name': 'JohnS', 'role': 'Manager', 'status': 'Active', 'last_login': '2025-10-20'},
    ]
    return render_template('user_management.html', users=users)


@app.route('/api/metrics', methods=['GET'])
def api_metrics():
    return jsonify(read_metrics())


@app.route('/api/alerts', methods=['POST'])
def api_alerts():
    payload = request.get_json(force=True, silent=True) or {}
    print(f"\n🚨 ALERT RECEIVED @ {datetime.now()} 🚨")
    print(json.dumps(payload, indent=2))
    append_alert_to_file(payload)
    return jsonify({"status": "ok", "message": "Alert received"}), 200


def launch_browser():
    time.sleep(1)
    url = "http://127.0.0.1:5000/login"
    try:
        if sys.platform.startswith('win'): subprocess.run(['start', url], shell=True)
        elif sys.platform.startswith('darwin'): subprocess.run(['open', url])
        else: subprocess.run(['xdg-open', url])
    except Exception as e:
        print(f"[app] Warning: could not launch browser: {e}")


if __name__ == '__main__':
    threading.Thread(target=launch_browser, daemon=True).start()
    app.run(debug=True)