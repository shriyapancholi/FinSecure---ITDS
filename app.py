from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
import json
import os
import time
import subprocess
import sys
import threading
from datetime import datetime

# -------------------- Flask Initialization --------------------

app = Flask(__name__)
app.secret_key = "your-secret-key"  # Needed for flash messages

# -------------------- File Paths --------------------

METRICS_FILE = 'metrics.json'
ALERTS_FILE = 'alerts_log.json'

# -------------------- Utility Functions --------------------

def read_metrics():
    """Read the latest system metrics from JSON file."""
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {'cpu_usage': '--', 'mem_usage': '--', 'is_spike': False}


def append_alert_to_file(payload):
    """Save incoming detector alerts to a local JSON log."""
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


# -------------------- Routes --------------------

@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Simple login form handling."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Temporary simple authentication logic (replace later with DB auth)
        if username and password:
            flash("Login successful!", "success")
            return redirect(url_for('dashboard', username=username))
        else:
            flash("Invalid credentials. Please try again.", "error")

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """Render main dashboard showing system metrics."""
    username = request.args.get('username', 'Admin')
    metrics = read_metrics()
    return render_template('dashboard.html', username=username, metrics=metrics)


@app.route('/alerts_detail')
def alerts_detail():
    """Show a list of past alerts."""
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
    """Static user management view."""
    users = [
        {'id': 101, 'name': 'JaneD', 'role': 'Analyst', 'status': 'Restricted', 'last_login': '2025-10-15'},
        {'id': 102, 'name': 'JohnS', 'role': 'Manager', 'status': 'Active', 'last_login': '2025-10-20'},
    ]
    return render_template('user_management.html', users=users)


# -------------------- API Endpoints --------------------

@app.route('/api/metrics', methods=['GET'])
def api_metrics():
    """Return live metrics JSON for AJAX polling."""
    return jsonify(read_metrics())


@app.route('/api/alerts', methods=['POST'])
def api_alerts():
    """Receive real-time alerts from detector.py via HTTP POST."""
    payload = request.get_json(force=True, silent=True) or {}
    print(f"\n🚨 ALERT RECEIVED @ {datetime.now()} 🚨")
    print(json.dumps(payload, indent=2))
    append_alert_to_file(payload)
    return jsonify({"status": "ok", "message": "Alert received"}), 200


# -------------------- Launch Browser --------------------

def launch_browser():
    """Open the default browser automatically."""
    time.sleep(1)
    url = "http://127.0.0.1:5000/login"
    try:
        if sys.platform.startswith('win'):
            subprocess.run(['start', url], shell=True)
        elif sys.platform.startswith('darwin'):
            subprocess.run(['open', url])
        else:
            subprocess.run(['xdg-open', url])
    except Exception as e:
        print(f"[app] Warning: could not launch browser: {e}")


# -------------------- Entry Point --------------------

if __name__ == '__main__':
    if getattr(sys, 'frozen', False):
        threading.Thread(target=launch_browser, daemon=True).start()
        app.run(debug=False)
    else:
        threading.Thread(target=launch_browser, daemon=True).start()
        app.run(debug=True)
