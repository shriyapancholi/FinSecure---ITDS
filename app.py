from flask import Flask, render_template, jsonify
import json
import os
import time
import subprocess  # REQUIRED for forcing browser launch in .exe
import sys         # REQUIRED to detect if running as an .exe
import threading   # REQUIRED for safe thread launching
from flask import request # Necessary for active link tracking in base.html

# Initialize the Flask application
app = Flask(__name__)

# Define the file path for the daemon data
METRICS_FILE = 'metrics.json' 

# --- FUNCTIONS ---

def read_metrics():
    """Reads the latest metrics from the JSON file created by detector.py."""
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    
    # CRITICAL: Always return a default dictionary if the file is missing/unreadable.
    return {'cpu_usage': '--', 'mem_usage': '--', 'is_spike': False}


# --- ROUTES ---

@app.route('/')
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    admin_name = "Admin Yashvi"
    metrics = read_metrics()
    
    return render_template(
        'dashboard.html', 
        username=admin_name, 
        metrics=metrics
    )

@app.route('/alerts_detail')
def alerts_detail():
    # Placeholder data for presentation
    alerts = [
        {'time': '10:05:30', 'user': 'JaneD', 'action': 'Suspension', 'reason': 'Access outside office hours', 'status': 'DANGER'},
        {'time': '10:06:15', 'user': 'JohnS', 'action': 'Soft Alert', 'reason': 'Failed login attempt (3/5)', 'status': 'WARNING'},
        {'time': '10:07:00', 'user': 'Admin Yashvi', 'action': 'Review', 'reason': 'Integrity Check Spike', 'status': 'INFO'},
    ]
    return render_template('alerts_detail.html', alerts=alerts)

@app.route('/user_management')
def user_management():
    # Placeholder data for presentation
    users = [
        {'id': 101, 'name': 'JaneD', 'role': 'Analyst', 'status': 'Restricted', 'last_login': '2025-10-15'},
        {'id': 102, 'name': 'JohnS', 'role': 'Manager', 'status': 'Active', 'last_login': '2025-10-20'},
    ]
    return render_template('user_management.html', users=users)

@app.route('/api/metrics', methods=['GET'])
def api_metrics():
    """Return live metrics data for AJAX polling"""
    data = read_metrics()
    return jsonify(data)

# --- FINAL LAUNCH LOGIC (Includes .EXE Fix) ---

def launch_browser():
    """Forces the browser to open using the Windows start command."""
    # Give the Flask server a moment to start up before launching the browser
    time.sleep(1) 
    url = "http://127.0.0.1:5000/login"
    
    # 'start' is the reliable Windows shell command for opening the default browser
    subprocess.run(['start', url], shell=True) 

if __name__ == '__main__':
    # Check if the app is running as a bundled executable (.exe)
    if getattr(sys, 'frozen', False):
        # If it's the .exe, launch the browser in a new thread and run the app
        threading.Thread(target=launch_browser).start()
        # Run the app in production mode
        app.run(debug=False)
    else:
        # If running via 'python app.py' in VS Code, use development mode
        app.run(debug=True)
