from flask import Flask, render_template
import json
import os
import time # Import time for better error reporting

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
        except (json.JSONDecodeError, IOError) as e:
            # Report the error but return default data
            print(f"[{time.strftime('%H:%M:%S')}] ERROR: Cannot read metrics.json. Daemon may be saving data.")
            pass
    # CRITICAL: Always return a default dictionary if the file is missing/unreadable.
    # This prevents the 'metrics is undefined' error.
    return {'cpu_usage': '--', 'mem_usage': '--', 'is_spike': False}

# --- ROUTES ---

@app.route('/')
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    admin_name = "Admin Yashvi"
    
    # 1. READ THE REAL-TIME DATA (Always returns a dictionary)
    metrics = read_metrics()
    
    # 2. RENDER THE TEMPLATE with all the variables
    # The 'metrics' variable is guaranteed to be defined here.
    return render_template(
        'dashboard.html', 
        username=admin_name, 
        metrics=metrics # Pass the metrics dictionary to the HTML
    )

# --- ADD THESE NEW ROUTES TO app.py ---

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

# ----------------------------------------

# --- RUN THE APP ---

if __name__ == '__main__':
    app.run(debug=True)