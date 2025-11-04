# app.py (hardened ready-to-paste)
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, Response
import json
import os
import time
import subprocess
import sys
import threading
import hashlib
from datetime import datetime, timedelta
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import defaultdict
from io import StringIO
import csv

# Rate limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------- App & config ----------------
# secret key from env (require in production)
SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY")
FLASK_ENV = os.environ.get("FLASK_ENV", "development")

if not SECRET_KEY:
    if FLASK_ENV == "production":
        raise RuntimeError("SENTINEL_SECRET_KEY environment variable is required in production")
    # dev fallback: ephemeral key (random)
    SECRET_KEY = os.urandom(32).hex()

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Trust reverse proxy headers (adjust counts to match your infra)
# If you have multiple proxies in front, increase x_for/x_proto accordingly.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# secure cookie settings (use secure cookies in production)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PREFERRED_URL_SCHEME='https',
    MAX_CONTENT_LENGTH = 4 * 1024 * 1024  # 4 MB limit for requests; tune as needed
)

# Set SESSION_COOKIE_SECURE only in production where HTTPS is actually used
if FLASK_ENV == "production":
    app.config.update(SESSION_COOKIE_SECURE=True, REMEMBER_COOKIE_SECURE=True)
else:
    # In local dev, avoid strict secure cookie to not break testing over http.
    app.config.update(SESSION_COOKIE_SECURE=False, REMEMBER_COOKIE_SECURE=False)

# ---------------- Rate limiter ----------------
# Use memory backend by default; for production use a Redis backend:
# export RATELIMIT_STORAGE_URI=redis://localhost:6379/0
_RATELIMIT_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

# create Limiter without passing `app` to avoid signature issues across versions
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri=_RATELIMIT_URI,
)
# rate limiter 
try:
    limiter.init_app(app)
except Exception as e:
    print("[warning] Rate limiter failed to initialize with storage:", _RATELIMIT_URI, "->", e)
    print("[warning] Falling back to in-memory rate limiter (non-persistent).")
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000 per day", "200 per hour"],
        storage_uri="memory://",
    )
    limiter.init_app(app)


# ---------------- Constants & DB ----------------
METRICS_FILE = 'metrics.json'
ALERTS_FILE = 'alerts_log.json'
DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")

# Lockout / suspension config
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_MINUTES = 15
SUSPEND_DURATION_MINUTES = 30   # timed suspension length
AUTO_SUSPEND_ON_LOCKOUT = True

# ---------------- DB helper ----------------
def get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- Logging helpers (compute hash + prev_hash) ----------------
def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _get_last_hash(conn):
    cur = conn.cursor()
    cur.execute("SELECT hash FROM logs ORDER BY id DESC LIMIT 1")
    r = cur.fetchone()
    return r['hash'] if r and 'hash' in r.keys() else ""

def log_event(conn, user_id=None, username=None, action="info", details=None, ip=None, user_agent=None):
    """
    Insert a log row with prev_hash & hash.
    details can be dict -> will be JSON serialized.
    Returns inserted log id.
    """
    details_text = json.dumps(details, default=str) if details is not None else None
    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    prev_hash = _get_last_hash(conn) or ""
    to_hash = f"{timestamp}|{user_id or ''}|{username or ''}|{action}|{details_text or ''}|{ip or ''}|{user_agent or ''}|{prev_hash}"
    h = _compute_hash(to_hash)

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (user_id, username, action, details, ip, user_agent, timestamp, prev_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, username, action, details_text, ip, user_agent, timestamp, prev_hash, h))
    conn.commit()
    return cur.lastrowid

# Optional: startup verification of the logs hash chain.
def verify_logs_chain(conn):
    """
    Walk the logs table ordered by id and verify hash chain integrity.
    Returns (ok: bool, bad_row: int or None, message)
    """
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, username, action, details, ip, user_agent, timestamp, prev_hash, hash FROM logs ORDER BY id ASC;")
        rows = cur.fetchall()
        last_hash = ""
        for r in rows:
            details_text = r['details'] if r['details'] is not None else ""
            to_hash = f"{r['timestamp']}|{r['user_id'] or ''}|{r['username'] or ''}|{r['action'] or ''}|{details_text or ''}|{r['ip'] or ''}|{r['user_agent'] or ''}|{r['prev_hash'] or ''}"
            computed = _compute_hash(to_hash)
            # prev_hash check: if prev_hash present, it should match last_hash
            if (r['prev_hash'] or "") != last_hash and (r['prev_hash'] not in ("", None)):
                return (False, r['id'], f"prev_hash mismatch at id {r['id']}")
            if r['hash'] != computed:
                return (False, r['id'], f"hash mismatch at id {r['id']}")
            last_hash = r['hash']
        return (True, None, "ok")
    except Exception as e:
        return (False, None, f"verify error: {e}")

# ---------------- Anomaly / response helpers ----------------
def raise_anomaly(conn, user_id=None, score=1.0, details=None, severity='high'):
    details_text = json.dumps(details, default=str) if details is not None else None
    created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO anomalies (user_id, score, details, severity, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (str(user_id) if user_id is not None else None, float(score) if score is not None else None, details_text, severity, created_at))
    conn.commit()
    return cur.lastrowid

def create_response(conn, anomaly_id=None, user_id=None, action='suspend_user', details=None):
    details_text = json.dumps(details, default=str) if details is not None else None
    created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO responses (anomaly_id, user_id, action, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (anomaly_id, user_id, action, details_text, created_at))
    conn.commit()
    return cur.lastrowid

def count_recent_failed_attempts(conn, username=None, ip=None, minutes=LOCKOUT_WINDOW_MINUTES):
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) as cnt FROM logs
        WHERE action = 'login_failed' AND timestamp >= ?
          AND (username = ? OR ip = ?)
    """, (cutoff_s, username, ip))
    row = cur.fetchone()
    return int(row["cnt"]) if row else 0

# ---------------- Metrics helpers (unchanged) ----------------
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
        payload['received_at'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        logs.append(payload)
        with open(ALERTS_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"[app] Warning: failed to save alert log: {e}")

# ---------------- Routes ----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# stricter rate-limit for login route (per IP)
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'
        user_agent = request.headers.get('User-Agent', 'unknown')

        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, role, suspended_until FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        uid = row['id'] if row else None

        # Log a "login_attempt"
        try:
            log_event(conn, user_id=uid, username=username, action='login_attempt', details={'ip': ip}, ip=ip, user_agent=user_agent)
        except Exception:
            # logging must not break authentication flow
            print("[warning] log_event failed for login_attempt")

        # User doesn't exist
        if not row:
            try:
                log_event(conn, username=username, action='login_failed', details={'reason': 'no_such_user'}, ip=ip, user_agent=user_agent)
            except Exception:
                pass
            conn.close()
            flash("No such user", "error")
            return render_template('login.html')

        # Check timed suspension (suspended_until)
        suspended_until = row['suspended_until']
        if suspended_until:
            suspended_dt = None
            try:
                suspended_dt = datetime.strptime(suspended_until, '%Y-%m-%d %H:%M:%S')
            except Exception:
                try:
                    suspended_dt = datetime.fromisoformat(suspended_until)
                except Exception:
                    suspended_dt = None

            if suspended_dt and datetime.utcnow() < suspended_dt:
                try:
                    log_event(conn, user_id=row['id'], username=username, action='login_blocked', details={'reason': 'suspended', 'until': suspended_until}, ip=ip, user_agent=user_agent)
                except Exception:
                    pass
                conn.close()
                flash("Account suspended until " + suspended_dt.strftime('%Y-%m-%d %H:%M:%S') + " UTC. Contact admin.", "error")
                return render_template('login.html')

        # No stored hash
        stored_hash = row['password_hash'] if 'password_hash' in row.keys() else None
        if not stored_hash:
            try:
                log_event(conn, user_id=row['id'], username=username, action='login_failed', details={'reason': 'no_password_hash'}, ip=ip, user_agent=user_agent)
            except Exception:
                pass
            conn.close()
            flash("User has no password set. Recreate account.", "error")
            return render_template('login.html')

        # Wrong password
        if not check_password_hash(stored_hash, password):
            try:
                log_event(conn, user_id=row['id'], username=username, action='login_failed', details={'reason': 'invalid_password'}, ip=ip, user_agent=user_agent)
            except Exception:
                pass

            fail_count = count_recent_failed_attempts(conn, username=username, ip=ip)
            print(f"[DEBUG] {username} failed attempts in window: {fail_count}")

            if fail_count >= LOCKOUT_THRESHOLD:
                details = {
                    'reason': 'failed_login_threshold',
                    'username': username,
                    'ip': ip,
                    'failed_count': fail_count,
                    'window_minutes': LOCKOUT_WINDOW_MINUTES
                }
                try:
                    anomaly_id = raise_anomaly(conn, user_id=row['id'], score=1.0, details=details, severity='high')
                    create_response(conn, anomaly_id=anomaly_id, user_id=row['id'],
                                    action='suspend_user', details={'auto': True, 'trigger': 'failed_logins'})
                except Exception as e:
                    print("[warning] anomaly raise failed:", e)

                append_alert_to_file({
                    "type": "auto_lockout",
                    "username": username,
                    "ip": ip,
                    "severity": "high",
                    "details": details,
                    "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                })

                if AUTO_SUSPEND_ON_LOCKOUT:
                    until_dt = datetime.utcnow() + timedelta(minutes=SUSPEND_DURATION_MINUTES)
                    until_s = until_dt.strftime('%Y-%m-%d %H:%M:%S')
                    try:
                        cur.execute("UPDATE users SET suspended_until = ? WHERE id = ?", (until_s, row['id']))
                        conn.commit()
                        log_event(conn, user_id=row['id'], username=username, action='user_suspended',
                                  details={'anomaly_id': anomaly_id, 'suspended_until': until_s}, ip=ip, user_agent=user_agent)
                    except Exception as e:
                        print("[warning] suspend update failed:", e)

                conn.close()
                flash("Account locked due to multiple failed login attempts.", "error")
                return render_template('login.html')

            conn.close()
            flash("Invalid credentials", "error")
            return render_template('login.html')

        # Success path
        try:
            log_event(conn, user_id=row['id'], username=username, action='login_success', details={'ip': ip}, ip=ip, user_agent=user_agent)
        except Exception:
            pass

        # Optional: clear past suspended_until if it's expired (cleanup)
        try:
            cur.execute("UPDATE users SET suspended_until = NULL WHERE id = ? AND suspended_until IS NOT NULL AND suspended_until <= ?", (row['id'], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        except Exception:
            pass

        # set session and redirect
        session['logged_in'] = True
        session['username'] = username
        # do not set 'suspended' flag to True by default — reflect actual state
        session['suspended'] = False
        session['role'] = row['role'] if row['role'] else 'analyst'
        conn.close()
        return redirect(url_for('dashboard', username=username))

    return render_template('login.html')

# signup should be rate-limited to avoid mass signup attempts
@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT,
                    password_hash TEXT,
                    role TEXT DEFAULT 'analyst' NOT NULL,
                    suspended_until DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # insert or update hashed password
            cur.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, COALESCE((SELECT role FROM users WHERE username = ?), 'analyst'), CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash
            """, (username, pw_hash, username))
            conn.commit()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            r = cur.fetchone()
            uid = r['id'] if r else None
            log_event(conn, user_id=uid, username=username, action='account_created', details={'method':'signup'})
            conn.close()
        except Exception as e:
            print("[signup] DB save warning:", e)

        flash("Account created (demo). Logging you in...", "success")
        return redirect(url_for('dashboard', username=username))

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """
    Dashboard page: system metrics + alert/lockout stats + recent anomalies.
    """
    metrics = read_metrics()  # unchanged metrics helper

    # DB stats
    try:
        conn = get_db_conn()
        cur = conn.cursor()

        # total anomalies
        cur.execute("SELECT COUNT(*) as cnt FROM anomalies;")
        total_anomalies = cur.fetchone()['cnt'] or 0

        # anomalies last 24 hours
        cur.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE created_at >= datetime('now','-1 day');")
        recent_24h = cur.fetchone()['cnt'] or 0

        # currently suspended users
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE suspended_until IS NOT NULL AND suspended_until > ?", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
        suspended_count = cur.fetchone()['cnt'] or 0

        # severity distribution (group by severity)
        cur.execute("SELECT severity, COUNT(*) as cnt FROM anomalies GROUP BY severity;")
        sev_rows = cur.fetchall()
        severity_counts = {r['severity'] or 'unknown': r['cnt'] for r in sev_rows}

        # last 5 anomalies
        cur.execute("SELECT id, user_id, score, details, severity, created_at FROM anomalies ORDER BY created_at DESC LIMIT 5;")
        recent_rows = cur.fetchall()
        recent_anomalies = []
        for r in recent_rows:
            details = None
            try:
                details = json.loads(r['details']) if r['details'] else None
            except Exception:
                details = r['details']
            recent_anomalies.append({
                "id": r['id'],
                "user_id": r['user_id'],
                "score": r['score'],
                "details": details,
                "severity": r['severity'],
                "created_at": r['created_at']
            })

        conn.close()
    except Exception as e:
        print("[dashboard] DB read failed:", e)
        total_anomalies = recent_24h = suspended_count = 0
        severity_counts = {}
        recent_anomalies = []

    labels = list(severity_counts.keys())
    values = [severity_counts[k] for k in labels]

    return render_template(
        'dashboard.html',
        username=session.get('username', 'Admin'),
        metrics=metrics,
        total_anomalies=total_anomalies,
        recent_24h=recent_24h,
        suspended_count=suspended_count,
        severity_labels=labels,
        severity_values=values,
        recent_anomalies=recent_anomalies
    )

@app.route('/alerts_detail')
def alerts_detail():
    anomalies = []
    file_alerts = []
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, score, details, severity, created_at FROM anomalies ORDER BY created_at DESC LIMIT 200;")
        rows = cur.fetchall()
        for r in rows:
            details = None
            try:
                details = json.loads(r['details']) if r['details'] else None
            except Exception:
                details = r['details']
            anomalies.append({
                "id": r['id'],
                "user_id": r['user_id'],
                "score": r['score'],
                "details": details,
                "severity": r['severity'],
                "created_at": r['created_at']
            })
        conn.close()
    except Exception as e:
        print("[alerts_detail] db read failed:", e)
        anomalies = []

    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                file_alerts = json.load(f) or []
        except Exception as _e:
            print("[alerts_detail] failed to read alerts_log.json:", _e)
            file_alerts = []

    return render_template('alerts_detail.html', alerts={"db": anomalies, "file": file_alerts})

# ---------------- API: metrics ----------------
@app.route('/api/metrics', methods=['GET'])
@limiter.limit("60 per minute")
def api_metrics():
    m = read_metrics()
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE suspended_until IS NOT NULL AND suspended_until > ?", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
        r = cur.fetchone()
        m['suspended_count'] = int(r['cnt']) if r else 0
        conn.close()
    except Exception as e:
        print("[api_metrics] suspended_count error:", e)
        m['suspended_count'] = 0
    return jsonify(m)

@app.route('/api/alerts', methods=['POST'])
@limiter.limit("60 per minute")
def api_alerts():
    payload = request.get_json(force=True, silent=True) or {}
    print(f"\n🚨 ALERT RECEIVED @ {datetime.utcnow()} 🚨")
    print(json.dumps(payload, indent=2))
    append_alert_to_file(payload)
    try:
        conn = get_db_conn()
        uid = payload.get('user_id') or payload.get('username') or None
        raise_anomaly(conn, user_id=uid, score=payload.get('score', 1.0), details=payload, severity=payload.get('severity','medium'))
        conn.close()
    except Exception as e:
        print("[api_alerts] DB write warning:", e)
    return jsonify({"status": "ok", "message": "Alert received"}), 200

# ---------------- API: anomalies ----------------
@app.route('/api/anomalies', methods=['GET'])
@limiter.limit("120 per minute")
def api_anomalies():
    severity = request.args.get('severity')
    username = request.args.get('username')
    limit = int(request.args.get('limit') or 200)

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        base_q = "SELECT id, user_id, score, details, severity, created_at FROM anomalies"
        clauses = []
        params = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if username:
            clauses.append("(user_id = ? OR details LIKE ?)")
            params.append(username)
            params.append(f'%{username}%')

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        order = " ORDER BY created_at DESC"
        limit_q = f" LIMIT {limit}"

        q = base_q + where + order + limit_q
        cur.execute(q, params)
        rows = cur.fetchall()
        anomalies = []
        for r in rows:
            details = None
            try:
                details = json.loads(r['details']) if r['details'] else None
            except Exception:
                details = r['details']
            anomalies.append({
                "id": r['id'],
                "user_id": r['user_id'],
                "score": r['score'],
                "details": details,
                "severity": r['severity'],
                "created_at": r['created_at']
            })
        conn.close()
        return jsonify({"status": "ok", "anomalies": anomalies})
    except Exception as e:
        print("[api_anomalies] error:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/anomalies/export', methods=['GET'])
@limiter.limit("10 per minute")
def api_anomalies_export():
    severity = request.args.get('severity')
    username = request.args.get('username')
    limit = int(request.args.get('limit') or 1000)

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        base_q = "SELECT id, user_id, score, details, severity, created_at FROM anomalies"
        clauses = []
        params = []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if username:
            clauses.append("(user_id = ? OR details LIKE ?)")
            params.append(username)
            params.append(f'%{username}%')

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        order = " ORDER BY created_at DESC"
        limit_q = f" LIMIT {limit}"

        q = base_q + where + order + limit_q
        cur.execute(q, params)
        rows = cur.fetchall()

        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(["id", "user_id", "score", "details", "severity", "created_at"])
        for r in rows:
            writer.writerow([r['id'], r['user_id'], r['score'], r['details'], r['severity'], r['created_at']])
        csv_data = si.getvalue()
        si.close()
        conn.close()

        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=anomalies_export.csv"}
        )
    except Exception as e:
        print("[api_anomalies_export] error:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------------- API: resume user (clears suspended_until) ----------------
@app.route('/api/users/resume', methods=['POST'])
@limiter.limit("10 per minute")
def api_users_resume():
    payload = request.get_json(force=True, silent=True) or {}
    user_id = payload.get('user_id')
    username = payload.get('username')

    if not user_id and not username:
        return jsonify({"error": "provide user_id or username"}), 400

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        if user_id:
            cur.execute("UPDATE users SET suspended_until = NULL WHERE id = ?", (user_id,))
        else:
            cur.execute("UPDATE users SET suspended_until = NULL WHERE username = ?", (username,))
        conn.commit()

        cur.execute("SELECT id, username FROM users WHERE id = ? OR username = ? LIMIT 1", (user_id, username))
        r = cur.fetchone()
        uid = r['id'] if r else None
        uname = r['username'] if r else (username or None)
        try:
            log_event(conn, user_id=uid, username=uname, action='user_resumed', details={'by': 'ui'}, ip=request.remote_addr, user_agent=request.headers.get('User-Agent'))
        except Exception:
            pass
        conn.close()
        return jsonify({"message": "user resumed"}), 200
    except Exception as e:
        print("[api/users/resume] error:", e)
        return jsonify({"error": str(e)}), 500

# ---------------- Utility: launch browser (dev only) ----------------
def launch_browser():
    if FLASK_ENV == "production":
        return
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

# ---------------- Enforce HTTPS (only when not debug/testing) ----------------
@app.before_request
def enforce_https_in_production():
    # Only force HTTPS if explicitly requested
    USE_HTTPS = os.environ.get("USE_HTTPS", "0").lower() in ("1", "true", "yes")

    if not (FLASK_ENV == "production" and USE_HTTPS):
        # Don’t force HTTPS unless enabled
        return

    proto = request.headers.get('X-Forwarded-Proto', request.scheme)
    if proto != 'https':
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

# ---------------- Run ----------------
if __name__ == '__main__':
    # Verify logs chain at startup (best-effort)
    try:
        conn = get_db_conn()
        ok, bad, msg = verify_logs_chain(conn)
        conn.close()
        if not ok:
            print("[SECURITY] Log chain verification FAILED:", msg)
        else:
            print("[SECURITY] Log chain OK")
    except Exception as e:
        print("[SECURITY] Log verification error:", e)

    # host/port from environment or defaults
    HOST = os.environ.get("FLASK_RUN_HOST", os.environ.get("HOST", "127.0.0.1"))
    PORT = int(os.environ.get("FLASK_RUN_PORT", os.environ.get("PORT", 5000)))

    # Update launch_browser to open correct port
    def launch_browser_with_port(host=HOST, port=PORT):
        if FLASK_ENV == "production":
            return
        time.sleep(1)
        url = f"http://{host}:{port}/login"
        try:
            if sys.platform.startswith('win'):
                subprocess.run(['start', url], shell=True)
            elif sys.platform.startswith('darwin'):
                subprocess.run(['open', url])
            else:
                subprocess.run(['xdg-open', url])
        except Exception as e:
            print(f"[app] Warning: could not launch browser: {e}")

    # Launch dev browser only in non-production
    threading.Thread(target=launch_browser_with_port, daemon=True).start()

    # debug flag driven by FLASK_ENV (if FLASK_ENV=production, disable debug)
    debug_mode = (FLASK_ENV != "production")
    # run with explicit host/port
    app.run(host=HOST, port=PORT, debug=debug_mode)