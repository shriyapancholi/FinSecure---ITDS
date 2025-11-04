# # app.py (hardened ready-to-paste)
# from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session, Response
# import json
# import os
# import time
# import subprocess
# import sys
# import threading
# import hashlib
# from datetime import datetime, timedelta
# import sqlite3
# from werkzeug.security import generate_password_hash, check_password_hash
# from werkzeug.middleware.proxy_fix import ProxyFix
# from collections import defaultdict
# from io import StringIO
# import csv

# # Rate limiter
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address

# # ---------------- App & config ----------------
# # secret key from env (require in production)
# SECRET_KEY = os.environ.get("SENTINEL_SECRET_KEY")
# FLASK_ENV = os.environ.get("FLASK_ENV", "development")

# if not SECRET_KEY:
#     if FLASK_ENV == "production":
#         raise RuntimeError("SENTINEL_SECRET_KEY environment variable is required in production")
#     # dev fallback: ephemeral key (random)
#     SECRET_KEY = os.urandom(32).hex()

# app = Flask(__name__)
# app.secret_key = SECRET_KEY

# # Trust reverse proxy headers (adjust counts to match your infra)
# # If you have multiple proxies in front, increase x_for/x_proto accordingly.
# app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# # secure cookie settings (use secure cookies in production)
# app.config.update(
#     SESSION_COOKIE_HTTPONLY=True,
#     SESSION_COOKIE_SAMESITE='Lax',
#     PREFERRED_URL_SCHEME='https',
#     MAX_CONTENT_LENGTH = 4 * 1024 * 1024  # 4 MB limit for requests; tune as needed
# )

# # Set SESSION_COOKIE_SECURE only in production where HTTPS is actually used
# if FLASK_ENV == "production":
#     app.config.update(SESSION_COOKIE_SECURE=True, REMEMBER_COOKIE_SECURE=True)
# else:
#     # In local dev, avoid strict secure cookie to not break testing over http.
#     app.config.update(SESSION_COOKIE_SECURE=False, REMEMBER_COOKIE_SECURE=False)

# # ---------------- Rate limiter ----------------
# # Use memory backend by default; for production use a Redis backend:
# # export RATELIMIT_STORAGE_URI=redis://localhost:6379/0
# _RATELIMIT_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

# # create Limiter without passing `app` to avoid signature issues across versions
# limiter = Limiter(
#     key_func=get_remote_address,
#     default_limits=["1000 per day", "200 per hour"],
#     storage_uri=_RATELIMIT_URI,
# )
# # rate limiter 
# try:
#     limiter.init_app(app)
# except Exception as e:
#     print("[warning] Rate limiter failed to initialize with storage:", _RATELIMIT_URI, "->", e)
#     print("[warning] Falling back to in-memory rate limiter (non-persistent).")
#     limiter = Limiter(
#         key_func=get_remote_address,
#         default_limits=["1000 per day", "200 per hour"],
#         storage_uri="memory://",
#     )
#     limiter.init_app(app)


# # ---------------- Constants & DB ----------------
# METRICS_FILE = 'metrics.json'
# ALERTS_FILE = 'alerts_log.json'
# DB_PATH = os.path.join(os.path.dirname(__file__), "finsecure.db")

# # Lockout / suspension config
# LOCKOUT_THRESHOLD = 5
# LOCKOUT_WINDOW_MINUTES = 15
# SUSPEND_DURATION_MINUTES = 30   # timed suspension length
# AUTO_SUSPEND_ON_LOCKOUT = True

# # ---------------- DB helper ----------------
# def get_db_conn():
#     conn = sqlite3.connect(DB_PATH)
#     conn.row_factory = sqlite3.Row
#     return conn

# # ---------------- Logging helpers (compute hash + prev_hash) ----------------
# def _compute_hash(text: str) -> str:
#     return hashlib.sha256(text.encode('utf-8')).hexdigest()

# def _get_last_hash(conn):
#     cur = conn.cursor()
#     cur.execute("SELECT hash FROM logs ORDER BY id DESC LIMIT 1")
#     r = cur.fetchone()
#     return r['hash'] if r and 'hash' in r.keys() else ""

# def log_event(conn, user_id=None, username=None, action="info", details=None, ip=None, user_agent=None):
#     """
#     Insert a log row with prev_hash & hash.
#     details can be dict -> will be JSON serialized.
#     Returns inserted log id.
#     """
#     details_text = json.dumps(details, default=str) if details is not None else None
#     timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

#     prev_hash = _get_last_hash(conn) or ""
#     to_hash = f"{timestamp}|{user_id or ''}|{username or ''}|{action}|{details_text or ''}|{ip or ''}|{user_agent or ''}|{prev_hash}"
#     h = _compute_hash(to_hash)

#     cur = conn.cursor()
#     cur.execute("""
#         INSERT INTO logs (user_id, username, action, details, ip, user_agent, timestamp, prev_hash, hash)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
#     """, (user_id, username, action, details_text, ip, user_agent, timestamp, prev_hash, h))
#     conn.commit()
#     return cur.lastrowid

# # Optional: startup verification of the logs hash chain.
# def verify_logs_chain(conn):
#     """
#     Walk the logs table ordered by id and verify hash chain integrity.
#     Returns (ok: bool, bad_row: int or None, message)
#     """
#     try:
#         cur = conn.cursor()
#         cur.execute("SELECT id, user_id, username, action, details, ip, user_agent, timestamp, prev_hash, hash FROM logs ORDER BY id ASC;")
#         rows = cur.fetchall()
#         last_hash = ""
#         for r in rows:
#             details_text = r['details'] if r['details'] is not None else ""
#             to_hash = f"{r['timestamp']}|{r['user_id'] or ''}|{r['username'] or ''}|{r['action'] or ''}|{details_text or ''}|{r['ip'] or ''}|{r['user_agent'] or ''}|{r['prev_hash'] or ''}"
#             computed = _compute_hash(to_hash)
#             # prev_hash check: if prev_hash present, it should match last_hash
#             if (r['prev_hash'] or "") != last_hash and (r['prev_hash'] not in ("", None)):
#                 return (False, r['id'], f"prev_hash mismatch at id {r['id']}")
#             if r['hash'] != computed:
#                 return (False, r['id'], f"hash mismatch at id {r['id']}")
#             last_hash = r['hash']
#         return (True, None, "ok")
#     except Exception as e:
#         return (False, None, f"verify error: {e}")

# # ---------------- Anomaly / response helpers ----------------
# def raise_anomaly(conn, user_id=None, score=1.0, details=None, severity='high'):
#     details_text = json.dumps(details, default=str) if details is not None else None
#     created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
#     cur = conn.cursor()
#     cur.execute("""
#         INSERT INTO anomalies (user_id, score, details, severity, created_at)
#         VALUES (?, ?, ?, ?, ?)
#     """, (str(user_id) if user_id is not None else None, float(score) if score is not None else None, details_text, severity, created_at))
#     conn.commit()
#     return cur.lastrowid

# def create_response(conn, anomaly_id=None, user_id=None, action='suspend_user', details=None):
#     details_text = json.dumps(details, default=str) if details is not None else None
#     created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
#     cur = conn.cursor()
#     cur.execute("""
#         INSERT INTO responses (anomaly_id, user_id, action, details, created_at)
#         VALUES (?, ?, ?, ?, ?)
#     """, (anomaly_id, user_id, action, details_text, created_at))
#     conn.commit()
#     return cur.lastrowid

# def count_recent_failed_attempts(conn, username=None, ip=None, minutes=LOCKOUT_WINDOW_MINUTES):
#     cutoff = datetime.utcnow() - timedelta(minutes=minutes)
#     cutoff_s = cutoff.strftime('%Y-%m-%d %H:%M:%S')
#     cur = conn.cursor()
#     cur.execute("""
#         SELECT COUNT(*) as cnt FROM logs
#         WHERE action = 'login_failed' AND timestamp >= ?
#           AND (username = ? OR ip = ?)
#     """, (cutoff_s, username, ip))
#     row = cur.fetchone()
#     return int(row["cnt"]) if row else 0

# # ---------------- Metrics helpers (unchanged) ----------------
# def read_metrics():
#     if os.path.exists(METRICS_FILE):
#         try:
#             with open(METRICS_FILE, 'r') as f:
#                 return json.load(f)
#         except Exception:
#             pass
#     return {'cpu_usage': '--', 'mem_usage': '--', 'is_spike': False}

# def append_alert_to_file(payload):
#     try:
#         logs = []
#         if os.path.exists(ALERTS_FILE):
#             with open(ALERTS_FILE, 'r') as f:
#                 logs = json.load(f)
#         payload['received_at'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
#         logs.append(payload)
#         with open(ALERTS_FILE, 'w') as f:
#             json.dump(logs, f, indent=4)
#     except Exception as e:
#         print(f"[app] Warning: failed to save alert log: {e}")

# # ---------------- Routes ----------------
# @app.route('/')
# def home():
#     return redirect(url_for('login'))

# # stricter rate-limit for login route (per IP)
# @app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("6 per minute")
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username', '').strip()
#         password = request.form.get('password', '').strip()
#         ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'unknown'
#         user_agent = request.headers.get('User-Agent', 'unknown')

#         conn = get_db_conn()
#         cur = conn.cursor()
#         cur.execute("SELECT id, username, password_hash, role, suspended_until FROM users WHERE username = ?", (username,))
#         row = cur.fetchone()
#         uid = row['id'] if row else None

#         # Log a "login_attempt"
#         try:
#             log_event(conn, user_id=uid, username=username, action='login_attempt', details={'ip': ip}, ip=ip, user_agent=user_agent)
#         except Exception:
#             # logging must not break authentication flow
#             print("[warning] log_event failed for login_attempt")

#         # User doesn't exist
#         if not row:
#             try:
#                 log_event(conn, username=username, action='login_failed', details={'reason': 'no_such_user'}, ip=ip, user_agent=user_agent)
#             except Exception:
#                 pass
#             conn.close()
#             flash("No such user", "error")
#             return render_template('login.html')

#         # Check timed suspension (suspended_until)
#         suspended_until = row['suspended_until']
#         if suspended_until:
#             suspended_dt = None
#             try:
#                 suspended_dt = datetime.strptime(suspended_until, '%Y-%m-%d %H:%M:%S')
#             except Exception:
#                 try:
#                     suspended_dt = datetime.fromisoformat(suspended_until)
#                 except Exception:
#                     suspended_dt = None

#             if suspended_dt and datetime.utcnow() < suspended_dt:
#                 try:
#                     log_event(conn, user_id=row['id'], username=username, action='login_blocked', details={'reason': 'suspended', 'until': suspended_until}, ip=ip, user_agent=user_agent)
#                 except Exception:
#                     pass
#                 conn.close()
#                 flash("Account suspended until " + suspended_dt.strftime('%Y-%m-%d %H:%M:%S') + " UTC. Contact admin.", "error")
#                 return render_template('login.html')

#         # No stored hash
#         stored_hash = row['password_hash'] if 'password_hash' in row.keys() else None
#         if not stored_hash:
#             try:
#                 log_event(conn, user_id=row['id'], username=username, action='login_failed', details={'reason': 'no_password_hash'}, ip=ip, user_agent=user_agent)
#             except Exception:
#                 pass
#             conn.close()
#             flash("User has no password set. Recreate account.", "error")
#             return render_template('login.html')

#         # Wrong password
#         if not check_password_hash(stored_hash, password):
#             try:
#                 log_event(conn, user_id=row['id'], username=username, action='login_failed', details={'reason': 'invalid_password'}, ip=ip, user_agent=user_agent)
#             except Exception:
#                 pass

#             fail_count = count_recent_failed_attempts(conn, username=username, ip=ip)
#             print(f"[DEBUG] {username} failed attempts in window: {fail_count}")

#             if fail_count >= LOCKOUT_THRESHOLD:
#                 details = {
#                     'reason': 'failed_login_threshold',
#                     'username': username,
#                     'ip': ip,
#                     'failed_count': fail_count,
#                     'window_minutes': LOCKOUT_WINDOW_MINUTES
#                 }
#                 try:
#                     anomaly_id = raise_anomaly(conn, user_id=row['id'], score=1.0, details=details, severity='high')
#                     create_response(conn, anomaly_id=anomaly_id, user_id=row['id'],
#                                     action='suspend_user', details={'auto': True, 'trigger': 'failed_logins'})
#                 except Exception as e:
#                     print("[warning] anomaly raise failed:", e)

#                 append_alert_to_file({
#                     "type": "auto_lockout",
#                     "username": username,
#                     "ip": ip,
#                     "severity": "high",
#                     "details": details,
#                     "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
#                 })

#                 if AUTO_SUSPEND_ON_LOCKOUT:
#                     until_dt = datetime.utcnow() + timedelta(minutes=SUSPEND_DURATION_MINUTES)
#                     until_s = until_dt.strftime('%Y-%m-%d %H:%M:%S')
#                     try:
#                         cur.execute("UPDATE users SET suspended_until = ? WHERE id = ?", (until_s, row['id']))
#                         conn.commit()
#                         log_event(conn, user_id=row['id'], username=username, action='user_suspended',
#                                   details={'anomaly_id': anomaly_id, 'suspended_until': until_s}, ip=ip, user_agent=user_agent)
#                     except Exception as e:
#                         print("[warning] suspend update failed:", e)

#                 conn.close()
#                 flash("Account locked due to multiple failed login attempts.", "error")
#                 return render_template('login.html')

#             conn.close()
#             flash("Invalid credentials", "error")
#             return render_template('login.html')

#         # Success path
#         try:
#             log_event(conn, user_id=row['id'], username=username, action='login_success', details={'ip': ip}, ip=ip, user_agent=user_agent)
#         except Exception:
#             pass

#         # Optional: clear past suspended_until if it's expired (cleanup)
#         try:
#             cur.execute("UPDATE users SET suspended_until = NULL WHERE id = ? AND suspended_until IS NOT NULL AND suspended_until <= ?", (row['id'], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
#             conn.commit()
#         except Exception:
#             pass

#         # set session and redirect
#         session['logged_in'] = True
#         session['username'] = username
#         # do not set 'suspended' flag to True by default — reflect actual state
#         session['suspended'] = False
#         session['role'] = row['role'] if row['role'] else 'analyst'
#         conn.close()
#         return redirect(url_for('dashboard', username=username))

#     return render_template('login.html')

# # signup should be rate-limited to avoid mass signup attempts
# @app.route('/signup', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
# def signup():
#     if request.method == 'POST':
#         username = request.form.get('username', '').strip()
#         password = request.form.get('password', '').strip()

#         if not username or not password:
#             flash("Provide username & password", "error")
#             return render_template('signup.html')

#         pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=12)

#         try:
#             conn = get_db_conn()
#             cur = conn.cursor()
#             cur.execute("""
#                 CREATE TABLE IF NOT EXISTS users (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     username TEXT UNIQUE NOT NULL,
#                     password TEXT,
#                     password_hash TEXT,
#                     role TEXT DEFAULT 'analyst' NOT NULL,
#                     suspended_until DATETIME,
#                     created_at DATETIME DEFAULT CURRENT_TIMESTAMP
#                 );
#             """)
#             # insert or update hashed password
#             cur.execute("""
#                 INSERT INTO users (username, password_hash, role, created_at)
#                 VALUES (?, ?, COALESCE((SELECT role FROM users WHERE username = ?), 'analyst'), CURRENT_TIMESTAMP)
#                 ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash
#             """, (username, pw_hash, username))
#             conn.commit()
#             cur.execute("SELECT id FROM users WHERE username = ?", (username,))
#             r = cur.fetchone()
#             uid = r['id'] if r else None
#             log_event(conn, user_id=uid, username=username, action='account_created', details={'method':'signup'})
#             conn.close()
#         except Exception as e:
#             print("[signup] DB save warning:", e)

#         flash("Account created (demo). Logging you in...", "success")
#         return redirect(url_for('dashboard', username=username))

#     return render_template('signup.html')

# @app.route('/logout')
# def logout():
#     session.clear()
#     flash("Logged out", "success")
#     return redirect(url_for('login'))

# @app.route('/dashboard')
# def dashboard():
#     """
#     Dashboard page: system metrics + alert/lockout stats + recent anomalies.
#     """
#     metrics = read_metrics()  # unchanged metrics helper

#     # DB stats
#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()

#         # total anomalies
#         cur.execute("SELECT COUNT(*) as cnt FROM anomalies;")
#         total_anomalies = cur.fetchone()['cnt'] or 0

#         # anomalies last 24 hours
#         cur.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE created_at >= datetime('now','-1 day');")
#         recent_24h = cur.fetchone()['cnt'] or 0

#         # currently suspended users
#         cur.execute("SELECT COUNT(*) as cnt FROM users WHERE suspended_until IS NOT NULL AND suspended_until > ?", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
#         suspended_count = cur.fetchone()['cnt'] or 0

#         # severity distribution (group by severity)
#         cur.execute("SELECT severity, COUNT(*) as cnt FROM anomalies GROUP BY severity;")
#         sev_rows = cur.fetchall()
#         severity_counts = {r['severity'] or 'unknown': r['cnt'] for r in sev_rows}

#         # last 5 anomalies
#         cur.execute("SELECT id, user_id, score, details, severity, created_at FROM anomalies ORDER BY created_at DESC LIMIT 5;")
#         recent_rows = cur.fetchall()
#         recent_anomalies = []
#         for r in recent_rows:
#             details = None
#             try:
#                 details = json.loads(r['details']) if r['details'] else None
#             except Exception:
#                 details = r['details']
#             recent_anomalies.append({
#                 "id": r['id'],
#                 "user_id": r['user_id'],
#                 "score": r['score'],
#                 "details": details,
#                 "severity": r['severity'],
#                 "created_at": r['created_at']
#             })

#         conn.close()
#     except Exception as e:
#         print("[dashboard] DB read failed:", e)
#         total_anomalies = recent_24h = suspended_count = 0
#         severity_counts = {}
#         recent_anomalies = []

#     labels = list(severity_counts.keys())
#     values = [severity_counts[k] for k in labels]

#     return render_template(
#         'dashboard.html',
#         username=session.get('username', 'Admin'),
#         metrics=metrics,
#         total_anomalies=total_anomalies,
#         recent_24h=recent_24h,
#         suspended_count=suspended_count,
#         severity_labels=labels,
#         severity_values=values,
#         recent_anomalies=recent_anomalies
#     )

# @app.route('/alerts_detail')
# def alerts_detail():
#     anomalies = []
#     file_alerts = []
#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         cur.execute("SELECT id, user_id, score, details, severity, created_at FROM anomalies ORDER BY created_at DESC LIMIT 200;")
#         rows = cur.fetchall()
#         for r in rows:
#             details = None
#             try:
#                 details = json.loads(r['details']) if r['details'] else None
#             except Exception:
#                 details = r['details']
#             anomalies.append({
#                 "id": r['id'],
#                 "user_id": r['user_id'],
#                 "score": r['score'],
#                 "details": details,
#                 "severity": r['severity'],
#                 "created_at": r['created_at']
#             })
#         conn.close()
#     except Exception as e:
#         print("[alerts_detail] db read failed:", e)
#         anomalies = []

#     if os.path.exists(ALERTS_FILE):
#         try:
#             with open(ALERTS_FILE, 'r') as f:
#                 file_alerts = json.load(f) or []
#         except Exception as _e:
#             print("[alerts_detail] failed to read alerts_log.json:", _e)
#             file_alerts = []

#     return render_template('alerts_detail.html', alerts={"db": anomalies, "file": file_alerts})

# # ---------------- API: metrics ----------------
# @app.route('/api/metrics', methods=['GET'])
# @limiter.limit("60 per minute")
# def api_metrics():
#     m = read_metrics()
#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         cur.execute("SELECT COUNT(*) as cnt FROM users WHERE suspended_until IS NOT NULL AND suspended_until > ?", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
#         r = cur.fetchone()
#         m['suspended_count'] = int(r['cnt']) if r else 0
#         conn.close()
#     except Exception as e:
#         print("[api_metrics] suspended_count error:", e)
#         m['suspended_count'] = 0
#     return jsonify(m)

# @app.route('/api/alerts', methods=['POST'])
# @limiter.limit("60 per minute")
# def api_alerts():
#     payload = request.get_json(force=True, silent=True) or {}
#     print(f"\n🚨 ALERT RECEIVED @ {datetime.utcnow()} 🚨")
#     print(json.dumps(payload, indent=2))
#     append_alert_to_file(payload)
#     try:
#         conn = get_db_conn()
#         uid = payload.get('user_id') or payload.get('username') or None
#         raise_anomaly(conn, user_id=uid, score=payload.get('score', 1.0), details=payload, severity=payload.get('severity','medium'))
#         conn.close()
#     except Exception as e:
#         print("[api_alerts] DB write warning:", e)
#     return jsonify({"status": "ok", "message": "Alert received"}), 200

# # ---------------- API: anomalies ----------------
# @app.route('/api/anomalies', methods=['GET'])
# @limiter.limit("120 per minute")
# def api_anomalies():
#     severity = request.args.get('severity')
#     username = request.args.get('username')
#     limit = int(request.args.get('limit') or 200)

#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         base_q = "SELECT id, user_id, score, details, severity, created_at FROM anomalies"
#         clauses = []
#         params = []

#         if severity:
#             clauses.append("severity = ?")
#             params.append(severity)
#         if username:
#             clauses.append("(user_id = ? OR details LIKE ?)")
#             params.append(username)
#             params.append(f'%{username}%')

#         where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
#         order = " ORDER BY created_at DESC"
#         limit_q = f" LIMIT {limit}"

#         q = base_q + where + order + limit_q
#         cur.execute(q, params)
#         rows = cur.fetchall()
#         anomalies = []
#         for r in rows:
#             details = None
#             try:
#                 details = json.loads(r['details']) if r['details'] else None
#             except Exception:
#                 details = r['details']
#             anomalies.append({
#                 "id": r['id'],
#                 "user_id": r['user_id'],
#                 "score": r['score'],
#                 "details": details,
#                 "severity": r['severity'],
#                 "created_at": r['created_at']
#             })
#         conn.close()
#         return jsonify({"status": "ok", "anomalies": anomalies})
#     except Exception as e:
#         print("[api_anomalies] error:", e)
#         return jsonify({"status": "error", "message": str(e)}), 500

# @app.route('/api/anomalies/export', methods=['GET'])
# @limiter.limit("10 per minute")
# def api_anomalies_export():
#     severity = request.args.get('severity')
#     username = request.args.get('username')
#     limit = int(request.args.get('limit') or 1000)

#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         base_q = "SELECT id, user_id, score, details, severity, created_at FROM anomalies"
#         clauses = []
#         params = []

#         if severity:
#             clauses.append("severity = ?")
#             params.append(severity)
#         if username:
#             clauses.append("(user_id = ? OR details LIKE ?)")
#             params.append(username)
#             params.append(f'%{username}%')

#         where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
#         order = " ORDER BY created_at DESC"
#         limit_q = f" LIMIT {limit}"

#         q = base_q + where + order + limit_q
#         cur.execute(q, params)
#         rows = cur.fetchall()

#         si = StringIO()
#         writer = csv.writer(si)
#         writer.writerow(["id", "user_id", "score", "details", "severity", "created_at"])
#         for r in rows:
#             writer.writerow([r['id'], r['user_id'], r['score'], r['details'], r['severity'], r['created_at']])
#         csv_data = si.getvalue()
#         si.close()
#         conn.close()

#         return Response(
#             csv_data,
#             mimetype="text/csv",
#             headers={"Content-disposition": "attachment; filename=anomalies_export.csv"}
#         )
#     except Exception as e:
#         print("[api_anomalies_export] error:", e)
#         return jsonify({"status": "error", "message": str(e)}), 500

# # ---------------- API: resume user (clears suspended_until) ----------------
# @app.route('/api/users/resume', methods=['POST'])
# @limiter.limit("10 per minute")
# def api_users_resume():
#     payload = request.get_json(force=True, silent=True) or {}
#     user_id = payload.get('user_id')
#     username = payload.get('username')

#     if not user_id and not username:
#         return jsonify({"error": "provide user_id or username"}), 400

#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         if user_id:
#             cur.execute("UPDATE users SET suspended_until = NULL WHERE id = ?", (user_id,))
#         else:
#             cur.execute("UPDATE users SET suspended_until = NULL WHERE username = ?", (username,))
#         conn.commit()

#         cur.execute("SELECT id, username FROM users WHERE id = ? OR username = ? LIMIT 1", (user_id, username))
#         r = cur.fetchone()
#         uid = r['id'] if r else None
#         uname = r['username'] if r else (username or None)
#         try:
#             log_event(conn, user_id=uid, username=uname, action='user_resumed', details={'by': 'ui'}, ip=request.remote_addr, user_agent=request.headers.get('User-Agent'))
#         except Exception:
#             pass
#         conn.close()
#         return jsonify({"message": "user resumed"}), 200
#     except Exception as e:
#         print("[api/users/resume] error:", e)
#         return jsonify({"error": str(e)}), 500
    
# # ---------------- API: delete user (remove from users table) ----------------
# @app.route('/api/users/delete', methods=['POST'])
# @limiter.limit("10 per minute")
# def api_users_delete():
#     payload = request.get_json(force=True, silent=True) or {}
#     user_id = payload.get('user_id')
#     username = payload.get('username')

#     if not user_id and not username:
#         return jsonify({"error": "provide user_id or username"}), 400

#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()

#         # Resolve id+username first (for logging)
#         if user_id:
#             cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
#         else:
#             cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
#         r = cur.fetchone()
#         if not r:
#             conn.close()
#             return jsonify({"error": "user not found"}), 404

#         uid = r["id"]
#         uname = r["username"]

#         # Delete user (keep anomalies/logs for audit)
#         cur.execute("DELETE FROM users WHERE id = ?", (uid,))
#         conn.commit()

#         try:
#             log_event(
#                 conn,
#                 user_id=uid,
#                 username=uname,
#                 action='user_deleted',
#                 details={'by': 'ui'},
#                 ip=request.remote_addr,
#                 user_agent=request.headers.get('User-Agent')
#             )
#         except Exception:
#             pass

#         conn.close()
#         return jsonify({"message": f"user '{uname}' deleted"}), 200
#     except Exception as e:
#         print("[api/users/delete] error:", e)
#         return jsonify({"error": str(e)}), 500

# # ---------------- Utility: launch browser (dev only) ----------------
# def launch_browser():
#     if FLASK_ENV == "production":
#         return
#     time.sleep(1)
#     url = "http://127.0.0.1:5000/login"
#     try:
#         if sys.platform.startswith('win'):
#             subprocess.run(['start', url], shell=True)
#         elif sys.platform.startswith('darwin'):
#             subprocess.run(['open', url])
#         else:
#             subprocess.run(['xdg-open', url])
#     except Exception as e:
#         print(f"[app] Warning: could not launch browser: {e}")

# # ---------------- Enforce HTTPS (only when not debug/testing) ----------------
# @app.before_request
# def enforce_https_in_production():
#     # Only force HTTPS if explicitly requested
#     USE_HTTPS = os.environ.get("USE_HTTPS", "0").lower() in ("1", "true", "yes")

#     if not (FLASK_ENV == "production" and USE_HTTPS):
#         # Don’t force HTTPS unless enabled
#         return

#     proto = request.headers.get('X-Forwarded-Proto', request.scheme)
#     if proto != 'https':
#         url = request.url.replace("http://", "https://", 1)
#         return redirect(url, code=301)
    
# # ---------------- API: flag counts per user (total anomalies ever) ----------------
# @app.route('/api/users/flag_counts', methods=['POST'])
# @limiter.limit("30 per minute")
# def api_users_flag_counts():
#     """
#     Payload: { "users": ["alice", "bob", "uid-123", ...] }
#     Returns: { "alice": 7, "bob": 1, "uid-123": 3, ... }
#     Counts an anomaly if either anomalies.user_id == username OR details contains that username.
#     """
#     payload = request.get_json(force=True, silent=True) or {}
#     users = payload.get('users') or []
#     if not isinstance(users, list) or not users:
#         return jsonify({"error": "provide non-empty 'users' array"}), 400

#     users = [str(u).strip() for u in users if str(u).strip()]
#     if not users:
#         return jsonify({"error": "no valid users"}), 400

#     counts = {}
#     try:
#         conn = get_db_conn()
#         cur = conn.cursor()
#         # Avoid JSON1 dependency by LIKE matching in details.
#         for u in set(users):
#             # Try matching in either user_id (string) or details JSON/text
#             # We use a conservative LIKE. If you store JSON uniformly, JSON1 can be used instead.
#             like = f'%"{u}"%'  # matches ... "username":"u" or any string containing u in JSON
#             cur.execute("""
#                 SELECT COUNT(*) as cnt
#                 FROM anomalies
#                 WHERE (user_id = ?)
#                    OR (details LIKE ?)
#             """, (u, like))
#             row = cur.fetchone()
#             counts[u] = int(row['cnt'] if row else 0)
#         conn.close()
#         return jsonify({"status": "ok", "counts": counts}), 200
#     except Exception as e:
#         print("[api/users/flag_counts] error:", e)
#         return jsonify({"error": str(e)}), 500

# # ---------------- Run ----------------
# if __name__ == '__main__':
#     # Verify logs chain at startup (best-effort)
#     try:
#         conn = get_db_conn()
#         ok, bad, msg = verify_logs_chain(conn)
#         conn.close()
#         if not ok:
#             print("[SECURITY] Log chain verification FAILED:", msg)
#         else:
#             print("[SECURITY] Log chain OK")
#     except Exception as e:
#         print("[SECURITY] Log verification error:", e)

#     # host/port from environment or defaults
#     HOST = os.environ.get("FLASK_RUN_HOST", os.environ.get("HOST", "127.0.0.1"))
#     PORT = int(os.environ.get("FLASK_RUN_PORT", os.environ.get("PORT", 5000)))

#     # Update launch_browser to open correct port
#     def launch_browser_with_port(host=HOST, port=PORT):
#         if FLASK_ENV == "production":
#             return
#         time.sleep(1)
#         url = f"http://{host}:{port}/login"
#         try:
#             if sys.platform.startswith('win'):
#                 subprocess.run(['start', url], shell=True)
#             elif sys.platform.startswith('darwin'):
#                 subprocess.run(['open', url])
#             else:
#                 subprocess.run(['xdg-open', url])
#         except Exception as e:
#             print(f"[app] Warning: could not launch browser: {e}")

#     # Launch dev browser only in non-production
#     threading.Thread(target=launch_browser_with_port, daemon=True).start()

#     # debug flag driven by FLASK_ENV (if FLASK_ENV=production, disable debug)
#     debug_mode = (FLASK_ENV != "production")
#     # run with explicit host/port
#     app.run(host=HOST, port=PORT, debug=debug_mode)


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
from typing import Optional, Dict, Any

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
    app.config.update(SESSION_COOKIE_SECURE=False, REMEMBER_COOKIE_SECURE=False)

# ---------------- Rate limiter ----------------
_RATELIMIT_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri=_RATELIMIT_URI,
)
try:
    limiter.init_app(app)
except Exception as e:
    print("[warning] Rate limiter init failed:", _RATELIMIT_URI, "->", e)
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
SUSPEND_DURATION_MINUTES = 30
AUTO_SUSPEND_ON_LOCKOUT = True

# ---------------- DB helper ----------------
def get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_db_schema():
    """
    Create required tables if missing (users/logs/anomalies/responses/audit_logs).
    Keeps your existing columns intact.
    """
    conn = get_db_conn()
    cur = conn.cursor()

    # users
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

    # logs with hash chain
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        username TEXT,
        action TEXT,
        details TEXT,
        ip TEXT,
        user_agent TEXT,
        timestamp DATETIME,
        prev_hash TEXT,
        hash TEXT
    );
    """)

    # anomalies
    cur.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        score REAL,
        details TEXT,
        severity TEXT,
        created_at DATETIME
    );
    """)

    # responses
    cur.execute("""
    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER,
        user_id TEXT,
        action TEXT,
        details TEXT,
        created_at DATETIME
    );
    """)

    # 🔐 audit_logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,          -- resume_user / delete_user / ...
        actor TEXT NOT NULL,           -- session username
        target_user TEXT,              -- affected username/id
        reason TEXT,
        ip TEXT,
        user_agent TEXT,
        extra TEXT,                    -- JSON string
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()

# ---------------- Logging helpers (compute hash + prev_hash) ----------------
def _compute_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def ensure_audit_table():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,           -- e.g. user_deleted, user_resumed, login_success
            actor TEXT NOT NULL,            -- who performed the action (session username or 'system')
            target_user TEXT,               -- subject user (if any)
            reason TEXT,                    -- reason from UI
            ip TEXT,
            user_agent TEXT,
            extra TEXT,                     -- JSON string
            created_at DATETIME NOT NULL
        );
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print("[audit] table ensure failed:", e)

def _get_last_hash(conn):
    cur = conn.cursor()
    cur.execute("SELECT hash FROM logs ORDER BY id DESC LIMIT 1")
    r = cur.fetchone()
    return r['hash'] if r and 'hash' in r.keys() else ""

def log_event(conn, user_id=None, username=None, action="info", details=None, ip=None, user_agent=None):
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

def verify_logs_chain(conn):
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, user_id, username, action, details, ip, user_agent, timestamp, prev_hash, hash FROM logs ORDER BY id ASC;")
        rows = cur.fetchall()
        last_hash = ""
        for r in rows:
            details_text = r['details'] if r['details'] is not None else ""
            to_hash = f"{r['timestamp']}|{r['user_id'] or ''}|{r['username'] or ''}|{r['action'] or ''}|{details_text or ''}|{r['ip'] or ''}|{r['user_agent'] or ''}|{r['prev_hash'] or ''}"
            computed = _compute_hash(to_hash)
            if (r['prev_hash'] or "") != last_hash and (r['prev_hash'] not in ("", None)):
                return (False, r['id'], f"prev_hash mismatch at id {r['id']}")
            if r['hash'] != computed:
                return (False, r['id'], f"hash mismatch at id {r['id']}")
            last_hash = r['hash']
        return (True, None, "ok")
    except Exception as e:
        return (False, None, f"verify error: {e}")

# ---------------- 🔐 Audit helper ----------------
def log_audit(
    action: str,
    actor: str,
    target_user: Optional[str] = None,
    reason: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None
):
    """
    Writes an audit_logs row. Never raises.
    """
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO audit_logs (action, actor, target_user, reason, ip, user_agent, extra, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            action,
            actor or "anonymous",
            target_user,
            reason,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent"),
            json.dumps(extra or {}, ensure_ascii=False),
            datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print("[audit] write failed:", e)

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

# ---------------- Metrics helpers ----------------
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
            print("[warning] log_event failed for login_attempt")

        if not row:
            try:
                log_event(conn, username=username, action='login_failed', details={'reason': 'no_such_user'}, ip=ip, user_agent=user_agent)
            except Exception:
                pass
            conn.close()
            flash("No such user", "error")
            return render_template('login.html')

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

        stored_hash = row['password_hash'] if 'password_hash' in row.keys() else None
        if not stored_hash:
            try:
                log_event(conn, user_id=row['id'], username=username, action='login_failed', details={'reason': 'no_password_hash'}, ip=ip, user_agent=user_agent)
            except Exception:
                pass
            conn.close()
            flash("User has no password set. Recreate account.", "error")
            return render_template('login.html')

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

        try:
            cur.execute("UPDATE users SET suspended_until = NULL WHERE id = ? AND suspended_until IS NOT NULL AND suspended_until <= ?", (row['id'], datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        except Exception:
            pass

        session['logged_in'] = True
        session['username'] = username
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
        desired_role = (request.form.get('role') or 'analyst').strip().lower()
        admin_code_supplied = (request.form.get('admin_code') or '').strip()

        if not username or not password:
            flash("Provide username & password", "error")
            return render_template('signup.html')

        # Ensure tables exist
        ensure_db_schema()

        # Check if any admin exists already
        conn = get_db_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'")
            admin_count = int(cur.fetchone()['c'])
        except Exception:
            admin_count = 0

        # If user selected admin role, enforce code unless this is the first admin
        if desired_role == 'admin':
            ADMIN_SIGNUP_CODE = os.environ.get('ADMIN_SIGNUP_CODE', '').strip()
            if admin_count > 0:
                if not ADMIN_SIGNUP_CODE:
                    flash("Admin signup is disabled (no ADMIN_SIGNUP_CODE set). Ask an existing admin.", "error")
                    conn.close()
                    return render_template('signup.html')
                if admin_code_supplied != ADMIN_SIGNUP_CODE:
                    flash("Invalid admin code.", "error")
                    conn.close()
                    return render_template('signup.html')

        pw_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=12)

        try:
            # create (or update) user and set the role
            cur.execute("""
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role
            """, (username, pw_hash, desired_role if desired_role in ('admin','analyst') else 'analyst'))
            conn.commit()

            cur.execute("SELECT id, role FROM users WHERE username=?", (username,))
            r = cur.fetchone()
            uid = r['id'] if r else None
            role = r['role'] if r else 'analyst'

            log_event(conn, user_id=uid, username=username, action='account_created',
                      details={'method':'signup','role':role})

            # Auto-login
            session['logged_in'] = True
            session['username'] = username
            session['suspended'] = False
            session['role'] = role
            conn.close()

            flash(f"Account created as {role}.", "success")
            return redirect(url_for('dashboard', username=username))
        except Exception as e:
            conn.close()
            flash("Signup failed. Username may be taken.", "error")
            return render_template('signup.html')

    # GET
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
    metrics = read_metrics()

    try:
        conn = get_db_conn()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as cnt FROM anomalies;")
        total_anomalies = cur.fetchone()['cnt'] or 0

        cur.execute("SELECT COUNT(*) as cnt FROM anomalies WHERE created_at >= datetime('now','-1 day');")
        recent_24h = cur.fetchone()['cnt'] or 0

        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE suspended_until IS NOT NULL AND suspended_until > ?", (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),))
        suspended_count = cur.fetchone()['cnt'] or 0

        cur.execute("SELECT severity, COUNT(*) as cnt FROM anomalies GROUP BY severity;")
        sev_rows = cur.fetchall()
        severity_counts = {r['severity'] or 'unknown': r['cnt'] for r in sev_rows}

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

@app.route('/user_management')
def user_management():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Allow only Admins to view the user management page
    if session.get('role') != "admin":
        return "Forbidden: Admins only", 403

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, suspended_until FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template('user_management.html', users=users)

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

        # hash-chain application log
        try:
            log_event(conn, user_id=uid, username=uname, action='user_resumed', details={'by': 'ui'}, ip=request.remote_addr, user_agent=request.headers.get('User-Agent'))
        except Exception:
            pass

        # 🔐 audit log
        actor = session.get("username", "anonymous")
        target = uname or str(user_id or "")
        log_audit(action="resume_user", actor=actor, target_user=target, reason="manual resume", extra={"route": "/api/users/resume"})

        conn.close()
        return jsonify({"message": "user resumed"}), 200
    except Exception as e:
        print("[api/users/resume] error:", e)
        return jsonify({"error": str(e)}), 500

# ---------------- API: delete user (remove from users table) ----------------
@app.route('/api/users/delete', methods=['POST'])
@limiter.limit("10 per minute")
def api_users_delete():
    payload = request.get_json(force=True, silent=True) or {}
    user_id = payload.get('user_id')
    username = payload.get('username')

    if not user_id and not username:
        return jsonify({"error": "provide user_id or username"}), 400

    try:
        conn = get_db_conn()
        cur = conn.cursor()

        if user_id:
            cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        else:
            cur.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        r = cur.fetchone()
        if not r:
            conn.close()
            return jsonify({"error": "user not found"}), 404

        uid = r["id"]
        uname = r["username"]

        cur.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()

        try:
            log_event(
                conn,
                user_id=uid,
                username=uname,
                action='user_deleted',
                details={'by': 'ui'},
                ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
        except Exception:
            pass

        # 🔐 audit log
        actor = session.get("username", "anonymous")
        log_audit(action="delete_user", actor=actor, target_user=uname, reason=payload.get("reason"), extra={"route": "/api/users/delete"})

        conn.close()
        return jsonify({"message": f"user '{uname}' deleted"}), 200
    except Exception as e:
        print("[api/users/delete] error:", e)
        return jsonify({"error": str(e)}), 500

# ---------------- API: flag counts per user (total anomalies ever) ----------------
@app.route('/api/users/flag_counts', methods=['POST'])
@limiter.limit("30 per minute")
def api_users_flag_counts():
    """
    Payload: { "users": ["alice", "bob", "uid-123", ...] }
    Returns: { "alice": 7, "bob": 1, "uid-123": 3, ... }
    Counts if anomalies.user_id == username OR details LIKE that username.
    """
    payload = request.get_json(force=True, silent=True) or {}
    users = payload.get('users') or []
    if not isinstance(users, list) or not users:
        return jsonify({"error": "provide non-empty 'users' array"}), 400

    users = [str(u).strip() for u in users if str(u).strip()]
    if not users:
        return jsonify({"error": "no valid users"}), 400

    counts = {}
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        for u in set(users):
            like = f'%"{u}"%'
            cur.execute("""
                SELECT COUNT(*) as cnt
                FROM anomalies
                WHERE (user_id = ?)
                   OR (details LIKE ?)
            """, (u, like))
            row = cur.fetchone()
            counts[u] = int(row['cnt'] if row else 0)
        conn.close()
        return jsonify({"status": "ok", "counts": counts}), 200
    except Exception as e:
        print("[api/users/flag_counts] error:", e)
        return jsonify({"error": str(e)}), 500

# ---------------- 🔐 API: audit list/export (admin only) ----------------

@app.route('/audit', methods=['GET'])
@limiter.limit("60 per minute")
def audit_log():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Optional filters via query params
    q_action = request.args.get('action', '').strip()
    q_actor  = request.args.get('actor', '').strip()

    clauses, params = [], []
    if q_action:
        clauses.append("action = ?")
        params.append(q_action)
    if q_actor:
        clauses.append("actor = ?")
        params.append(q_actor)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT id, action, actor, target_user, reason, ip, user_agent, extra, created_at
            FROM audit_logs
            {where}
            ORDER BY id DESC
            LIMIT 300
        """, params)
        rows = cur.fetchall()
        # convert to list of dicts
        items = []
        for r in rows:
            try:
                extra = json.loads(r['extra']) if r['extra'] else {}
            except Exception:
                extra = r['extra']
            items.append({
                "id": r['id'],
                "action": r['action'],
                "actor": r['actor'],
                "target_user": r['target_user'],
                "reason": r['reason'],
                "ip": r['ip'],
                "user_agent": r['user_agent'],
                "extra": extra,
                "created_at": r['created_at'],
            })
        conn.close()
    except Exception as e:
        print("[/audit] read error:", e)
        items = []

    return render_template('audit_log.html', items=items, q_action=q_action, q_actor=q_actor)

@app.route('/api/audit', methods=['GET'])
@limiter.limit("60 per minute")
def api_audit():
    if not session.get('logged_in'):
        return jsonify({"error": "unauthorized"}), 401

    q_action = request.args.get('action', '').strip()
    q_actor  = request.args.get('actor', '').strip()

    clauses, params = [], []
    if q_action:
        clauses.append("action = ?")
        params.append(q_action)
    if q_actor:
        clauses.append("actor = ?")
        params.append(q_actor)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT id, action, actor, target_user, reason, ip, user_agent, extra, created_at
            FROM audit_logs
            {where}
            ORDER BY id DESC
            LIMIT 500
        """, params)
        rows = cur.fetchall()
        out = []
        for r in rows:
            try:
                extra = json.loads(r['extra']) if r['extra'] else {}
            except Exception:
                extra = r['extra']
            out.append({
                "id": r['id'],
                "action": r['action'],
                "actor": r['actor'],
                "target_user": r['target_user'],
                "reason": r['reason'],
                "ip": r['ip'],
                "user_agent": r['user_agent'],
                "extra": extra,
                "created_at": r['created_at'],
            })
        conn.close()
        return jsonify({"status":"ok","items":out})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

@app.get("/api/audit/export")
def api_audit_export():
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    conn = get_db_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, created_at, action, actor, target_user, reason, ip, user_agent, extra
            FROM audit_logs
            ORDER BY created_at DESC, id DESC
        """)
        rows = cur.fetchall()
        si = StringIO()
        w = csv.writer(si)
        w.writerow(["id","created_at","action","actor","target_user","reason","ip","user_agent","extra"])
        for a in rows:
            w.writerow([
                a["id"], a["created_at"], a["action"], a["actor"], a["target_user"] or "",
                (a["reason"] or "").replace("\n"," "),
                a["ip"] or "",
                (a["user_agent"] or "").replace("\n"," "),
                a["extra"] or ""
            ])
        si.seek(0)
        return Response(
            si.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
        )
    finally:
        conn.close()

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
    USE_HTTPS = os.environ.get("USE_HTTPS", "0").lower() in ("1", "true", "yes")
    if not (FLASK_ENV == "production" and USE_HTTPS):
        return
    proto = request.headers.get('X-Forwarded-Proto', request.scheme)
    if proto != 'https':
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

# ---------------- Run ----------------
if __name__ == '__main__':
    # Ensure tables exist (incl. audit_logs)
    ensure_db_schema()
    try:
        ensure_audit_table()   # harmless if already created
    except Exception as e:
        print("[audit] ensure table error:", e)

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
    app.run(host=HOST, port=PORT, debug=debug_mode)