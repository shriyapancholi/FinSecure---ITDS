# desktop_boot.py — SAFE desktop launcher for Flask backend

import os, sys, time, tempfile, requests, threading, traceback

PORT       = int(os.environ.get("PORT", "5501"))
BASE_URL   = f"http://127.0.0.1:{PORT}"
HEALTH_URL = f"{BASE_URL}/_health"
LOGIN_URL  = f"{BASE_URL}/login"
ONLINE_URL = os.environ.get("FINSECURE_ONLINE_URL", "").strip()
WAIT_SECS  = 18.0
PROBE_EVERY= 0.30

# ✅ Lock file so only 1 instance runs
LOCK_FILE = os.path.join(tempfile.gettempdir(), "finsecure.run.lock")

# ✅ Create log folder for backend errors
LOG_DIR  = os.path.join(os.path.expanduser("~"), "Library", "Logs", "FinSecure")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "backend.log")


def log_backend_error(msg: str):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"\n[{time.ctime()}] {msg}\n")
    except:
        pass


def already_running():
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, "r") as f:
                pid = int(f.read().strip() or "0")
            os.kill(pid, 0)
            return True
        except Exception:
            pass
    try:
        with open(LOCK_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass
    return False


def port_open(port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except Exception:
            return False


def run_backend_thread():
    """
    Import and start Flask backend from inside the .app bundle safely.
    """
    try:
        os.environ["DESKTOP_EMBEDDED"] = "1"
        os.environ["PORT"] = str(PORT)

        import importlib.util

        BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        candidates = [
            os.path.join(BASE_DIR, "app.py"),
            os.path.join(BASE_DIR, "app", "__init__.py"),
        ]
        backend_path = next((p for p in candidates if os.path.exists(p)), None)

        if not backend_path:
            log_backend_error(f"app.py not found. Tried: {candidates}")
            return

        spec = importlib.util.spec_from_file_location("finsecure_backend", backend_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        flask_app = getattr(mod, "app", None)
        if not flask_app:
            log_backend_error("Flask app object not found inside backend file.")
            return

        flask_app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False)

    except Exception as e:
        log_backend_error("Backend crashed:\n" + traceback.format_exc())


def start_backend():
    if port_open(PORT):
        return
    t = threading.Thread(target=run_backend_thread, daemon=True)
    t.start()


def wait_healthy(url, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(url, timeout=1.2)
            if 200 <= r.status_code < 400:
                return True
        except Exception:
            pass
        time.sleep(PROBE_EVERY)
    return False


def open_window(url=None, html=None):
    import webview

    if url:
        webview.create_window("FinSecure ITDS", url, width=1200, height=800)
    else:
        msg = html or (
            "<div style='font-family:system-ui;margin:40px;text-align:center'>"
            "<h2>Backend did not start</h2>"
            "<p>See logs at:<br>"
            f"<code>{LOG_FILE}</code></p>"
            "<p>Try running once from Terminal:<br><code>python app.py</code></p>"
            "</div>"
        )
        webview.create_window("FinSecure ITDS", html=msg, width=800, height=520)

    webview.start()


def main():
    # ✅ Prevent infinite loops (only one instance)
    if already_running():
        sys.exit(0)

    # ✅ If online backend configured & healthy → open it
    if ONLINE_URL:
        try:
            r = requests.get(ONLINE_URL, timeout=2)
            if 200 <= r.status_code < 400:
                return open_window(ONLINE_URL)
        except Exception:
            pass

    # ✅ Start local backend
    start_backend()

    # ✅ Wait until backend responds
    if not wait_healthy(HEALTH_URL, WAIT_SECS):
        return open_window()

    # ✅ Backend is ready → open login
    return open_window(LOGIN_URL)


if __name__ == "__main__":
    try:
        main()
    finally:
        # ✅ always clean lock file
        try: os.remove(LOCK_FILE)
        except Exception: pass