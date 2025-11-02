# detector.py
import psutil
import time
import json
import os
from pathlib import Path
import threading
import requests  # make sure requests is installed

# --- Configuration (can be overridden by env vars) ---
BASE_DIR = Path(__file__).resolve().parent
METRICS_FILE = os.getenv("METRICS_FILE", str(BASE_DIR / "metrics.json"))
MONITORING_INTERVAL = int(os.getenv("MONITORING_INTERVAL", "5"))  # seconds
SPIKE_THRESHOLD = float(os.getenv("SPIKE_THRESHOLD", "60"))      # percent
BACKEND_ALERT_URL = os.getenv("BACKEND_ALERT_URL")                # e.g. http://127.0.0.1:8000/api/alerts
REQUEST_TIMEOUT = float(os.getenv("ALERT_REQUEST_TIMEOUT", "2"))  # seconds

# --- CORE FUNCTIONS ---

def get_os_metrics():
    """
    Collects real-time CPU and Memory usage using psutil.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=1)  # blocks 1s to compute
        mem_info = psutil.virtual_memory()
        mem_percent = mem_info.percent

        return {
            "timestamp": time.time(),
            "cpu_usage": round(cpu_percent, 1),
            "mem_usage": round(mem_percent, 1),
            "is_spike": False,  # default
        }
    except Exception as e:
        print(f"[detector] Error collecting metrics: {e}")
        return None

def _post_alert_thread(payload):
    """
    Worker thread to POST alert without blocking main loop.
    """
    try:
        # POST with small timeout to avoid blocking
        requests.post(BACKEND_ALERT_URL, json=payload, timeout=REQUEST_TIMEOUT)
        # optional: you can print status if needed
        # print(f"[detector] alert posted to backend")
    except Exception as e:
        # don't crash main loop for network errors
        print(f"[detector] Warning: failed to post alert: {e}")

def post_alert(metrics):
    """
    Trigger a non-blocking POST to BACKEND_ALERT_URL with the metrics payload.
    """
    if not BACKEND_ALERT_URL:
        # Backend URL not configured, silently skip
        return
    payload = {
        "source": "detector",
        "severity": "high",
        "metric": metrics,
        "timestamp": metrics.get("timestamp"),
    }
    t = threading.Thread(target=_post_alert_thread, args=(payload,), daemon=True)
    t.start()

def check_for_spikes(metrics):
    """
    Implements a simple rule-based check for a Rate Spike anomaly.
    If a new spike is detected (is_spike was previously False), post to backend.
    """
    if not metrics:
        return metrics

    cpu = metrics.get("cpu_usage", 0)
    already_spike = bool(metrics.get("is_spike", False))

    if cpu >= SPIKE_THRESHOLD:
        metrics["is_spike"] = True
        # If this is a newly detected spike, notify backend
        if not already_spike:
            post_alert(metrics)
        print(f"\n!!! ALERT: Rate Spike Detected! CPU at {metrics['cpu_usage']}% !!!\n")
    else:
        metrics["is_spike"] = False

    return metrics

def save_current_metrics(metrics):
    """
    Atomically saves the latest metrics to METRICS_FILE.
    Uses a temp file + rename to avoid partial writes.
    """
    if not metrics:
        return
    try:
        p = Path(METRICS_FILE)
        tmp = p.with_suffix(".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w") as f:
            json.dump(metrics, f, indent=4)
        tmp.replace(p)  # atomic on most OSes
        print(f"[{time.strftime('%H:%M:%S')}] Saved: CPU {metrics['cpu_usage']}%, MEM {metrics['mem_usage']}%")
    except Exception as e:
        print(f"[detector] Error saving data to JSON file: {e}")

def daemon_loop():
    """
    The main monitoring loop that runs continuously.
    Gracefully stops on KeyboardInterrupt.
    """
    print(f"--- Sentinel OS Daemon Starting ---")
    print(f"Monitoring system every {MONITORING_INTERVAL} seconds... (threshold={SPIKE_THRESHOLD}%)")
    try:
        while True:
            current_metrics = get_os_metrics()
            if current_metrics:
                current_metrics = check_for_spikes(current_metrics)
                save_current_metrics(current_metrics)
            time.sleep(MONITORING_INTERVAL)
    except KeyboardInterrupt:
        print("\n[detector] Stopped by user (KeyboardInterrupt). Exiting.")
    except Exception as e:
        print(f"[detector] Unexpected error: {e}")
    finally:
        print("[detector] Daemon exiting.")

# --- EXECUTION ---
if __name__ == "__main__":
    daemon_loop()