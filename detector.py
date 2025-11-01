import psutil
import time
import json
import os

# --- Configuration ---
MONITORING_INTERVAL = 5    # Check every 5 seconds (Scheduled Check)
METRICS_FILE = 'metrics.json' # File where the data bridge lives
SPIKE_THRESHOLD = 60       # CPU percentage considered a "rate spike"

# --- CORE FUNCTIONS ---

def get_os_metrics():
    """
    Collects real-time CPU and Memory usage using the psutil library.
    """
    try:
        # psutil.cpu_percent(interval=1) waits 1 second to calculate the percentage
        cpu_percent = psutil.cpu_percent(interval=1)
        mem_info = psutil.virtual_memory()
        mem_percent = mem_info.percent
        
        return {
            'timestamp': time.time(),
            'cpu_usage': round(cpu_percent, 1),
            'mem_usage': round(mem_percent, 1),
            'is_spike': False # Default status
        }
    except Exception as e:
        print(f"Error collecting metrics: {e}")
        return None

def check_for_spikes(metrics):
    """
    Implements a simple rule-based check for a Rate Spike anomaly.
    """
    if metrics and metrics['cpu_usage'] >= SPIKE_THRESHOLD:
        metrics['is_spike'] = True
        # Print a warning to the console
        print(f"\n!!! ALERT: Rate Spike Detected! CPU at {metrics['cpu_usage']}% !!!\n")
    return metrics

def save_current_metrics(metrics):
    """
    Saves the latest metrics to a simple JSON file (the data bridge).
    """
    if metrics:
        try:
            # Writing 'w' mode overwrites the file with the latest data
            with open(METRICS_FILE, 'w') as f:
                json.dump(metrics, f, indent=4)
            print(f"[{time.strftime('%H:%M:%S')}] Saved: CPU {metrics['cpu_usage']}%, MEM {metrics['mem_usage']}%")
        except Exception as e:
            print(f"Error saving data to JSON file: {e}")

def daemon_loop():
    """
    The main monitoring loop that runs continuously.
    """
    print(f"--- Sentinel OS Daemon Starting ---")
    print(f"Monitoring system every {MONITORING_INTERVAL} seconds...")

    while True:
        # 1. Collect raw metrics
        current_metrics = get_os_metrics()
        
        if current_metrics:
            # 2. Run simple anomaly detection
            current_metrics = check_for_spikes(current_metrics)
            
            # 3. Save the results (Data Bridge)
            save_current_metrics(current_metrics)

        # 4. Wait for the next scheduled check
        time.sleep(MONITORING_INTERVAL)

# --- EXECUTION ---
if __name__ == '__main__':
    daemon_loop()