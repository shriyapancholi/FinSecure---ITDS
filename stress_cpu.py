# stress_cpu.py
# Simple CPU load generator. Stop with Ctrl+C.
import multiprocessing as mp
import time
import math
import argparse
import sys

def busy_worker(duration):
    """Each worker burns CPU for <duration> seconds."""
    end_time = time.time() + duration
    x = 0.0001
    while time.time() < end_time:
        x = x * math.sin(x + 1.2345) + 0.000001

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="Seconds to run")
    parser.add_argument("--workers", type=int, default=mp.cpu_count(), help="Number of cores to use")
    args = parser.parse_args()

    print(f"🔥 Starting CPU stress: {args.workers} workers for {args.duration} seconds")
    processes = []
    try:
        for _ in range(args.workers):
            p = mp.Process(target=busy_worker, args=(args.duration,))
            p.start()
            processes.append(p)

        for p in processes:
            p.join()

    except KeyboardInterrupt:
        print("\n🛑 Stopping stress test...")
        for p in processes:
            p.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
