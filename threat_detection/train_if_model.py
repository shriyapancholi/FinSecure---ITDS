# threat_detection/train_if_model.py
"""
Generate synthetic normal data and train the IsolationForest.
Run: python -m threat_detection.train_if_model
"""
import numpy as np
import pandas as pd
from .ml_model import train_and_save_isolation_forest, df_from_records

def generate_synthetic_normal(n=2000):
    # actions_per_min: most users low
    actions_per_min = np.clip(np.random.normal(3, 2, size=n), 0, 100)
    txn_amount = np.clip(np.random.normal(50, 20, size=n), 0, 10000)
    ip_entropy = np.clip(np.random.normal(1.5, 0.5, size=n), 0, 8)
    cpu_z = np.clip(np.random.normal(0, 0.7, size=n), -5, 5)
    mem_z = np.clip(np.random.normal(0, 0.7, size=n), -5, 5)

    rows = []
    for i in range(n):
        rows.append({
            "actions_per_min": float(actions_per_min[i]),
            "txn_amount": float(txn_amount[i]),
            "ip_entropy": float(ip_entropy[i]),
            "cpu_z": float(cpu_z[i]),
            "mem_z": float(mem_z[i]),
        })
    return rows

def main():
    rows = generate_synthetic_normal(2000)
    df = df_from_records(rows)
    model = train_and_save_isolation_forest(df, n_estimators=200, contamination=0.01)
    print("Trained and saved IsolationForest model.")

if __name__ == "__main__":
    main()