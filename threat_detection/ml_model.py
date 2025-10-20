# threat_detection/ml_model.py
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.joblib")

def synth_features(n=2000, random_state=42):
    rng = np.random.RandomState(random_state)
    # features: actions_per_min, txn_amount, ip_entropy, cpu_z, mem_z
    actions = rng.poisson(5, size=n).astype(float)
    txn = rng.normal(50, 20, size=n).clip(0)
    ip_entropy = rng.normal(1.0, 0.3, size=n).clip(0, 5)
    cpu_z = rng.normal(0, 1, size=n)
    mem_z = rng.normal(0, 1, size=n)
    df = pd.DataFrame({
        "actions_per_min": actions,
        "txn_amount": txn,
        "ip_entropy": ip_entropy,
        "cpu_z": cpu_z,
        "mem_z": mem_z,
    })
    return df

def train_and_save(path=MODEL_PATH):
    df = synth_features()
    model = IsolationForest(n_estimators=200, contamination=0.01, random_state=1)
    model.fit(df.values)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump({"model": model, "columns": df.columns.tolist()}, path)
    print("Model saved to", path)

if __name__ == "__main__":
    train_and_save()