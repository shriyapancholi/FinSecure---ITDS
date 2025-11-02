PRAGMA foreign_keys = ON;

-- roles (optional: simple name/permissions)
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  permissions TEXT
);

-- logs (append-only action logs)
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  details TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  prev_hash TEXT,   -- previous log entry hash
  hash TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- log_integrity (daily checkpoints)
CREATE TABLE IF NOT EXISTS log_integrity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  date TEXT UNIQUE,
  last_hash TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- anomalies (ML or rule-detected)
CREATE TABLE IF NOT EXISTS anomalies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT,
  severity TEXT,
  details TEXT,
  metric_json TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- responses (actions taken by rule-engine)
CREATE TABLE IF NOT EXISTS responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  anomaly_id INTEGER,
  action_taken TEXT,
  target_user_id INTEGER,
  details TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(anomaly_id) REFERENCES anomalies(id),
  FOREIGN KEY(target_user_id) REFERENCES users(id)
);

-- system_metrics (daemon OS metrics)
CREATE TABLE IF NOT EXISTS system_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cpu REAL,
  memory REAL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
