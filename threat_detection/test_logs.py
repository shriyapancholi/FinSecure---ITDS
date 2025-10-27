# threat_detection/test_logs.py
from datetime import datetime, timedelta

def sample_logs():
    """Generate sample logs that trigger all 5 rules."""
    return [
        {'user_id': 'U01', 'role': 'user', 'action': 'view',
         'timestamp': datetime(2025, 10, 18, 23, 30),
         'event': 'login', 'actions_per_min': 10},
        {'user_id': 'U02', 'role': 'user', 'action': 'login',
         'timestamp': datetime.now(), 'event': 'failed_login', 'actions_per_min': 2},
        {'user_id': 'U02', 'role': 'user', 'action': 'login',
         'timestamp': datetime.now() + timedelta(seconds=30), 'event': 'failed_login', 'actions_per_min': 2},
        {'user_id': 'U02', 'role': 'user', 'action': 'login',
         'timestamp': datetime.now() + timedelta(seconds=60), 'event': 'failed_login', 'actions_per_min': 2},
        {'user_id': 'U02', 'role': 'user', 'action': 'login',
         'timestamp': datetime.now() + timedelta(seconds=90), 'event': 'failed_login', 'actions_per_min': 2},
        {'user_id': 'U02', 'role': 'user', 'action': 'login',
         'timestamp': datetime.now() + timedelta(seconds=120), 'event': 'failed_login', 'actions_per_min': 2},
        {'user_id': 'U03', 'role': 'auditor', 'action': 'delete',
         'timestamp': datetime.now(), 'event': 'action', 'actions_per_min': 5},
        {'user_id': 'U04', 'role': 'user', 'action': 'create',
         'timestamp': datetime.now(), 'event': 'action', 'actions_per_min': 80},
        {'user_id': 'U05', 'role': 'admin', 'action': 'update',
         'timestamp': datetime.now(), 'event': 'verify', 'actions_per_min': 10}
    ]