# rule_engine.py
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, time
from typing import Callable, Dict, List, Optional, Any, Iterable
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Response levels:
RESPONSE_LEVELS = ["soft_alert", "restrict", "suspend", "lock_account"]

@dataclass
class Response:
    user_id: str
    rule: str
    severity: str
    timestamp: datetime
    details: Dict[str, Any]

    def to_dict(self):
        return asdict(self)


class RuleEngine:
    """
    Simple rule-engine for:
      1) Access outside office hours
      2) 5 failed logins in 5 min
      3) Role violation (forbidden action by role)
      4) Rate spike detection (actions_per_min threshold)
      5) Integrity break (external check callback)

    Usage:
      engine = RuleEngine(persist_callback=maybe_db_save_fn)
      responses = engine.run(logs)
    """

    def __init__(
        self,
        office_start: time = time(8, 0),
        office_end: time = time(18, 0),
        failed_login_window: timedelta = timedelta(minutes=5),
        failed_login_threshold: int = 5,
        rate_spike_threshold: int = 50,  # actions_per_min threshold
        role_policy: Optional[Dict[str, Iterable[str]]] = None,
        integrity_check_fn: Optional[Callable[[datetime], bool]] = None,
        persist_callback: Optional[Callable[[Response], None]] = None,
    ):
        self.office_start = office_start
        self.office_end = office_end
        self.failed_login_window = failed_login_window
        self.failed_login_threshold = failed_login_threshold
        self.rate_spike_threshold = rate_spike_threshold
        # role_policy: map role -> allowed actions (if omitted, default basic)
        self.role_policy = role_policy or {
            "auditor": ("view", "audit", "export"),
            "user": ("view", "create", "update"),
            "admin": ("view", "create", "update", "delete", "verify"),
        }
        # integrity_check_fn should accept a datetime (or None) and return True if integrity ok, False if broken.
        self.integrity_check_fn = integrity_check_fn
        # persist_callback: function(Response) -> None to save to DB
        self.persist_callback = persist_callback

    def run(self, logs: List[Dict[str, Any]]) -> List[Response]:
        """
        Run all rules over the incoming `logs` sequence (list of dicts).
        Each log dict should contain at least: user_id, role, action, timestamp, event, actions_per_min (optional).
        """
        responses: List[Response] = []

        # normalize timestamps to datetime & sort by time
        normalized = []
        for r in logs:
            rec = dict(r)
            ts = rec.get("timestamp")
            if isinstance(ts, str):
                try:
                    rec["timestamp"] = datetime.fromisoformat(ts)
                except Exception:
                    rec["timestamp"] = datetime.utcnow()
            if rec.get("timestamp") is None:
                rec["timestamp"] = datetime.utcnow()
            normalized.append(rec)
        normalized.sort(key=lambda x: x["timestamp"])

        # Run each rule
        responses.extend(self._rule_out_of_hours(normalized))
        responses.extend(self._rule_failed_logins(normalized))
        responses.extend(self._rule_role_violation(normalized))
        responses.extend(self._rule_rate_spike(normalized))
        responses.extend(self._rule_integrity_break(normalized))

        # persist responses if desired
        for resp in responses:
            if self.persist_callback:
                try:
                    self.persist_callback(resp)
                except Exception as e:
                    logger.exception("persist_callback failed: %s", e)
            else:
                # default: log to STDOUT
                logger.info("Response: %s", resp.to_dict())

        return responses

    # ---------- rules implementations ----------

    def _rule_out_of_hours(self, logs: List[Dict[str, Any]]) -> List[Response]:
        out: List[Response] = []
        for rec in logs:
            if rec.get("event") != "login":
                continue
            ts: datetime = rec["timestamp"]
            t = ts.time()
            if not (self.office_start <= t <= self.office_end):
                # outside office hours -> soft alert
                resp = Response(
                    user_id=str(rec.get("user_id")),
                    rule="access_outside_office_hours",
                    severity="soft_alert",
                    timestamp=datetime.utcnow(),
                    details={"when": ts.isoformat(), "action": rec.get("action")},
                )
                out.append(resp)
        return out

    def _rule_failed_logins(self, logs: List[Dict[str, Any]]) -> List[Response]:
        out: List[Response] = []
        # collect failed login timestamps per user
        failed_by_user: Dict[str, List[datetime]] = {}
        for rec in logs:
            if rec.get("event") == "failed_login":
                uid = str(rec.get("user_id"))
                failed_by_user.setdefault(uid, []).append(rec["timestamp"])

        for uid, times in failed_by_user.items():
            times.sort()
            # sliding window: count how many in any failed_login_window
            i = 0
            for j in range(len(times)):
                # advance i while window exceeded
                while times[j] - times[i] > self.failed_login_window:
                    i += 1
                count = j - i + 1
                if count >= self.failed_login_threshold:
                    # escalate severity based on count: soft_alert -> restrict -> suspend -> lock
                    level_index = min((count - self.failed_login_threshold) // 1 + 1, len(RESPONSE_LEVELS) - 1)
                    severity = RESPONSE_LEVELS[level_index]  # e.g. restrict or suspend
                    resp = Response(
                        user_id=uid,
                        rule="failed_logins_rate",
                        severity=severity,
                        timestamp=datetime.utcnow(),
                        details={"window_minutes": self.failed_login_window.total_seconds() / 60.0, "count": count},
                    )
                    out.append(resp)
                    # once triggered for this window, skip overlapping subsequent triggers for same user (break)
                    break
        return out

    def _rule_role_violation(self, logs: List[Dict[str, Any]]) -> List[Response]:
        out: List[Response] = []
        for rec in logs:
            role = rec.get("role")
            action = rec.get("action")
            uid = str(rec.get("user_id"))
            allowed = self.role_policy.get(role, ())
            if action and (action not in allowed):
                # role violation -> restrict (or soft_alert if minor)
                severity = "restrict" if role != "admin" else "suspend"
                resp = Response(
                    user_id=uid,
                    rule="role_violation",
                    severity=severity,
                    timestamp=datetime.utcnow(),
                    details={"role": role, "action": action},
                )
                out.append(resp)
        return out

    def _rule_rate_spike(self, logs: List[Dict[str, Any]]) -> List[Response]:
        out: List[Response] = []
        for rec in logs:
            apm = rec.get("actions_per_min") or 0
            uid = str(rec.get("user_id"))
            if apm >= self.rate_spike_threshold:
                severity = "restrict" if apm < (self.rate_spike_threshold * 2) else "suspend"
                resp = Response(
                    user_id=uid,
                    rule="rate_spike",
                    severity=severity,
                    timestamp=datetime.utcnow(),
                    details={"actions_per_min": apm},
                )
                out.append(resp)
        return out

    def _rule_integrity_break(self, logs: List[Dict[str, Any]]) -> List[Response]:
        out: List[Response] = []
        # if an integrity_check_fn is provided, call it (pass None or date from logs)
        if self.integrity_check_fn is None:
            return out
        try:
            # call the function and expect a boolean (False means integrity broken)
            ok = self.integrity_check_fn()
        except TypeError:
            # maybe the function expects a date; pass None
            try:
                ok = self.integrity_check_fn(None)
            except Exception as e:
                logger.exception("integrity_check_fn failed: %s", e)
                ok = True
        except Exception as e:
            logger.exception("integrity_check_fn failed: %s", e)
            ok = True

        if not ok:
            # integrity break -> escalate to suspend/lock depending on your policy
            resp = Response(
                user_id="system",
                rule="integrity_break",
                severity="suspend",
                timestamp=datetime.utcnow(),
                details={"msg": "Log integrity check failed"},
            )
            out.append(resp)
        return out


# ---------- Example persist callback (SQLAlchemy) ----------
def make_sqlalchemy_persist_fn(db_session_factory, ResponseModel):
    """
    Helper: returns a persist_callback that will persist the Response into DB.
    db_session_factory: callable -> Session
    ResponseModel: SQLAlchemy model class with columns: id, user_id, rule, severity, timestamp, details (JSON/text)
    """
    import json
    def persist(resp: Response):
        session = db_session_factory()
        try:
            row = ResponseModel(
                user_id=str(resp.user_id),
                rule=resp.rule,
                severity=resp.severity,
                timestamp=resp.timestamp,
                details=json.dumps(resp.details, default=str, ensure_ascii=False)
            )
            session.add(row)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return persist


# ----------------- Test harness -----------------
if __name__ == "__main__":
    # Sample logs (you can replace this with import from test_logs.py)
    from datetime import datetime, timedelta

    def sample_logs():
        return [
            {'user_id': 'U01', 'role': 'user', 'action': 'view',
             'timestamp': datetime(2025, 10, 18, 23, 30),
             'event': 'login', 'actions_per_min': 10},

            # failed logins for U02 (5 within 5 minutes)
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

            # role violation - auditor performing delete
            {'user_id': 'U03', 'role': 'auditor', 'action': 'delete',
             'timestamp': datetime.now(), 'event': 'action', 'actions_per_min': 5},

            # rate spike
            {'user_id': 'U04', 'role': 'user', 'action': 'create',
             'timestamp': datetime.now(), 'event': 'action', 'actions_per_min': 80},

            # integrity break: will be simulated below by integrity_check_fn returning False
            {'user_id': 'U05', 'role': 'admin', 'action': 'update',
             'timestamp': datetime.now(), 'event': 'verify', 'actions_per_min': 10}
        ]

    # Example integrity function (simulate break)
    def fake_integrity_check():
        # return False to indicate broken integrity
        return False

    engine = RuleEngine(
        integrity_check_fn=fake_integrity_check,
        rate_spike_threshold=50
    )

    out = engine.run(sample_logs())
    print("--- DETECTIONS ---")
    for r in out:
        print(r.to_dict())