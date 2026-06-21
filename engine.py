import time
from collections import defaultdict, deque


class Alert:
    def __init__(self, rule_name, severity, message, event, detail=""):
        self.rule_name = rule_name
        self.severity = severity
        self.message = message
        self.timestamp = event.timestamp
        self.user = event.user
        self.src_ip = event.src_ip
        self.host = event.host
        self.source = event.source
        self.detail = detail

    def to_dict(self):
        return {
            "timestamp": self.timestamp, "rule": self.rule_name, "severity": self.severity,
            "message": self.message, "user": self.user, "src_ip": self.src_ip,
            "host": self.host, "source": self.source, "detail": self.detail,
        }


class BruteForceRule:
    name = "BRUTE_FORCE"
    severity = "High"

    def __init__(self, count=5, seconds=120):
        self.count = count
        self.seconds = seconds
        self._windows = defaultdict(deque)
        self._armed = defaultdict(lambda: True)

    def process(self, event):
        if event.event_type != "LOGIN_FAILURE":
            return None
        key = event.src_ip or event.user
        window = self._windows[key]
        window.append(event.timestamp)
        cutoff = event.timestamp - self.seconds
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.count:
            if self._armed[key]:
                self._armed[key] = False
                return Alert(self.name, self.severity,
                             f"Brute-force login attempts detected ({len(window)} failures in {self.seconds}s)",
                             event, detail=f"target={key}")
            return None
        self._armed[key] = True
        return None


class SuccessAfterFailuresRule:
    name = "LOGIN_AFTER_BRUTE_FORCE"
    severity = "Critical"

    def __init__(self, min_failures=3, seconds=300):
        self.min_failures = min_failures
        self.seconds = seconds
        self._recent_failures = defaultdict(deque)

    def process(self, event):
        key = event.user
        if event.event_type == "LOGIN_FAILURE":
            window = self._recent_failures[key]
            window.append(event.timestamp)
            cutoff = event.timestamp - self.seconds
            while window and window[0] < cutoff:
                window.popleft()
            return None

        if event.event_type == "LOGIN_SUCCESS":
            window = self._recent_failures[key]
            cutoff = event.timestamp - self.seconds
            recent = [t for t in window if t >= cutoff]
            if len(recent) >= self.min_failures:
                self._recent_failures[key].clear()
                return Alert(self.name, self.severity,
                             f"Successful login for '{key}' immediately after {len(recent)} failed attempts",
                             event, detail="possible compromised credentials")
        return None


class PrivilegeEscalationRule:
    name = "PRIVILEGE_ESCALATION"
    severity = "Medium"

    def process(self, event):
        if event.event_type == "PRIV_ESCALATION":
            return Alert(self.name, self.severity,
                         f"Special/admin privileges assigned to '{event.user}'", event)
        return None


class AccountChangeRule:
    name = "ACCOUNT_CHANGE"
    severity = "Medium"

    def process(self, event):
        if event.event_type == "ACCOUNT_CHANGE":
            return Alert(self.name, self.severity,
                         f"User account created or modified: '{event.user}'", event)
        return None


class LateralMovementRule:
    name = "LATERAL_MOVEMENT"
    severity = "High"

    def __init__(self, min_targets=3, seconds=600):
        self.min_targets = min_targets
        self.seconds = seconds
        self._targets = defaultdict(dict)
        self._armed = defaultdict(lambda: True)

    def process(self, event):
        if event.event_type not in ("LOGIN_SUCCESS", "EXPLICIT_CREDS"):
            return None
        target = event.host or event.src_ip
        if not target:
            return None

        key = event.user
        targets = self._targets[key]
        targets[target] = event.timestamp
        cutoff = event.timestamp - self.seconds
        for t in [t for t, ts in targets.items() if ts < cutoff]:
            del targets[t]

        if len(targets) >= self.min_targets:
            if self._armed[key]:
                self._armed[key] = False
                return Alert(self.name, self.severity,
                             f"User '{key}' authenticated to {len(targets)} distinct hosts/IPs in {self.seconds}s",
                             event, detail=f"targets={list(targets.keys())}")
            return None
        self._armed[key] = True
        return None


class AfterHoursLoginRule:
    name = "AFTER_HOURS_LOGIN"
    severity = "Low"

    def __init__(self, start_hour=8, end_hour=20):
        self.start_hour = start_hour
        self.end_hour = end_hour

    def process(self, event):
        if event.event_type != "LOGIN_SUCCESS":
            return None
        hour = time.localtime(event.timestamp).tm_hour
        if hour < self.start_hour or hour >= self.end_hour:
            return Alert(self.name, self.severity,
                         f"Login for '{event.user}' outside business hours ({hour:02d}:00)", event)
        return None


DEFAULT_RULES = [
    BruteForceRule(count=5, seconds=120),
    SuccessAfterFailuresRule(min_failures=3, seconds=300),
    PrivilegeEscalationRule(),
    AccountChangeRule(),
    LateralMovementRule(min_targets=3, seconds=600),
    AfterHoursLoginRule(start_hour=8, end_hour=20),
]


class Engine:
    def __init__(self, rules=None, on_alert=None):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)
        self.on_alert = on_alert

    def process_event(self, event):
        fired = []
        for rule in self.rules:
            alert = rule.process(event)
            if alert:
                fired.append(alert)
                if self.on_alert:
                    self.on_alert(alert)
        return fired

    def process_all(self, events):
        events = sorted(events, key=lambda e: e.timestamp)
        all_alerts = []
        for e in events:
            all_alerts.extend(self.process_event(e))
        return all_alerts