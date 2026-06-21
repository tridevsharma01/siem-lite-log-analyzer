import csv
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class LogEvent:
    timestamp: float
    source: str
    event_type: str
    user: str
    src_ip: Optional[str]
    host: Optional[str]
    raw: str


_WIN_EVENT_MAP = {
    "4624": "LOGIN_SUCCESS",
    "4625": "LOGIN_FAILURE",
    "4672": "PRIV_ESCALATION",
    "4720": "ACCOUNT_CHANGE",
    "4738": "ACCOUNT_CHANGE",
    "4648": "EXPLICIT_CREDS",
}

_WIN_USER_RE = re.compile(r"Account Name:\s*([^\r\n]+)")
_WIN_IP_RE = re.compile(r"Source Network Address:\s*([0-9a-fA-F\.:]+)")


def parse_windows_security_csv(path):
    events = []
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = str(row.get("Id", "")).strip()
            event_type = _WIN_EVENT_MAP.get(event_id)
            if not event_type:
                continue

            message = row.get("Message", "") or ""
            user_match = _WIN_USER_RE.search(message)
            ip_match = _WIN_IP_RE.search(message)
            user = user_match.group(1).strip() if user_match else "unknown"
            src_ip = ip_match.group(1).strip() if ip_match else None
            if src_ip in ("-", "::1", "127.0.0.1"):
                src_ip = None

            ts = _parse_windows_timestamp(row.get("TimeCreated", ""))

            events.append(LogEvent(
                timestamp=ts, source="windows", event_type=event_type,
                user=user, src_ip=src_ip, host=None, raw=message[:300],
            ))
    return events


def _parse_windows_timestamp(value):
    if not value:
        return time.time()
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).timestamp()
        except ValueError:
            continue
    return time.time()


_LINUX_LINE_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[\d+\])?:\s+(?P<msg>.*)$'
)
_LINUX_FAIL_RE = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)')
_LINUX_SUCCESS_RE = re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>[\d\.]+)')
_LINUX_SUDO_RE = re.compile(r'^(?P<user>\S+)\s*:\s*TTY=')


def parse_linux_auth_log(path, assumed_year=None):
    assumed_year = assumed_year or datetime.now().year
    events = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = _LINUX_LINE_RE.match(line.strip())
            if not m:
                continue

            host = m.group("host")
            msg = m.group("msg")
            ts = _parse_linux_timestamp(m.group("month"), m.group("day"), m.group("time"), assumed_year)

            fail = _LINUX_FAIL_RE.search(msg)
            success = _LINUX_SUCCESS_RE.search(msg)
            sudo = _LINUX_SUDO_RE.search(msg)

            if fail:
                events.append(LogEvent(ts, "linux", "LOGIN_FAILURE", fail.group("user"),
                                        fail.group("ip"), host, line.strip()[:300]))
            elif success:
                events.append(LogEvent(ts, "linux", "LOGIN_SUCCESS", success.group("user"),
                                        success.group("ip"), host, line.strip()[:300]))
            elif sudo:
                events.append(LogEvent(ts, "linux", "SUDO", sudo.group("user"),
                                        None, host, line.strip()[:300]))
    return events


def _parse_linux_timestamp(month, day, time_str, year):
    try:
        dt = datetime.strptime(f"{month} {day} {year} {time_str}", "%b %d %Y %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return time.time()