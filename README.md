# siem-lite-log-analyzer
A lightweight SIEM-style log analysis tool built in Python. Parses Windows Security Event Logs and Linux auth.log files, correlates events using a custom rule-based detection engine (brute force , credential compromise , privilrge escalation , lateral movement, after-hours logins) , and visualizes result on a dashboard . Fully unit-tested.
# SIEM-Lite: Log Analysis & Detection Dashboard (Python)

A lightweight SIEM-style log analysis tool that parses *Windows Security Event Logs* (exported to CSV) and *Linux auth.log* files, correlates events using a rule-based detection engine, and visualizes findings on a dashboard.

Built as the same proven architecture as a network IDS project: parser → detection engine → alert logging → dashboard, with everything unit-tested against synthetic data before touching real logs.

## What's in this repo

| File | Description |
|------|--------------|
| parsers.py | Normalizes Windows Security Event CSV exports and Linux auth.log into a common event format |
| engine.py | Correlation engine — 6 detection rules: brute force, compromised-credential pattern, privilege escalation, account changes, lateral movement, after-hours logins |
| alert_log.py | Console output + JSON-lines alert logging |
| analyze_logs.py | Main entry point — run this against real log files |
| generate_demo_logs.py | Generates realistic synthetic logs with 6 embedded attack scenarios, for testing/demo without real logs |
| dashboard.py | Visualizes the alert log as a 4-panel PNG dashboard |
| test_engine.py | Unit tests verifying every detection rule fires correctly |

## Detection rules

| Rule | Severity | What it catches |
|------|----------|------------------|
| Brute Force | High | N login failures from the same source within a time window |
| Login After Brute Force | Critical | A successful login immediately following a burst of failures — classic compromised-credential pattern |
| Privilege Escalation | Medium | Admin/special privileges assigned to an account |
| Account Change | Medium | New user accounts created or existing accounts modified |
| Lateral Movement | High | The same account authenticating to multiple distinct hosts/IPs in a short window |
| After-Hours Login | Low | Successful logins outside configured business hours |

## How to run it

```bash
pip install matplotlib
python test_engine.py
python generate_demo_logs.py
python analyze_logs.py --windows sample_security_log.csv --linux sample_auth.log
python dashboard.py
