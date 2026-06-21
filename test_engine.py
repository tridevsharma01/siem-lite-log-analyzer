from parsers import LogEvent
from engine import (
    Engine, BruteForceRule, SuccessAfterFailuresRule, PrivilegeEscalationRule,
    AccountChangeRule, LateralMovementRule, AfterHoursLoginRule,
)


def check(name, alerts, expected_min, substr=None):
    ok = len(alerts) >= expected_min
    if substr and ok:
        ok = any(substr.lower() in a.message.lower() for a in alerts)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}  (alerts: {len(alerts)})")
    for a in alerts:
        print(f"          -> {a.severity:<8} {a.message}")
    return ok


def main():
    all_ok = True
    t0 = 1_700_000_000.0

    rule = BruteForceRule(count=5, seconds=120)
    alerts = []
    for i in range(5):
        e = LogEvent(t0 + i * 5, "linux", "LOGIN_FAILURE", "root", "203.0.113.5", "srv1", "raw")
        a = rule.process(e)
        if a:
            alerts.append(a)
    all_ok &= check("Brute force (5 failures/120s)", alerts, 1, "brute-force")

    rule2 = BruteForceRule(count=5, seconds=120)
    alerts2 = []
    for i in range(3):
        e = LogEvent(t0 + i * 5, "linux", "LOGIN_FAILURE", "root", "203.0.113.6", "srv1", "raw")
        a = rule2.process(e)
        if a:
            alerts2.append(a)
    ok = len(alerts2) == 0
    print(f"[{'PASS' if ok else 'FAIL'}] Below threshold stays silent  (alerts: {len(alerts2)})")
    all_ok &= ok

    rule3 = SuccessAfterFailuresRule(min_failures=3, seconds=300)
    alerts3 = []
    for i in range(4):
        e = LogEvent(t0 + i * 2, "linux", "LOGIN_FAILURE", "alice", "198.51.100.9", "srv2", "raw")
        a = rule3.process(e)
        if a:
            alerts3.append(a)
    e_success = LogEvent(t0 + 20, "linux", "LOGIN_SUCCESS", "alice", "198.51.100.9", "srv2", "raw")
    a = rule3.process(e_success)
    if a:
        alerts3.append(a)
    all_ok &= check("Login success after brute force", alerts3, 1, "after")

    rule4 = PrivilegeEscalationRule()
    e = LogEvent(t0, "windows", "PRIV_ESCALATION", "jdoe", None, "WIN-SRV1", "raw")
    alerts4 = [a for a in [rule4.process(e)] if a]
    all_ok &= check("Privilege escalation", alerts4, 1, "privileges")

    rule5 = AccountChangeRule()
    e = LogEvent(t0, "windows", "ACCOUNT_CHANGE", "newuser1", None, "WIN-SRV1", "raw")
    alerts5 = [a for a in [rule5.process(e)] if a]
    all_ok &= check("Account creation/change", alerts5, 1, "account")

    rule6 = LateralMovementRule(min_targets=3, seconds=600)
    alerts6 = []
    for i, host in enumerate(["HOST-A", "HOST-B", "HOST-C", "HOST-D"]):
        e = LogEvent(t0 + i * 30, "windows", "LOGIN_SUCCESS", "svc_admin", None, host, "raw")
        a = rule6.process(e)
        if a:
            alerts6.append(a)
    all_ok &= check("Lateral movement (4 hosts/600s)", alerts6, 1, "distinct hosts")

    rule7 = AfterHoursLoginRule(start_hour=8, end_hour=20)
    import time
    late_night = time.mktime(time.localtime(t0)[:3] + (2, 30, 0, 0, 0, 0))
    e = LogEvent(late_night, "linux", "LOGIN_SUCCESS", "bob", "10.0.0.5", "srv3", "raw")
    alerts7 = [a for a in [rule7.process(e)] if a]
    all_ok &= check("After-hours login", alerts7, 1, "business hours")

    engine = Engine()
    events = [
        LogEvent(t0 + i, "linux", "LOGIN_FAILURE", "admin", "192.0.2.50", "srv1", "raw")
        for i in range(6)
    ]
    fired = engine.process_all(events)
    ok = len(fired) >= 1
    print(f"[{'PASS' if ok else 'FAIL'}] Full Engine integration  (alerts: {len(fired)})")
    all_ok &= ok

    print("\n" + ("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())