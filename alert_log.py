import json
import time

ANSI = {
    "Low": "\033[37m", "Medium": "\033[33m", "High": "\033[31m",
    "Critical": "\033[1;31m", "reset": "\033[0m",
}


class AlertLogger:
    def __init__(self, log_path="siem_alerts.log"):
        self.log_path = log_path

    def handle(self, alert):
        self._print(alert)
        self._log(alert)

    def _print(self, alert):
        color = ANSI.get(alert.severity, "")
        reset = ANSI["reset"]
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert.timestamp))
        print(f"{color}[{ts}] [{alert.severity.upper():<8}] {alert.rule_name}: {alert.message}{reset}")
        if alert.detail:
            print(f"           {alert.detail}")

    def _log(self, alert):
        with open(self.log_path, "a") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")