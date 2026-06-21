import argparse
import sys

from parsers import parse_windows_security_csv, parse_linux_auth_log
from engine import Engine
from alert_log import AlertLogger


def main():
    ap = argparse.ArgumentParser(description="SIEM-lite log analyzer")
    ap.add_argument("--windows", help="Path to a Windows Security Event Log CSV export")
    ap.add_argument("--linux", help="Path to a Linux auth.log file")
    ap.add_argument("--log", default="siem_alerts.log", help="Path to write the alert log")
    args = ap.parse_args()

    if not args.windows and not args.linux:
        print("Provide at least one log source: --windows <file.csv> and/or --linux <auth.log>")
        sys.exit(1)

    events = []
    if args.windows:
        try:
            win_events = parse_windows_security_csv(args.windows)
            print(f"Parsed {len(win_events)} events from {args.windows}")
            events += win_events
        except FileNotFoundError:
            print(f"File not found: {args.windows}")
            sys.exit(1)

    if args.linux:
        try:
            linux_events = parse_linux_auth_log(args.linux)
            print(f"Parsed {len(linux_events)} events from {args.linux}")
            events += linux_events
        except FileNotFoundError:
            print(f"File not found: {args.linux}")
            sys.exit(1)

    if not events:
        print("No recognizable events found in the provided log(s).")
        sys.exit(0)

    print(f"\nTotal events: {len(events)}")
    print(f"Running detection engine...\n")

    logger = AlertLogger(log_path=args.log)
    engine = Engine(on_alert=logger.handle)
    alerts = engine.process_all(events)

    print(f"\n{'=' * 60}")
    print(f"Total alerts fired: {len(alerts)}  (logged to {args.log})")
    print("Run 'python dashboard.py' to visualize these results.")


if __name__ == "__main__":
    main()