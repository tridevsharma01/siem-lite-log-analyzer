import csv
from datetime import datetime, timedelta


def generate_linux_log(path="sample_auth.log", base_time=None):
    base_time = base_time or datetime.now() - timedelta(hours=5)
    lines = []

    def fmt(dt):
        return dt.strftime("%b %d %H:%M:%S")

    t = base_time
    attacker_ip = "203.0.113.50"
    for i in range(7):
        lines.append(f"{fmt(t)} webserver01 sshd[2001]: Failed password for invalid user root from {attacker_ip} port {40000+i} ssh2")
        t += timedelta(seconds=4)
    t += timedelta(minutes=2)

    t += timedelta(minutes=10)
    lines.append(f"{fmt(t)} webserver01 sshd[2050]: Accepted password for alice from 198.51.100.20 port 41000 ssh2")
    t += timedelta(seconds=30)
    lines.append(f"{fmt(t)} webserver01 sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")

    t += timedelta(minutes=15)
    victim_ip = "198.51.100.77"
    for i in range(4):
        lines.append(f"{fmt(t)} webserver01 sshd[2090]: Failed password for svc_backup from {victim_ip} port {42000+i} ssh2")
        t += timedelta(seconds=5)
    t += timedelta(seconds=10)
    lines.append(f"{fmt(t)} webserver01 sshd[2090]: Accepted password for svc_backup from {victim_ip} port 42100 ssh2")

    night = t.replace(hour=2, minute=14, second=0)
    lines.append(f"{fmt(night)} webserver01 sshd[2110]: Accepted password for jdoe from 192.0.2.30 port 43000 ssh2")

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {path}")


def generate_windows_csv(path="sample_security_log.csv", base_time=None):
    base_time = base_time or datetime.now() - timedelta(hours=4)
    rows = []
    t = base_time

    def add(event_id, user, src_ip=None, minutes_offset=0):
        nonlocal t
        t = t + timedelta(minutes=minutes_offset)
        msg_parts = []
        if event_id == "4625":
            msg_parts.append("An account failed to log on.")
        elif event_id == "4624":
            msg_parts.append("An account was successfully logged on.")
        elif event_id == "4672":
            msg_parts.append("Special privileges assigned to new logon.")
        elif event_id in ("4720", "4738"):
            msg_parts.append("A user account was created or changed.")
        elif event_id == "4648":
            msg_parts.append("A logon was attempted using explicit credentials.")
        msg_parts.append(f"\nAccount Name:\t\t{user}")
        if src_ip:
            msg_parts.append(f"Source Network Address:\t{src_ip}")
        rows.append({
            "TimeCreated": t.strftime("%m/%d/%Y %I:%M:%S %p"),
            "Id": event_id,
            "LevelDisplayName": "Information",
            "Message": "\n".join(msg_parts),
        })

    for i in range(6):
        add("4625", "svc_sql", "192.0.2.88", minutes_offset=0.05)
    add("4624", "svc_sql", "192.0.2.88", minutes_offset=0.1)
    add("4672", "svc_sql", minutes_offset=0.05)

    add("4648", "it_admin", "10.10.10.11", minutes_offset=20)
    add("4648", "it_admin", "10.10.10.12", minutes_offset=2)
    add("4648", "it_admin", "10.10.10.13", minutes_offset=2)
    add("4648", "it_admin", "10.10.10.14", minutes_offset=2)

    add("4720", "backup_svc2", minutes_offset=30)

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["TimeCreated", "Id", "LevelDisplayName", "Message"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {path}")


if __name__ == "__main__":
    generate_linux_log()
    generate_windows_csv()