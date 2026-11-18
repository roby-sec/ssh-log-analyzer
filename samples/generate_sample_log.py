#!/usr/bin/env python3
"""Generate a SYNTHETIC auth.log with known attack patterns.

All IPs come from the documentation ranges (RFC 5737), so nothing here
belongs to a real system. Seeded, so the output is reproducible.
"""
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
HOST = "web01"
DAY = datetime(2026, 11, 14)
rows = []  # (datetime, line)


def stamp(t):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def add(t, msg, proc="sshd"):
    pid = random.randint(1000, 9999)
    rows.append((t, f"{stamp(t)} {HOST} {proc}[{pid}]: {msg}"))


def failed(t, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    add(t, f"Failed password for {prefix}{user} from {ip} port {random.randint(30000, 65000)} ssh2")


def accepted(t, user, ip):
    add(t, f"Accepted password for {user} from {ip} port {random.randint(30000, 65000)} ssh2")


# 1) Normal activity: legitimate admins, one mistyped password
for h, user, ip in [(8, "roby", "198.51.100.7"), (9, "deploy", "198.51.100.20"),
                    (14, "roby", "198.51.100.7"), (17, "deploy", "198.51.100.20")]:
    t = DAY + timedelta(hours=h, minutes=random.randint(0, 50))
    if user == "roby" and h == 8:
        failed(t, user, ip)
        t += timedelta(seconds=9)
    accepted(t, user, ip)

# 2) Classic brute force: 60 attempts in ~8 minutes against root/admin
t0 = DAY + timedelta(hours=3, minutes=12)
for i in range(60):
    user = random.choice(["root", "admin", "ubuntu"])
    failed(t0 + timedelta(seconds=i * 8), user, "203.0.113.45", invalid=user != "root")

# 3) Password spraying: many usernames, few tries each
names = ["test", "oracle", "postgres", "git", "user", "guest", "pi", "ftp", "nagios", "jenkins"]
t0 = DAY + timedelta(hours=11, minutes=40)
for i, name in enumerate(names):
    for j in range(2):
        failed(t0 + timedelta(seconds=i * 20 + j * 5), name, "203.0.113.99", invalid=True)

# 4) Compromise: failures against a real account, then a successful login
t0 = DAY + timedelta(hours=22, minutes=5)
for i in range(12):
    failed(t0 + timedelta(seconds=i * 12), "deploy", "192.0.2.77")
accepted(t0 + timedelta(seconds=12 * 12 + 4), "deploy", "192.0.2.77")

# 5) Noise the parser must ignore
for h in (2, 6, 13, 19):
    t = DAY + timedelta(hours=h, minutes=1)
    add(t, "(root) CMD (/usr/local/bin/backup.sh)", proc="CRON")
    add(t + timedelta(seconds=30), "pam_unix(sudo:session): session opened for user root", proc="sudo")

rows.sort(key=lambda r: r[0])
out = Path(__file__).with_name("auth_sample.log")
out.write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")
print(f"wrote {len(rows)} lines to {out}")
