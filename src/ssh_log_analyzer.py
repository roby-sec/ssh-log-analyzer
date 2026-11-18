#!/usr/bin/env python3
"""SSH log analyzer: detect brute-force and password-spraying in auth.log.

Standard library only. Reads a syslog-style SSH log, flags suspicious source
IPs and writes a Markdown report plus a CSV of the flagged IPs.

Usage:
    python src/ssh_log_analyzer.py samples/auth_sample.log --out reports/
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class Event:
    ts: datetime
    kind: str  # "failed" or "accepted"
    user: str
    ip: str
    invalid_user: bool = False


def parse_line(line: str, year: int) -> Event | None:
    """Return an Event for a failed/accepted SSH login line, else None."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        # syslog has no year and may pad the day with two spaces
        ts = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m["msg"]
    f = FAILED_RE.search(msg)
    if f:
        return Event(ts, "failed", f["user"], f["ip"], bool(f["invalid"]))
    a = ACCEPTED_RE.search(msg)
    if a:
        return Event(ts, "accepted", a["user"], a["ip"])
    return None


def parse_file(path: Path, year: int) -> list[Event]:
    events = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line, year)
            if ev:
                events.append(ev)
    return sorted(events, key=lambda e: e.ts)


def max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of timestamps falling inside any sliding window."""
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(events: list[Event], threshold: int = 5, window_minutes: int = 10,
            spray_users: int = 5) -> list[dict]:
    """Flag IPs showing brute-force, password spraying or a login after failures."""
    window = timedelta(minutes=window_minutes)
    failed_by_ip: dict[str, list[Event]] = defaultdict(list)
    accepted_by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        (failed_by_ip if ev.kind == "failed" else accepted_by_ip)[ev.ip].append(ev)

    findings = []
    for ip, fails in failed_by_ip.items():
        times = [e.ts for e in fails]
        peak = max_in_window(times, window)
        users = {e.user for e in fails}
        reasons = []
        if peak >= threshold:
            reasons.append(f"brute force ({peak} failures in {window_minutes} min)")
        if len(users) >= spray_users:
            reasons.append(f"password spraying ({len(users)} different usernames)")
        # a successful login after the first failure is the dangerous case
        compromised = [a for a in accepted_by_ip.get(ip, []) if a.ts >= times[0]]
        if reasons and compromised:
            reasons.append(f"successful login as '{compromised[0].user}' after failures")
        if not reasons:
            continue
        severity = "HIGH" if compromised else "MEDIUM"
        findings.append({
            "ip": ip,
            "severity": severity,
            "failed_total": len(fails),
            "peak_in_window": peak,
            "distinct_users": len(users),
            "invalid_users": sum(e.invalid_user for e in fails),
            "first_seen": times[0].isoformat(sep=" "),
            "last_seen": times[-1].isoformat(sep=" "),
            "reasons": "; ".join(reasons),
        })
    order = {"HIGH": 0, "MEDIUM": 1}
    return sorted(findings, key=lambda f: (order[f["severity"]], -f["failed_total"]))


def build_report(events: list[Event], findings: list[dict], source: str,
                 threshold: int, window_minutes: int) -> str:
    failed = [e for e in events if e.kind == "failed"]
    accepted = [e for e in events if e.kind == "accepted"]
    top_users = Counter(e.user for e in failed).most_common(5)
    lines = [
        "# SSH Log Analysis Report",
        "",
        f"- **Source:** `{source}`",
        f"- **Rule:** >= {threshold} failed logins from one IP within {window_minutes} minutes",
        f"- **Events parsed:** {len(events)} ({len(failed)} failed, {len(accepted)} accepted)",
        f"- **Unique source IPs:** {len({e.ip for e in events})}",
        f"- **Flagged IPs:** {len(findings)}",
        "",
        "## Flagged IPs",
        "",
    ]
    if findings:
        lines += ["| Severity | IP | Failed | Peak/window | Users | First seen | Reasons |",
                  "|---|---|---|---|---|---|---|"]
        for f in findings:
            lines.append(
                f"| {f['severity']} | `{f['ip']}` | {f['failed_total']} | {f['peak_in_window']} "
                f"| {f['distinct_users']} | {f['first_seen']} | {f['reasons']} |"
            )
    else:
        lines.append("No suspicious activity detected with the current thresholds.")
    lines += ["", "## Most targeted usernames", ""]
    lines += [f"- `{u}`: {n} failed attempts" for u, n in top_users] or ["- none"]
    lines += [
        "",
        "## Recommended actions",
        "",
        "- Block or rate-limit flagged IPs (firewall, `fail2ban`).",
        "- For any HIGH finding: treat the account as compromised, reset credentials, "
        "review session activity.",
        "- Disable password login and root login; use key-based authentication.",
        "",
    ]
    return "\n".join(lines)


def write_csv(findings: list[dict], path: Path) -> None:
    fields = ["severity", "ip", "failed_total", "peak_in_window", "distinct_users",
              "invalid_users", "first_seen", "last_seen", "reasons"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth.log")
    p.add_argument("logfile", type=Path)
    p.add_argument("--threshold", type=int, default=5, help="failed logins to flag (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="syslog has no year; assume this one")
    p.add_argument("--out", type=Path, default=Path("reports"), help="output folder")
    args = p.parse_args(argv)

    if not args.logfile.is_file():
        print(f"error: {args.logfile} not found", file=sys.stderr)
        return 2
    events = parse_file(args.logfile, args.year)
    findings = analyze(events, args.threshold, args.window)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.md").write_text(
        build_report(events, findings, args.logfile.name, args.threshold, args.window),
        encoding="utf-8")
    write_csv(findings, args.out / "flagged_ips.csv")
    print(f"{len(events)} events parsed, {len(findings)} IPs flagged -> {args.out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
