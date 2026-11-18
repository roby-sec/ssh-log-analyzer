import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssh_log_analyzer import Event, analyze, max_in_window, parse_line  # noqa: E402

FAILED = "Nov  4 03:12:45 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 53422 ssh2"
ACCEPTED = "Nov 14 08:01:02 web01 sshd[99]: Accepted password for roby from 198.51.100.7 port 40000 ssh2"


class ParseTests(unittest.TestCase):
    def test_failed_invalid_user(self):
        ev = parse_line(FAILED, 2026)
        self.assertEqual((ev.kind, ev.user, ev.ip, ev.invalid_user),
                         ("failed", "admin", "203.0.113.5", True))
        self.assertEqual(ev.ts, datetime(2026, 11, 4, 3, 12, 45))  # double space after month

    def test_accepted(self):
        ev = parse_line(ACCEPTED, 2026)
        self.assertEqual((ev.kind, ev.user, ev.ip), ("accepted", "roby", "198.51.100.7"))

    def test_ignores_other_lines(self):
        self.assertIsNone(parse_line("Nov 14 02:01:00 web01 CRON[1]: (root) CMD (x)", 2026))
        self.assertIsNone(parse_line("garbage", 2026))


class DetectionTests(unittest.TestCase):
    base = datetime(2026, 11, 14, 12, 0, 0)

    def fails(self, ip, n, step, user="root"):
        return [Event(self.base + timedelta(seconds=i * step), "failed", user, ip) for i in range(n)]

    def test_sliding_window(self):
        times = [self.base + timedelta(minutes=m) for m in (0, 1, 2, 30)]
        self.assertEqual(max_in_window(times, timedelta(minutes=10)), 3)

    def test_brute_force_flagged(self):
        res = analyze(self.fails("203.0.113.1", 6, 10))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "MEDIUM")

    def test_slow_attempts_not_flagged(self):
        # 6 failures, but 20 minutes apart: never 5 inside a 10-minute window
        self.assertEqual(analyze(self.fails("203.0.113.2", 6, 1200)), [])

    def test_success_after_failures_is_high(self):
        evs = self.fails("192.0.2.9", 6, 10, user="deploy")
        evs.append(Event(self.base + timedelta(minutes=5), "accepted", "deploy", "192.0.2.9"))
        self.assertEqual(analyze(evs)[0]["severity"], "HIGH")

    def test_spraying_flagged(self):
        evs = [Event(self.base + timedelta(minutes=i * 30), "failed", f"u{i}", "203.0.113.3")
               for i in range(6)]
        res = analyze(evs)
        self.assertIn("spraying", res[0]["reasons"])

    def test_legit_typo_not_flagged(self):
        evs = self.fails("198.51.100.7", 1, 1, user="roby")
        evs.append(Event(self.base + timedelta(seconds=9), "accepted", "roby", "198.51.100.7"))
        self.assertEqual(analyze(evs), [])


if __name__ == "__main__":
    unittest.main()
