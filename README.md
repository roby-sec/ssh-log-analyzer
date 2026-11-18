# SSH Log Analyzer

A small Python tool that reads an SSH `auth.log`, detects **brute-force attacks**, **password spraying** and **suspicious successful logins**, and produces a Markdown report plus a CSV of flagged IP addresses.

Built as a hands-on project after completing the *Google Cybersecurity Professional Certificate* (Linux, Python, detection and response).

## Why this matters

Failed SSH logins are one of the most common signals a SOC analyst triages. The most dangerous pattern is not the failures themselves but **a successful login right after many failures**: it can mean an account has been compromised. This tool surfaces that pattern automatically.

## What it detects

| Pattern | Rule (configurable) | Severity |
|---|---|---|
| Brute force | >= 5 failed logins from one IP within 10 minutes | MEDIUM |
| Password spraying | one IP tries >= 5 different usernames | MEDIUM |
| Possible compromise | a rule above fires **and** the same IP then logs in successfully | HIGH |

A user mistyping their password once and then logging in correctly is **not** flagged (covered by a test).

## Usage

Requires Python 3.9+ and no external packages.

```bash
python src/ssh_log_analyzer.py samples/auth_sample.log --year 2026 --out reports/
```

Options: `--threshold` (failures to flag), `--window` (minutes), `--year` (syslog lines carry no year), `--out` (output folder).

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Example output

Run on the synthetic sample log (see [`reports/report.md`](reports/report.md)):

| Severity | IP | Failed | Reasons |
|---|---|---|---|
| HIGH | 192.0.2.77 | 12 | brute force; successful login as `deploy` after failures |
| MEDIUM | 203.0.113.45 | 60 | brute force against `root` / `admin` / `ubuntu` |
| MEDIUM | 203.0.113.99 | 20 | brute force; password spraying (10 usernames) |

## Project structure

```
src/ssh_log_analyzer.py        parser, detection logic, report writer
samples/generate_sample_log.py generates a reproducible synthetic log
samples/auth_sample.log        synthetic data (documentation IPs, RFC 5737)
tests/test_analyzer.py         unit tests
reports/                       example output
```

## Data and ethics

The sample log is **100% synthetic**: all IPs belong to the documentation ranges reserved by RFC 5737. Only analyze logs from systems you own or are authorized to review. Never commit real logs to a public repository.

## Limitations and next steps

- Handles the classic syslog `auth.log` format only (not `journald` JSON).
- Detection is threshold-based; it does not use IP reputation or GeoIP.
- Ideas: `fail2ban`-style ban list export, journald support, a time-series chart of attempts.

## What I learned

- Parsing semi-structured logs with regular expressions.
- Sliding-window detection instead of simple counting (slow attacks vs. bursts).
- Translating a security concept (brute force, spraying, compromise) into testable rules.

## License

MIT
