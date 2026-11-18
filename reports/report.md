# SSH Log Analysis Report

- **Source:** `auth_sample.log`
- **Rule:** >= 5 failed logins from one IP within 10 minutes
- **Events parsed:** 98 (93 failed, 5 accepted)
- **Unique source IPs:** 5
- **Flagged IPs:** 3

## Flagged IPs

| Severity | IP | Failed | Peak/window | Users | First seen | Reasons |
|---|---|---|---|---|---|---|
| HIGH | `192.0.2.77` | 12 | 12 | 1 | 2026-11-14 22:05:00 | brute force (12 failures in 10 min); successful login as 'deploy' after failures |
| MEDIUM | `203.0.113.45` | 60 | 60 | 3 | 2026-11-14 03:12:00 | brute force (60 failures in 10 min) |
| MEDIUM | `203.0.113.99` | 20 | 20 | 10 | 2026-11-14 11:40:00 | brute force (20 failures in 10 min); password spraying (10 different usernames) |

## Most targeted usernames

- `ubuntu`: 23 failed attempts
- `admin`: 21 failed attempts
- `root`: 16 failed attempts
- `deploy`: 12 failed attempts
- `test`: 2 failed attempts

## Recommended actions

- Block or rate-limit flagged IPs (firewall, `fail2ban`).
- For any HIGH finding: treat the account as compromised, reset credentials, review session activity.
- Disable password login and root login; use key-based authentication.
