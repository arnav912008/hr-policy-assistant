# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-10

First public release. It builds on the original single-file `app4.py` prototype.

### Added
- Synthetic HR database (30 fictional employees) with profiles, leave balances, leave requests and company holidays.
- Chat actions: look up employee details, see who is on leave and when they return, apply for / cancel / approve / reject leave, update your own contact details, HR record updates. Every write needs confirmation.
- Role-based visibility: directory, manager and full views of an employee record.
- Optional two-step sign-in (TOTP), password change screen, password policy.
- Append-only, hash-chained audit log with an admin viewer and `manage.py verify-audit`.
- `manage.py` operator tool, unit tests (43), GitHub Actions workflow.

### Security
- Removed start-up accounts that reset to known passwords on every launch (`INSERT OR REPLACE` backdoor). Legacy `ChangeMe!N` accounts are rotated on upgrade.
- Login lockout with progressive delay, applied equally to unknown IDs; equal-time responses; PBKDF2 raised to 600,000 rounds.
- Role and account status re-read from the database on every interaction; sessions expire (idle and absolute) and end on password change.
- Upload hardening: size, magic-byte and page limits, unique temp files, hashed backups, generic user-facing errors.
- Knowledge-base rebuild is atomic: the live index is replaced only after the new one is complete.
- LLM hardening: capped history and input, per-user rate limits, delimited policy text, and removal of images, links and HTML from model output to close an image-URL data leak.
- File permissions tightened; Google Fonts no longer loaded by default.
