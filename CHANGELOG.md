# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Personal dashboard for every employee: leave left by type, pending requests, who is away this week, leave taken by month, and a request form.
- Approvals from the dashboard for managers and HR (Approve and Reject buttons with the requester's remaining balance and which department colleagues are already away).
- Light and dark mode with a switch in the top bar, remembered per person.
- Sidebar menu to move between the Dashboard and the Assistant.
- Bulk import of real company data from CSV: `manage.py import-employees`, `import-holidays`, `import-allotments`, `import-leave`. Every file is validated in full first, errors list their line numbers, nothing is written if any row fails, and `--dry-run` previews the result. See `docs/IMPORTING_DATA.md` and the templates in `docs/import-templates/`.
- `HR_SEED_DEMO=0` stops demo data being created; `HR_DEFAULT_ALLOTMENT` sets the company's yearly leave days.

### Changed
- Salary band accepts any short code (up to 12 letters, digits, dots or dashes) instead of only B1 to B9.
- Dashboard-style layout: a soft page background with bordered cards, one teal accent that is deeper in light mode and brighter in dark mode. Both themes share one set of variables (`BASE_CSS` and `DARK_CSS`).

- Redesigned the interface. Calmer, lighter look on a single colour system (all tokens are variables at the top of `BASE_CSS`).
- Conversation reads like a document: replies are plain text, your messages are soft tinted bubbles, and the composer is a light floating input instead of a dark bar.
- Sidebar simplified into quiet text rows with sentence-case section labels, an avatar for the signed-in user, and collapsible Account, Admin and Audit rows.
- Welcome screen greets you by name and suggests real tasks ("Who is on leave today?", "What is my leave balance?") alongside policy questions.
- Sign-in page shows a sample conversation instead of decorative graphics; Confirm and Cancel have their own action styling.
- The sidebar collapses on phones (it was forced open at every width); entrance animations and hover lifts were removed.
- `HR_ALLOW_EXTERNAL_FONTS=1` now loads Figtree (was Inter). The default is still the system font, with no external requests.

## [1.0.0] - 2026-10-10

First public release. It builds on the original single-file `app4.py` prototype.

### Added
- Synthetic HR database (30 fictional employees) with profiles, leave balances, leave requests and company holidays.
- Chat actions: look up employee details, see who is on leave and when they return, apply for / cancel / approve / reject leave, update your own contact details, HR record updates. Every write needs confirmation.
- Role-based visibility: directory, manager and full views of an employee record.
- Optional two-step sign-in (TOTP), password change screen, password policy.
- Append-only, hash-chained audit log with an admin viewer and `manage.py verify-audit`.
- `manage.py` operator tool, unit tests (43 at the time), GitHub Actions workflow.

### Security
- Removed start-up accounts that reset to known passwords on every launch (`INSERT OR REPLACE` backdoor). Legacy `ChangeMe!N` accounts are rotated on upgrade.
- Login lockout with progressive delay, applied equally to unknown IDs; equal-time responses; PBKDF2 raised to 600,000 rounds.
- Role and account status re-read from the database on every interaction; sessions expire (idle and absolute) and end on password change.
- Upload hardening: size, magic-byte and page limits, unique temp files, hashed backups, generic user-facing errors.
- Knowledge-base rebuild is atomic: the live index is replaced only after the new one is complete.
- LLM hardening: capped history and input, per-user rate limits, delimited policy text, and removal of images, links and HTML from model output to close an image-URL data leak.
- File permissions tightened; Google Fonts no longer loaded by default.
