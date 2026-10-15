# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private
[security advisory form](../../security/advisories/new) for this repository, or contact the maintainer directly.
Include steps to reproduce and the affected version. You can expect an acknowledgement within a few days.

## Supported versions

Only the latest release receives security fixes.

## Scope and threat model

This is a reference/demo project that ships with **synthetic data**. If you adapt it for real employee data,
you are responsible for a production review. In particular:

- Run it behind a reverse proxy with **TLS**; passwords cross the network.
- Add per-IP rate limiting at the proxy (Streamlit does not expose client IPs).
- Move the audit log off the server for real tamper-resistance; the built-in hash chain is tamper-*evident* only.
- Protect the host: `auth.db`, `employee_dbs/` and `chroma_db/` are protected by file permissions, not encryption.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model) for the design.

## What is deliberately not possible from chat

Changing roles, resetting passwords, or turning MFA off for someone else. Those are operator tasks in `manage.py`.
