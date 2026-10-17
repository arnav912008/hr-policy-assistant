# HR Policy Assistant

[![tests](https://github.com/<your-username>/hr-policy-assistant/actions/workflows/tests.yml/badge.svg)](https://github.com/<your-username>/hr-policy-assistant/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A private, self-hosted HR chatbot. It answers policy questions from your own `Policy.pdf` **and** looks up and updates
employee records through chat: who is on leave, when they are back, apply for and approve leave, update your details.
Everything runs locally with [Ollama](https://ollama.com), and every change needs a confirmation click.

> All HR data in this repository is **synthetic**: 30 fictional people, `@globalcorp.example` emails and `+1-555-01xx` phone numbers.

## Features

- **Personal dashboard** for everyone: leave left by type, pending requests, who is away this week, a leave-by-month chart and a request form
- **Approve from the dashboard:** managers (their team) and HR (everyone else) see a "Waiting for your approval" panel with Approve and Reject buttons, the person's remaining balance and who else in their department is away
- **Light and dark mode**, switched in the top bar and remembered per person
- **Policy Q&A** over your PDF (Chroma + Ollama), with answers stripped of links, images and HTML
- **Who is away?** "Is Carol on leave?", "When will Bob be back?", "Who is on leave next week?" (return dates skip weekends and holidays and merge back-to-back leave)
- **Leave workflow:** apply, cancel, approve, reject, balances, pending-approval lists; nobody approves their own request
- **Self-service:** update your phone, address and emergency contact
- **HR tools:** update employee records with guardrails (no self-promotion, no reporting-line loops, last admin protected)
- **Privacy by role:** directory, manager and full views of an employee record; leave *type* is private
- **Security built in:** lockout, 600k-round password hashing, optional authenticator-app MFA, session expiry, role re-checks, tamper-evident audit log
- **Admin panel:** replace the policy PDF safely, atomic index rebuild, hashed backups, audit viewer

## Quick start

Requires Python 3.12 and [Ollama](https://ollama.com).

```bash
ollama pull nomic-embed-text
ollama pull llama3.2:3b

git clone https://github.com/<your-username>/hr-policy-assistant.git
cd hr-policy-assistant
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp /path/to/your/Policy.pdf .                       # your policy document
streamlit run app4.py
```

1. On first start the app creates its databases and seeds the demo company.
2. One-time passwords are written to `initial_credentials.txt` (owner-only). Find `E001` (HR admin), `E002` (manager) or `E003` (employee), sign in, and choose a new password. **Delete the file when you have handed the passwords out.**
3. Open http://localhost:8501 and try the examples below.

## The dashboard

Everyone lands on their own dashboard. The sidebar menu switches between **Dashboard** and **Assistant** (the chat).

| Panel | Who sees it |
|---|---|
| Four cards: annual, sick and casual leave left (with a bar for days taken) and your pending requests | everyone |
| **Waiting for your approval**: Approve and Reject buttons, with the requester's days left and who in their department is already away | managers (their direct reports), HR admins (everyone except themselves) |
| **My leave requests** with status; cancel a pending or future request | everyone |
| **Request leave** form (dates, type, reason) | everyone |
| **Away this week** with return dates | everyone |
| **Leave taken by month** chart, current month highlighted | everyone |

The **Light / Dark** switch is at the top right of every page. Approvals made here follow the same rules as in chat: you
cannot approve your own request, and managers can only decide for their direct reports. Every decision is written to the audit log.

## What you can ask

| Ask | Who can |
|---|---|
| "Is Carol on leave?" / "When will Bob be back?" / "Who is on leave today?" | everyone (dates only; leave type visible to the person, their manager and HR) |
| "Apply for leave from 14 Oct to 16 Oct" / "sick leave tomorrow" | you |
| "My leave balance" / "Show my leave requests" / "Cancel leave 12" | you |
| "Pending leave requests" / "Approve leave 12" / "Reject leave 12 because ..." | managers (their reports), HR |
| "Show my details" / "Who is my manager?" / "What's Priya's email?" | everyone, filtered by role |
| "Update my phone to +1-555-0123" | you |
| "Change the department of Aarav to Finance" / "Make E010 report to E002" | HR admins |

Anything else is answered from the policy PDF. Every change shows a summary first and needs **Confirm**.

## How it works

The language model **never reads or writes HR data**. Fixed patterns turn the user's own typed message into an action,
permissions are checked in code, and the user confirms each write. Text hidden in a PDF, or in model output, cannot trigger a change.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the diagram, data model and threat table.

## Operations

```bash
python manage.py list                  # accounts
python manage.py reset-password E001   # one-time password, forced change at next sign-in
python manage.py reset-mfa E001        # lost authenticator device
python manage.py unlock E001           # clear a lockout
python manage.py verify-audit          # check the audit log was not altered
make test                              # 69 unit tests, standard library only, no Ollama needed
```

Settings (environment variables, see `.env.example`): `HR_DATA_DIR`, `HR_IDLE_TIMEOUT_MIN` (30),
`HR_SESSION_MAX_HOURS` (8), `HR_ALLOW_EXTERNAL_FONTS` (off).
Streamlit hardening (upload limit, XSRF, no stack traces) is in `.streamlit/config.toml`.

## Changing the look

The whole interface runs on a few colour and size variables at the top of `BASE_CSS` in `app4.py`:

```css
--pine: #0b6b5d;      /* the accent: buttons, focus rings, send button */
--tint: #e8f2ef;      /* your message bubbles, soft highlights */
--mist: #f3f5f4;      /* sidebar background */
--ink: #1f2933;       /* main text */
--sidebar-w: 17.5rem; --column-w: 760px;
```

Change `--pine`, `--pine-hover`, `--pine-press` and `--tint` together to re-colour the app. The default font is your
system font; set `HR_ALLOW_EXTERNAL_FONTS=1` to load Figtree instead.

## Using it for a real company

The demo data is fictional. To load your own people, holidays and leave balances from CSV files, follow
**[docs/IMPORTING_DATA.md](docs/IMPORTING_DATA.md)**. In short:

```bash
export HR_SEED_DEMO=0
python manage.py import-employees employees.csv --dry-run   # check first, nothing is written
python manage.py import-employees employees.csv
```

## Deploying for real people

This is a reference project. Before using it with real data, read [SECURITY.md](SECURITY.md). In short: put it behind a
reverse proxy with **TLS** and per-IP rate limiting, copy the audit log off the server, and have your own security review.

## Project layout

```
app4.py            UI and policy Q&A
hr_security.py     auth, sessions, MFA, audit log, file permissions
hr_data.py         HR database, synthetic data, leave rules, permission-checked reads/writes
hr_agent.py        chat to action, confirmation, output sanitising, rate limits
manage.py          operator commands
tests/             unit tests
docs/              architecture and security model
```

## Status and limitations

Tested on Python 3.12. The Ollama/Chroma parts (index build, PDF upload) are exercised in the app but are not covered
by the automated tests, which stub them out. No per-IP throttling (use a proxy). Files are protected by permissions,
not encryption. See [CHANGELOG.md](CHANGELOG.md) for what changed from the original prototype.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first, and report security problems privately via [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
