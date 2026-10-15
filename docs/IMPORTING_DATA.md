# Loading a real company's data

The project ships with 30 fictional employees so you can try it. For a real company, load your own people with the
importer in `manage.py`. Nothing here needs a database tool: you prepare CSV files (Excel or Google Sheets can export them).

## Before you start

- **Decide what you need.** The app works with names, emails, departments, titles, managers and hire dates alone.
  Address, emergency contact and salary band are optional. Every extra personal field is more to protect, so leave
  out what you will not use.
- **Check the legal basis.** Employee records are personal data (for example under GDPR or India's DPDP Act). Agree
  with HR and your legal or privacy team what may be stored, who may see it and how long it is kept. This guide is not legal advice.
- **Use a fresh data folder** so demo people never mix with real ones (step 1).

## Step by step

**1. Start clean and turn demo data off.** In the environment the app and `manage.py` both run in:

```bash
export HR_DATA_DIR=/srv/hr-assistant/data     # outside the code folder, readable only by the service user
export HR_SEED_DEMO=0
export HR_DEFAULT_ALLOTMENT="annual=24,sick=12,casual=8"   # your policy's yearly days
```

Use the same values every time you run `manage.py` or the app. `manage.py` itself never creates demo data.

**2. Prepare the files.** Copy the examples from `docs/import-templates/` and replace the rows. Save as **CSV UTF-8**.

| File | Needed | Contents |
|---|---|---|
| `employees.csv` | yes | everyone, including managers and at least one `hr_admin` |
| `holidays.csv` | strongly advised | your company holidays, so leave days and return dates are right |
| `leave_allotments.csv` | optional | individual yearly entitlements that differ from the default |
| `leave_history.csv` | optional | leave already taken this year, so balances are right from day one |

**3. Check each file without changing anything.**

```bash
python manage.py import-employees employees.csv --dry-run
```

If anything is wrong you get every problem with its line number, and nothing is written. Fix the file and run it again.

**4. Import, in this order** (later files refer to people from the first):

```bash
python manage.py import-employees employees.csv
python manage.py import-holidays holidays.csv
python manage.py import-allotments leave_allotments.csv     # optional
python manage.py import-leave leave_history.csv             # optional
```

**5. Hand out the one-time passwords.** The import writes them to `initial_credentials.txt` in the data folder
(readable only by its owner). Give each person theirs privately, then **delete the file**. Everyone must choose their
own password at first sign-in. Passwords are never taken from your CSV files.

**6. Add the policy and start the app.** Put the company's `Policy.pdf` next to `app4.py`, run `streamlit run app4.py`,
sign in as an HR admin and use **Admin > Rebuild knowledge base** if answers do not reflect the PDF.

**7. Test with a few real people** (an employee, a manager and an HR admin) before announcing it.

## `employees.csv` columns

Required: `employee_id`, `name`, `email`. Everything else is optional.

| Column | Rules |
|---|---|
| `employee_id` | 2-20 letters, digits, `-` or `_`; unique. This is what people sign in with. |
| `name` | up to 80 characters |
| `email` | valid and unique |
| `role` | `employee` (default), `manager` or `hr_admin` |
| `manager_id` | must be in this file or already in the system, and active. No loops. |
| `department`, `job_title`, `location` | short plain text (40, 60 and 60 characters). No `<`, `>`, brackets or backslashes. |
| `hire_date` | `YYYY-MM-DD` |
| `phone`, `emergency_contact_phone` | 6-20 characters: digits, spaces, `+`, `-`, `(`, `)` |
| `status` | `active` (default) or `terminated` (no account password is issued) |
| `address`, `emergency_contact_name`, `salary_band` | optional; band is up to 12 letters or digits, such as `B3` |

Put quotes around any value that contains a comma: `"Head of People, EMEA"`.

Who sees what is fixed by the app, not by the file: everyone sees names, titles, departments, emails and locations;
managers also see phone, hire date and status for their direct reports; HR and the person themselves see everything.

## Keeping it up to date

Re-run the import with `--update` after any change in your HR system:

```bash
python manage.py import-employees employees.csv --update
```

- Without `--update`, people who already exist are skipped, so it is safe to re-run.
- With `--update`, a **blank cell leaves the existing value alone** (the importer cannot erase a field).
- Passwords are never touched. Changing someone's role or status signs out their open sessions.
- To remove someone, set `status` to `terminated`. They can no longer sign in. Their record is kept.
- Re-importing the same `leave_history.csv` is refused (it would count leave twice).
- The file is checked as a whole. One bad row means nothing is imported.

You can schedule this (cron or Task Scheduler) against a nightly export from your HR system.

## Before going live

- **Serve it over HTTPS** behind a reverse proxy (nginx, Caddy, IIS). Passwords cross the network.
- **Encrypt the disk** that holds `HR_DATA_DIR`, and limit who can log in to that server. The databases are protected by file permissions, not encryption.
- **Back up** `HR_DATA_DIR` (it holds `auth.db` and `employee_dbs/`) and test restoring it. Keep backups encrypted.
- **Delete `initial_credentials.txt`** once passwords are handed out.
- Ask HR admins to turn on two-step sign-in (sidebar > Account security).
- Run `python manage.py verify-audit` from time to time, and copy the audit log off the server for real assurance.

## Limits to know about

- **One working week and one holiday calendar.** Monday to Friday are working days, and the holidays you import apply to
  everyone. Companies with other weekends or different holidays per country need code changes.
- **Four leave types** (annual, sick, casual, unpaid), whole or half days entitlements, no carry-over, no half-day requests.
- **No single sign-in (SSO)** yet. People sign in with the ID and password issued here.
- **Deactivated, not erased.** There is no tool to delete a person's data permanently. If your policy or the law requires erasure, that has to be added.
- **SQLite and one server process.** Fine for a few hundred to a few thousand employees. Beyond that, plan a move to a server database.
