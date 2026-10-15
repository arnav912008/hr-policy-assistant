"""Bulk import of real company data from CSV files. Operator tool, used through manage.py.

Rules that apply to every importer:
  * The whole file is validated first. If any row has a problem, NOTHING is written and every
    problem is listed with its line number.
  * Writes happen in a single transaction, so a crash cannot leave a half-imported company.
  * Passwords are never read from files. New accounts get random one-time passwords.
  * Use --dry-run to see what would happen without changing anything.
"""
from __future__ import annotations

import csv
import re
import secrets
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import hr_data as hd
import hr_security as sec
from hr_security import audit

MAX_ROWS = 50_000
MAX_FILE_BYTES = 20 * 1024 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{2,20}$")
_PROFILE_COLUMNS = ("email", "phone", "department", "job_title", "location", "hire_date", "address",
                    "emergency_contact_name", "emergency_contact_phone", "salary_band")


@dataclass
class Report:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    credentials: list = field(default_factory=list)   # [(employee_id, one-time password)]
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors


# --------------------------------------------------------------------------- reading
def _read_csv(path, required, optional, report: Report):
    """Return [(line_number, {column: value})]. Problems go into report.errors."""
    p = Path(path)
    if not p.is_file():
        report.errors.append(f"File not found: {path}")
        return []
    if p.stat().st_size > MAX_FILE_BYTES:
        report.errors.append("File is larger than 20 MB. Split it into several files.")
        return []
    rows = []
    try:
        with open(p, newline="", encoding="utf-8-sig") as f:   # utf-8-sig also accepts Excel's byte-order mark
            reader = csv.DictReader(f)
            header = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
            allowed = set(required) | set(optional)
            for h in header:
                if h not in allowed:
                    report.errors.append(f"Unknown column '{h}'. Allowed columns: {', '.join(list(required) + list(optional))}.")
            for r in required:
                if r not in header:
                    report.errors.append(f"Missing required column '{r}'.")
            if report.errors:
                return []
            reader.fieldnames = header
            for line, row in enumerate(reader, start=2):
                if None in row:
                    report.errors.append(f"line {line}: more values than columns (a comma inside a value? wrap it in quotes).")
                    continue
                clean = {k: (v or "").strip() for k, v in row.items() if k}
                if not any(clean.values()):
                    continue
                rows.append((line, clean))
                if len(rows) > MAX_ROWS:
                    report.errors.append(f"More than {MAX_ROWS} rows. Split the file.")
                    return []
    except UnicodeDecodeError:
        report.errors.append("The file is not UTF-8. In Excel use 'Save as: CSV UTF-8 (Comma delimited)'.")
        return []
    except csv.Error as e:
        report.errors.append(f"Could not read the CSV: {e}")
        return []
    if not rows and not report.errors:
        report.errors.append("The file has a header but no data rows.")
    return rows


def _date(value: str, label: str):
    try:
        d = date.fromisoformat(value)
    except ValueError:
        return None, f"{label} '{value}' is not a date in YYYY-MM-DD format."
    if not (date(1950, 1, 1) <= d <= date(2100, 12, 31)):
        return None, f"{label} '{value}' is out of range."
    return d, None


# --------------------------------------------------------------------------- password hashing (parallel)
def _hash_one(pw: str) -> str:
    return sec.hash_password(pw)


def _hash_many(passwords: list) -> list:
    """600,000-round hashing takes about a quarter of a second each, so spread large imports over all CPU cores."""
    if len(passwords) < 40:
        return [_hash_one(p) for p in passwords]
    with ProcessPoolExecutor() as pool:
        return list(pool.map(_hash_one, passwords, chunksize=8))


# --------------------------------------------------------------------------- employees
EMPLOYEE_REQUIRED = ("employee_id", "name", "email")
EMPLOYEE_OPTIONAL = ("role", "manager_id", "department", "job_title", "location", "hire_date", "phone", "status",
                     "address", "emergency_contact_name", "emergency_contact_phone", "salary_band")


def import_employees(path, update: bool = False, dry_run: bool = False) -> Report:
    """Create employees (and, with update=True, change existing ones). Blank optional cells leave existing values unchanged."""
    report = Report(dry_run=dry_run)
    sec.init_auth_db()
    hd.init_hr_db()
    rows = _read_csv(path, EMPLOYEE_REQUIRED, EMPLOYEE_OPTIONAL, report)
    if report.errors:
        return report

    existing = {p["employee_id"]: p for p in hd.all_people()}
    db_emails = {(p["email"] or "").lower(): p["employee_id"] for p in existing.values() if p["email"]}
    seen_ids, seen_emails, recs = set(), {}, []

    for line, row in rows:
        def err(msg, _l=line):
            report.errors.append(f"line {_l}: {msg}")
        before = len(report.errors)
        eid = row["employee_id"]
        if not _ID_RE.match(eid):
            err(f"employee_id '{eid}' must be 2-20 letters, digits, '-' or '_'.")
            continue
        if eid in seen_ids:
            err(f"employee_id '{eid}' appears more than once in this file.")
            continue
        seen_ids.add(eid)
        exists = eid in existing
        if exists and not update:
            report.skipped += 1
            report.warnings.append(f"line {line}: {eid} already exists and was skipped (use --update to change existing employees).")
            continue

        rec = {"employee_id": eid, "exists": exists, "line": line}
        name = hd.clean_text(row["name"], 80)
        if not name:
            err("name is empty, longer than 80 characters, or has characters that are not allowed.")
        rec["name"] = name
        email, e = hd.validate_field("email", row["email"])
        if e:
            err(f"email: {e}")
        else:
            rec["email"] = email
            other = seen_emails.get(email) or db_emails.get(email)
            if other and other != eid:
                err(f"email {email} is already used by {other}.")
            seen_emails[email] = eid

        role = row.get("role", "").lower()
        if role and role not in sec.VALID_ROLES:
            err(f"role '{role}' must be one of: {', '.join(sec.VALID_ROLES)}.")
        elif role:
            rec["role"] = role
        status = row.get("status", "").lower()
        if status:
            status, e = hd.validate_field("status", status)
            if e:
                err(e)
            else:
                rec["status"] = status
        mgr = row.get("manager_id", "")
        if mgr:
            if not _ID_RE.match(mgr):
                err(f"manager_id '{mgr}' is not a valid employee id.")
            else:
                rec["manager_id"] = mgr
        if row.get("hire_date"):
            d, e = _date(row["hire_date"], "hire_date")
            if e:
                err(e)
            else:
                rec["hire_date"] = d.isoformat()
        for f in ("department", "job_title", "location", "address", "emergency_contact_name", "phone",
                  "emergency_contact_phone", "salary_band"):
            if row.get(f):
                v, e = hd.validate_field(f, row[f])
                if e:
                    err(f"{f}: {e}")
                else:
                    rec[f] = v
        if len(report.errors) == before:
            recs.append(rec)

    # --- checks that need the whole file and the existing data together
    final_active = {i: p["active"] for i, p in existing.items()}
    final_role = {i: p["role"] for i, p in existing.items()}
    final_mgr = {i: p["manager_id"] for i, p in existing.items()}
    for r in recs:
        eid = r["employee_id"]
        if "status" in r:
            final_active[eid] = r["status"] == "active"
        elif not r["exists"]:
            final_active[eid] = True
        final_role[eid] = r.get("role", final_role.get(eid, "employee"))
        final_mgr[eid] = r.get("manager_id", final_mgr.get(eid))
    for r in recs:
        m = r.get("manager_id")
        if not m:
            continue
        if m == r["employee_id"]:
            report.errors.append(f"line {r['line']}: {m} cannot be their own manager.")
        elif m not in final_active:
            report.errors.append(f"line {r['line']}: manager '{m}' was not found in this file or in the system.")
        elif not final_active[m]:
            report.errors.append(f"line {r['line']}: manager '{m}' is terminated.")
    for r in recs:
        cur, hops = final_mgr.get(r["employee_id"]), 0
        while cur and hops <= len(final_mgr):
            if cur == r["employee_id"]:
                report.errors.append(f"line {r['line']}: {r['employee_id']} is part of a reporting loop.")
                break
            cur, hops = final_mgr.get(cur), hops + 1
    if not any(final_active.get(i) and final_role.get(i) == "hr_admin" for i in final_active):
        report.errors.append("After this import there would be no active hr_admin. Include at least one row with role hr_admin.")
    if report.errors:
        return report

    if _has_demo_data():
        report.warnings.append("This database contains DEMO data. For a real company start from an empty data folder with HR_SEED_DEMO=0.")

    new = [r for r in recs if not r["exists"]]
    upd = [r for r in recs if r["exists"]]
    report.created, report.updated = len(new), len(upd)
    if dry_run:
        return report

    passwords = {r["employee_id"]: secrets.token_urlsafe(12) for r in new}
    hashes = dict(zip(passwords.keys(), _hash_many(list(passwords.values()))))
    now = time.time()
    with hd.hr_conn() as conn:
        with conn:
            for r in new:
                eid = r["employee_id"]
                active = 1 if r.get("status", "active") == "active" else 0
                h = hashes[eid]
                conn.execute(
                    "INSERT INTO auth.employees (employee_id, name, role, manager_id, salt, pw_hash, active, must_change, pw_changed) "
                    "VALUES (?,?,?,?,?,?,?,1,?)",
                    (eid, r["name"], r.get("role", "employee"), r.get("manager_id"), h.split("$")[2], h, active, now))
                conn.execute("INSERT OR IGNORE INTO employee_profile (employee_id, department, job_title) VALUES (?,?,?)",
                             (eid, r.get("department", "Unassigned"), r.get("job_title", "Employee")))
                _write_profile(conn, eid, r)
                if active:
                    report.credentials.append((eid, passwords[eid]))
            for r in upd:
                eid = r["employee_id"]
                cur = existing[eid]
                sets, vals = ["name=?"], [r["name"]]
                if "role" in r:
                    sets.append("role=?"); vals.append(r["role"])
                if "manager_id" in r:
                    sets.append("manager_id=?"); vals.append(r["manager_id"])
                if "status" in r:
                    sets.append("active=?"); vals.append(1 if r["status"] == "active" else 0)
                if ("role" in r and r["role"] != cur["role"]) or ("status" in r and (r["status"] == "active") != cur["active"]):
                    sets.append("session_epoch=session_epoch+1")   # sign out open sessions when access changes
                conn.execute(f"UPDATE auth.employees SET {', '.join(sets)} WHERE employee_id=?", (*vals, eid))  # fixed column names only
                conn.execute("INSERT OR IGNORE INTO employee_profile (employee_id) VALUES (?)", (eid,))
                _write_profile(conn, eid, r)
    if report.credentials:
        sec.write_credentials(report.credentials, note="Imported employees.")
    audit("cli", "employees_imported", detail=f"created={report.created} updated={report.updated} skipped={report.skipped}")
    return report


def _write_profile(conn, eid: str, rec: dict) -> None:
    for col in _PROFILE_COLUMNS:  # fixed whitelist, never user input
        if col in rec:
            conn.execute(f"UPDATE employee_profile SET {col}=?, updated_at=?, updated_by=? WHERE employee_id=?",
                         (rec[col], time.time(), "import", eid))


def _has_demo_data() -> bool:
    with hd.hr_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM employee_profile WHERE updated_by='seed'").fetchone()[0] > 0


# --------------------------------------------------------------------------- holidays
def import_holidays(path, replace: bool = False, dry_run: bool = False) -> Report:
    """Company holidays (date,name). They are skipped when counting leave days and working out return dates."""
    report = Report(dry_run=dry_run)
    hd.init_hr_db()
    rows = _read_csv(path, ("date", "name"), (), report)
    if report.errors:
        return report
    items, seen = [], set()
    for line, row in rows:
        d, e = _date(row["date"], "date")
        name = hd.clean_text(row["name"], 60)
        if e:
            report.errors.append(f"line {line}: {e}")
        elif not name:
            report.errors.append(f"line {line}: name is empty or too long (max 60).")
        elif d in seen:
            report.errors.append(f"line {line}: {d} appears more than once.")
        else:
            seen.add(d)
            items.append((d.isoformat(), name))
    if report.errors:
        return report
    report.created = len(items)
    if dry_run:
        return report
    with hd.hr_conn() as conn:
        with conn:
            if replace:
                conn.execute("DELETE FROM holidays")
            conn.executemany("INSERT OR REPLACE INTO holidays (date, name) VALUES (?,?)", items)
    audit("cli", "holidays_imported", detail=f"{len(items)} dates, replace={replace}")
    return report


# --------------------------------------------------------------------------- yearly leave entitlements
def import_allotments(path, dry_run: bool = False) -> Report:
    """Per-person yearly entitlements (employee_id,year,leave_type,days). People without a row get the company default."""
    report = Report(dry_run=dry_run)
    hd.init_hr_db()
    rows = _read_csv(path, ("employee_id", "year", "leave_type", "days"), (), report)
    if report.errors:
        return report
    known = {p["employee_id"] for p in hd.all_people()}
    items, seen = [], set()
    for line, row in rows:
        eid, lt = row["employee_id"], row["leave_type"].lower()
        try:
            year, days = int(row["year"]), float(row["days"])
        except ValueError:
            report.errors.append(f"line {line}: year must be a whole number and days a number.")
            continue
        if eid not in known:
            report.errors.append(f"line {line}: employee '{eid}' not found. Import employees first.")
        elif lt not in hd.DEFAULT_ALLOTMENT:
            report.errors.append(f"line {line}: leave_type '{lt}' must be one of: {', '.join(hd.DEFAULT_ALLOTMENT)}.")
        elif not (2000 <= year <= 2100) or not (0 <= days <= 366) or (days * 2) % 1:
            report.errors.append(f"line {line}: year must be 2000-2100 and days 0-366 in steps of 0.5.")
        elif (eid, year, lt) in seen:
            report.errors.append(f"line {line}: {eid} {year} {lt} appears more than once.")
        else:
            seen.add((eid, year, lt))
            items.append((eid, year, lt, days))
    if report.errors:
        return report
    report.created = len(items)
    if dry_run:
        return report
    with hd.hr_conn() as conn:
        with conn:
            conn.executemany("INSERT OR REPLACE INTO leave_allotments (employee_id, year, leave_type, days) VALUES (?,?,?,?)", items)
    audit("cli", "allotments_imported", detail=f"{len(items)} rows")
    return report


# --------------------------------------------------------------------------- leave history
def import_leave_history(path, dry_run: bool = False) -> Report:
    """Leave already taken before go-live, so balances and 'who is away' are right on day one."""
    report = Report(dry_run=dry_run)
    hd.init_hr_db()
    rows = _read_csv(path, ("employee_id", "leave_type", "start_date", "end_date"), ("status", "reason"), report)
    if report.errors:
        return report
    known = {p["employee_id"] for p in hd.all_people()}
    with hd.hr_conn() as conn:
        hol = hd._holidays(conn)
        db_rows = conn.execute("SELECT employee_id, start_date, end_date FROM leave_requests WHERE status IN ('pending','approved')").fetchall()
    taken = {}
    for eid, s, e in db_rows:
        taken.setdefault(eid, []).append((date.fromisoformat(s), date.fromisoformat(e), "already in the system"))
    items = []
    for line, row in rows:
        eid, lt = row["employee_id"], row["leave_type"].lower()
        status = (row.get("status") or "approved").lower()
        s, es = _date(row["start_date"], "start_date")
        e, ee = _date(row["end_date"], "end_date")
        reason = hd.clean_text(row["reason"], 200) if row.get("reason") else None
        if eid not in known:
            report.errors.append(f"line {line}: employee '{eid}' not found. Import employees first.")
        elif lt not in hd.LEAVE_TYPES:
            report.errors.append(f"line {line}: leave_type '{lt}' must be one of: {', '.join(hd.LEAVE_TYPES)}.")
        elif status not in ("approved", "rejected", "cancelled"):
            report.errors.append(f"line {line}: status must be approved, rejected or cancelled.")
        elif es or ee:
            report.errors.append(f"line {line}: {es or ee}")
        elif e < s:
            report.errors.append(f"line {line}: end_date is before start_date.")
        elif s.year != e.year:
            report.errors.append(f"line {line}: leave spanning two calendar years must be split into one row per year.")
        elif row.get("reason") and reason is None:
            report.errors.append(f"line {line}: reason is too long or has characters that are not allowed.")
        else:
            days = hd.count_working_days(s, e, hol)
            if days == 0:
                report.errors.append(f"line {line}: {s} to {e} has no working days.")
                continue
            if status == "approved":
                clash = next((w for a, b, w in taken.get(eid, []) if a <= e and b >= s), None)
                if clash:
                    report.errors.append(f"line {line}: overlaps other leave for {eid} ({clash}). Was this file already imported?")
                    continue
                taken.setdefault(eid, []).append((s, e, f"line {line}"))
            items.append((eid, lt, s.isoformat(), e.isoformat(), float(days), reason, status))
    if report.errors:
        return report
    report.created = len(items)
    if dry_run:
        return report
    now = time.time()
    with hd.hr_conn() as conn:
        with conn:
            conn.executemany(
                "INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, days, reason, status, created_at, decided_by, decided_at) "
                "VALUES (?,?,?,?,?,?,?,?,'import',?)", [(*i, now, now) for i in items])
    audit("cli", "leave_history_imported", detail=f"{len(items)} rows")
    return report
