"""HR data layer: employee records, leave, synthetic seed data.

Every function takes the *acting employee id* and re-reads that person's role from the database,
so permissions can never be stale. All SQL is parameterised; the only f-strings insert column names
taken from fixed whitelists, never from user input.
"""
from __future__ import annotations

import os
import random
import re
import secrets
import time
from contextlib import contextmanager
from datetime import date, timedelta
from typing import Optional

import hr_security as sec
from hr_security import audit

LEAVE_TYPES = ("annual", "sick", "casual", "unpaid")
def _load_default_allotment() -> dict:
    """Yearly leave days per type. Override with HR_DEFAULT_ALLOTMENT="annual=24,sick=12,casual=8"."""
    base = {"annual": 18.0, "sick": 10.0, "casual": 6.0}
    for part in os.environ.get("HR_DEFAULT_ALLOTMENT", "").split(","):
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key in base:
            try:
                days = float(val)
            except ValueError:
                continue
            if 0 <= days <= 366:
                base[key] = days
    return base


DEFAULT_ALLOTMENT = _load_default_allotment()
MAX_LEAVE_CALENDAR_DAYS = 60
BACKDATE_LIMIT_DAYS = 7
MAX_FUTURE_DAYS = 366

DIRECTORY_FIELDS = ("employee_id", "name", "email", "department", "job_title", "location")
MANAGER_FIELDS = DIRECTORY_FIELDS + ("phone", "hire_date", "manager_id", "status")
ALL_FIELDS = MANAGER_FIELDS + ("address", "emergency_contact_name", "emergency_contact_phone", "salary_band")
FIELD_LABELS = {
    "employee_id": "Employee ID", "name": "Name", "email": "Email", "department": "Department",
    "job_title": "Job title", "location": "Location", "phone": "Phone", "hire_date": "Hire date",
    "manager_id": "Manager", "status": "Status", "address": "Address",
    "emergency_contact_name": "Emergency contact", "emergency_contact_phone": "Emergency contact phone",
    "salary_band": "Salary band",
}
# what an employee may change about themselves
SELF_EDITABLE = ("phone", "address", "emergency_contact_name", "emergency_contact_phone")
# what HR may change about anyone else (role / password are never editable from chat)
HR_EDITABLE = (
    "department", "job_title", "location", "email", "phone", "address",
    "emergency_contact_name", "emergency_contact_phone", "salary_band", "manager_id", "status",
)
_PROFILE_COLUMN = {  # whitelist: field -> employee_profile column
    "department": "department", "job_title": "job_title", "location": "location", "email": "email",
    "phone": "phone", "address": "address", "emergency_contact_name": "emergency_contact_name",
    "emergency_contact_phone": "emergency_contact_phone", "salary_band": "salary_band",
}
_TEXT_LIMITS = {
    "department": 40, "job_title": 60, "location": 60, "address": 150,
    "emergency_contact_name": 60,
}
_RE_PHONE = re.compile(r"^\+?[0-9][0-9 ()\-.]{5,19}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$")
_RE_BAND = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,11}$")
_BAD_CHARS = re.compile(r"[<>`\[\]{}\\|]")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def today() -> date:  # separate function so tests can pin the date
    return date.today()


# --------------------------------------------------------------------------- connection
@contextmanager
def hr_conn():
    """hr.db with auth.db attached as `auth`, so one transaction can touch both."""
    conn = sec.connect(sec.HR_DB)
    try:
        conn.execute("ATTACH DATABASE ? AS auth", (str(sec.AUTH_DB),))
        yield conn
    finally:
        conn.close()


def init_hr_db() -> None:
    sec.secure_runtime()
    conn = sec.connect(sec.HR_DB)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS employee_profile (
                employee_id TEXT PRIMARY KEY,
                email TEXT, phone TEXT,
                department TEXT NOT NULL DEFAULT 'Unassigned',
                job_title TEXT NOT NULL DEFAULT 'Employee',
                location TEXT, hire_date TEXT,
                address TEXT, emergency_contact_name TEXT, emergency_contact_phone TEXT,
                salary_band TEXT,
                updated_at REAL, updated_by TEXT
            );
            CREATE TABLE IF NOT EXISTS leave_allotments (
                employee_id TEXT NOT NULL, year INTEGER NOT NULL, leave_type TEXT NOT NULL, days REAL NOT NULL,
                PRIMARY KEY (employee_id, year, leave_type)
            );
            CREATE TABLE IF NOT EXISTS leave_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id TEXT NOT NULL,
                leave_type TEXT NOT NULL CHECK(leave_type IN ('annual','sick','casual','unpaid')),
                start_date TEXT NOT NULL, end_date TEXT NOT NULL, days REAL NOT NULL,
                reason TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','cancelled')),
                created_at REAL NOT NULL, decided_by TEXT, decided_at REAL, decision_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_leave_emp ON leave_requests(employee_id, status, end_date);
            CREATE TABLE IF NOT EXISTS holidays (date TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS user_prefs (
                employee_id TEXT PRIMARY KEY,
                theme TEXT NOT NULL DEFAULT 'light' CHECK(theme IN ('light','dark'))
            );
            """
        )
        conn.commit()
    finally:
        conn.close()
    sec.harden(sec.HR_DB, 0o600)


# --------------------------------------------------------------------------- validation helpers
def clean_text(value, maxlen: int) -> Optional[str]:
    """Collapse whitespace, reject control/markup characters. Returns None if unacceptable."""
    v = " ".join(_CTRL.sub(" ", str(value or "")).split())
    if not v or len(v) > maxlen or _BAD_CHARS.search(v):
        return None
    return v


def validate_field(field: str, value: str):
    """Return (clean_value, error)."""
    if field == "phone" or field == "emergency_contact_phone":
        v = " ".join(str(value or "").split())
        return (v, None) if _RE_PHONE.match(v) else (None, "That doesn't look like a valid phone number (6-20 digits, optional +).")
    if field == "email":
        v = str(value or "").strip()
        return (v.lower(), None) if _RE_EMAIL.match(v) else (None, "That doesn't look like a valid email address.")
    if field == "salary_band":
        v = str(value or "").strip().upper()
        return (v, None) if _RE_BAND.match(v) else (None, "Salary band can use up to 12 letters, digits, dots or dashes (for example B3).")
    if field == "status":
        v = str(value or "").strip().lower()
        v = {"inactive": "terminated"}.get(v, v)
        return (v, None) if v in ("active", "terminated") else (None, "Status must be 'active' or 'terminated'.")
    if field == "manager_id":
        v = str(value or "").strip()
        return (v, None) if re.fullmatch(r"[A-Za-z0-9_-]{2,20}", v) else (None, "Give the manager's Employee ID.")
    maxlen = _TEXT_LIMITS.get(field)
    if maxlen is None:
        return None, "That field can't be changed."
    v = clean_text(value, maxlen)
    return (v, None) if v else (None, f"Use up to {maxlen} plain characters (no brackets, <, >, or backslashes).")


# --------------------------------------------------------------------------- dates / leave maths
def _d(s: str) -> date:
    return date.fromisoformat(s)


def _holidays(conn) -> set:
    return {_d(r[0]) for r in conn.execute("SELECT date FROM holidays")}


def is_working_day(d: date, hol: set) -> bool:
    return d.weekday() < 5 and d not in hol


def count_working_days(start: date, end: date, hol: set) -> int:
    n, d = 0, start
    while d <= end:
        n += is_working_day(d, hol)
        d += timedelta(days=1)
    return n


def next_working_day(d: date, hol: set) -> date:
    d += timedelta(days=1)
    while not is_working_day(d, hol):
        d += timedelta(days=1)
    return d


def advance_working_days(start: date, n: int, hol: set) -> date:
    """The date on which the n-th working day, counting `start` if it is one, falls."""
    d, count = start, 0
    while True:
        if is_working_day(d, hol):
            count += 1
            if count >= n:
                return d
        d += timedelta(days=1)


# --------------------------------------------------------------------------- people
def _row_to_person(r) -> dict:
    keys = ("employee_id", "name", "role", "manager_id", "active", "email", "phone", "department", "job_title",
            "location", "hire_date", "address", "emergency_contact_name", "emergency_contact_phone", "salary_band")
    p = dict(zip(keys, r))
    p["active"] = bool(p["active"])
    p["status"] = "active" if p["active"] else "terminated"
    return p


_PERSON_SQL = (
    "SELECT a.employee_id, a.name, a.role, a.manager_id, a.active, p.email, p.phone, p.department, p.job_title, "
    "p.location, p.hire_date, p.address, p.emergency_contact_name, p.emergency_contact_phone, p.salary_band "
    "FROM auth.employees a LEFT JOIN employee_profile p ON p.employee_id = a.employee_id"
)


def get_person(employee_id: str) -> Optional[dict]:
    with hr_conn() as conn:
        r = conn.execute(_PERSON_SQL + " WHERE a.employee_id = ?", (employee_id,)).fetchone()
    return _row_to_person(r) if r else None


def all_people() -> list:
    """Every employee with full profile fields. Used by the bulk importer; not exposed to chat."""
    with hr_conn() as conn:
        rows = conn.execute(_PERSON_SQL + " ORDER BY a.employee_id").fetchall()
    return [_row_to_person(r) for r in rows]


def list_people(include_inactive: bool = False) -> list:
    sql = "SELECT a.employee_id, a.name, a.active FROM auth.employees a"
    if not include_inactive:
        sql += " WHERE a.active = 1"
    with hr_conn() as conn:
        rows = conn.execute(sql + " ORDER BY a.employee_id").fetchall()
    return [{"employee_id": r[0], "name": r[1], "active": bool(r[2])} for r in rows]


def _actor(actor_id: str) -> Optional[dict]:
    u = sec.get_user(actor_id)
    return u if u and u["active"] else None


def visible_fields(actor: dict, target: dict) -> tuple:
    if actor["employee_id"] == target["employee_id"] or actor["role"] == "hr_admin":
        return ALL_FIELDS
    if target.get("manager_id") == actor["employee_id"]:
        return MANAGER_FIELDS
    return DIRECTORY_FIELDS


def can_see_leave_detail(actor: dict, target: dict) -> bool:
    """Leave *type* is private; dates and return date are directory-level."""
    return (actor["employee_id"] == target["employee_id"] or actor["role"] == "hr_admin"
            or target.get("manager_id") == actor["employee_id"])


def can_see_person(actor: dict, target: dict) -> bool:
    return target["active"] or actor["role"] == "hr_admin"


def get_profile(actor_id: str, target_id: str):
    """Return (True, {field: value}) filtered by what the actor may see, or (False, message)."""
    actor = _actor(actor_id)
    target = get_person(target_id)
    if not actor or not target or not can_see_person(actor, target):
        return False, "I couldn't find that employee."
    fields = visible_fields(actor, target)
    out = {f: target.get(f) for f in fields}
    if "manager_id" in out and out["manager_id"]:
        m = get_person(out["manager_id"])
        out["manager_id"] = f"{m['name']} ({m['employee_id']})" if m else out["manager_id"]
    if actor_id != target_id:
        audit(actor_id, "profile_view", target=target_id, detail=f"level={'full' if fields == ALL_FIELDS else 'manager' if fields == MANAGER_FIELDS else 'directory'}")
    return True, {"fields": out, "restricted": fields != ALL_FIELDS}


def direct_reports(actor_id: str) -> list:
    with hr_conn() as conn:
        rows = conn.execute(
            "SELECT a.employee_id, a.name, p.job_title FROM auth.employees a LEFT JOIN employee_profile p "
            "ON p.employee_id=a.employee_id WHERE a.manager_id=? AND a.active=1 ORDER BY a.name", (actor_id,)
        ).fetchall()
    return [{"employee_id": r[0], "name": r[1], "job_title": r[2]} for r in rows]


# --------------------------------------------------------------------------- leave: blocks and lookups
def _blocks(conn, employee_id: str, since: date) -> list:
    """Approved leave merged into continuous blocks (Fri + following Mon count as one absence)."""
    hol = _holidays(conn)
    rows = conn.execute(
        "SELECT start_date, end_date, leave_type FROM leave_requests WHERE employee_id=? AND status='approved' "
        "AND end_date >= ? ORDER BY start_date",
        (employee_id, (since - timedelta(days=10)).isoformat()),
    ).fetchall()
    blocks = []
    for s, e, t in rows:
        s, e = _d(s), _d(e)
        if blocks and s <= next_working_day(blocks[-1]["end"], hol):
            blocks[-1]["end"] = max(blocks[-1]["end"], e)
            blocks[-1]["types"].add(t)
        else:
            blocks.append({"start": s, "end": e, "types": {t}})
    for b in blocks:
        b["return_date"] = next_working_day(b["end"], hol)
    return blocks


def current_leave(employee_id: str, on: Optional[date] = None) -> Optional[dict]:
    on = on or today()
    with hr_conn() as conn:
        for b in _blocks(conn, employee_id, on):
            if b["start"] <= on <= b["end"]:
                return b
    return None


def next_leave(employee_id: str, on: Optional[date] = None) -> Optional[dict]:
    on = on or today()
    with hr_conn() as conn:
        for b in _blocks(conn, employee_id, on):
            if b["start"] > on:
                return b
    return None


def who_on_leave(start: date, end: Optional[date] = None) -> list:
    """Active employees with approved leave overlapping [start, end]. Directory-level info only."""
    end = end or start
    out = []
    with hr_conn() as conn:
        ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT l.employee_id FROM leave_requests l JOIN auth.employees a ON a.employee_id=l.employee_id "
            "WHERE l.status='approved' AND a.active=1 AND l.start_date <= ? AND l.end_date >= ?",
            (end.isoformat(), start.isoformat()),
        )]
        for eid in ids:
            for b in _blocks(conn, eid, start):
                if b["start"] <= end and b["end"] >= start:
                    r = conn.execute(
                        "SELECT a.name, p.department FROM auth.employees a LEFT JOIN employee_profile p ON p.employee_id=a.employee_id "
                        "WHERE a.employee_id=?", (eid,)).fetchone()
                    out.append({"employee_id": eid, "name": r[0], "department": r[1], **b})
                    break
    return sorted(out, key=lambda x: (x["return_date"], x["name"]))


# --------------------------------------------------------------------------- leave: balances / requests
def _allotment(conn, employee_id: str, year: int, leave_type: str) -> float:
    r = conn.execute("SELECT days FROM leave_allotments WHERE employee_id=? AND year=? AND leave_type=?",
                     (employee_id, year, leave_type)).fetchone()
    return float(r[0]) if r else DEFAULT_ALLOTMENT[leave_type]


def _sum_days(conn, employee_id: str, leave_type: str, year: int, status: str) -> float:
    r = conn.execute(
        "SELECT COALESCE(SUM(days),0) FROM leave_requests WHERE employee_id=? AND leave_type=? AND status=? "
        "AND substr(start_date,1,4)=?", (employee_id, leave_type, status, str(year))).fetchone()
    return float(r[0])


def leave_balance(employee_id: str, year: Optional[int] = None) -> dict:
    year = year or today().year
    out = {}
    with hr_conn() as conn:
        for t in DEFAULT_ALLOTMENT:
            allot = _allotment(conn, employee_id, year, t)
            used = _sum_days(conn, employee_id, t, year, "approved")
            pend = _sum_days(conn, employee_id, t, year, "pending")
            out[t] = {"allotted": allot, "used": used, "pending": pend, "available": allot - used - pend}
    return out


def _row_request(r) -> dict:
    return {"id": r[0], "employee_id": r[1], "leave_type": r[2], "start": _d(r[3]), "end": _d(r[4]),
            "days": r[5], "reason": r[6], "status": r[7]}


_REQ_SQL = "SELECT id, employee_id, leave_type, start_date, end_date, days, reason, status FROM leave_requests"


def request_leave(actor_id: str, leave_type: str, start: date, end: date, reason: Optional[str] = None):
    """Create a pending request. Returns (ok, message, request_id)."""
    actor = _actor(actor_id)
    if not actor:
        return False, "Your account isn't active.", None
    if leave_type not in LEAVE_TYPES:
        return False, "Unknown leave type.", None
    if end < start:
        return False, "The end date is before the start date.", None
    t = today()
    if start < t - timedelta(days=BACKDATE_LIMIT_DAYS):
        return False, f"Leave can only be backdated by up to {BACKDATE_LIMIT_DAYS} days. Please contact HR.", None
    if end > t + timedelta(days=MAX_FUTURE_DAYS):
        return False, "That's more than a year ahead. Please choose nearer dates.", None
    if (end - start).days + 1 > MAX_LEAVE_CALENDAR_DAYS:
        return False, f"A single request can cover at most {MAX_LEAVE_CALENDAR_DAYS} days. Please split it or contact HR.", None
    if start.year != end.year:
        return False, "Please submit separate requests for each calendar year.", None
    reason_clean = None
    if reason:
        reason_clean = clean_text(reason, 200)
        if reason_clean is None:
            return False, "The reason is too long or has characters that aren't allowed (max 200).", None
    with hr_conn() as conn:
        hol = _holidays(conn)
        days = float(count_working_days(start, end, hol))
        if days == 0:
            return False, "That range has no working days (weekends and company holidays don't count).", None
        clash = conn.execute(
            "SELECT id, start_date, end_date FROM leave_requests WHERE employee_id=? AND status IN ('pending','approved') "
            "AND start_date <= ? AND end_date >= ?", (actor_id, end.isoformat(), start.isoformat())).fetchone()
        if clash:
            return False, f"That overlaps with your leave request #{clash[0]} ({clash[1]} to {clash[2]}).", None
        if leave_type != "unpaid":
            allot = _allotment(conn, actor_id, start.year, leave_type)
            used = _sum_days(conn, actor_id, leave_type, start.year, "approved") + _sum_days(conn, actor_id, leave_type, start.year, "pending")
            if days > allot - used:
                return False, (f"That needs {days:g} working day(s) of {leave_type} leave but only {max(allot - used, 0):g} "
                               f"{'is' if allot - used == 1 else 'are'} available for {start.year}."), None
        with conn:
            cur = conn.execute(
                "INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, days, reason, status, created_at) "
                "VALUES (?,?,?,?,?,?, 'pending', ?)",
                (actor_id, leave_type, start.isoformat(), end.isoformat(), days, reason_clean, time.time()))
        rid = cur.lastrowid
    audit(actor_id, "leave_requested", target=str(rid), detail=f"{leave_type} {start}..{end} ({days:g}d)")
    return True, f"Leave request #{rid} submitted for approval ({days:g} working day(s)).", rid


def _can_decide(actor: dict, requester_id: str, requester_manager: Optional[str]) -> bool:
    if actor["employee_id"] == requester_id:
        return False  # nobody approves their own leave
    return actor["role"] == "hr_admin" or actor["employee_id"] == requester_manager


def decide_leave(actor_id: str, request_id: int, approve: bool, note: Optional[str] = None):
    actor = _actor(actor_id)
    if not actor:
        return False, "Your account isn't active."
    note_clean = clean_text(note, 200) if note else None
    with hr_conn() as conn:
        r = conn.execute(
            "SELECT l.employee_id, l.status, a.manager_id, l.start_date, l.end_date FROM leave_requests l "
            "JOIN auth.employees a ON a.employee_id=l.employee_id WHERE l.id=?", (request_id,)).fetchone()
        if not r:
            return False, f"I couldn't find leave request #{request_id}."
        if not _can_decide(actor, r[0], r[2]):
            audit(actor_id, "leave_decision", target=str(request_id), outcome="denied")
            return False, "You can't decide that request. Requests are approved by the employee's manager or an HR admin, never by the employee."
        if r[1] != "pending":
            return False, f"Request #{request_id} is already {r[1]}."
        with conn:
            cur = conn.execute(
                "UPDATE leave_requests SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE id=? AND status='pending'",
                ("approved" if approve else "rejected", actor_id, time.time(), note_clean, request_id))
        if cur.rowcount != 1:
            return False, "That request was just changed by someone else."
    audit(actor_id, "leave_approved" if approve else "leave_rejected", target=str(request_id), detail=f"employee={r[0]}")
    return True, f"Request #{request_id} {'approved' if approve else 'rejected'}."


def cancel_leave(actor_id: str, request_id: int):
    actor = _actor(actor_id)
    if not actor:
        return False, "Your account isn't active."
    t = today()
    with hr_conn() as conn:
        r = conn.execute("SELECT employee_id, status, start_date, end_date FROM leave_requests WHERE id=?", (request_id,)).fetchone()
        if not r or (r[0] != actor_id and actor["role"] != "hr_admin"):
            return False, f"I couldn't find a leave request #{request_id} that you can cancel."
        if r[1] not in ("pending", "approved"):
            return False, f"Request #{request_id} is already {r[1]}."
        if _d(r[2]) < t and r[1] == "approved" and actor["role"] != "hr_admin":
            return False, "Leave that has already started can only be changed by HR."
        if _d(r[3]) < t:
            return False, "That leave has already ended."
        with conn:
            conn.execute("UPDATE leave_requests SET status='cancelled', decided_by=?, decided_at=? WHERE id=?",
                         (actor_id, time.time(), request_id))
    audit(actor_id, "leave_cancelled", target=str(request_id), detail=f"employee={r[0]}")
    return True, f"Request #{request_id} cancelled."


def my_requests(actor_id: str, limit: int = 8) -> list:
    with hr_conn() as conn:
        rows = conn.execute(_REQ_SQL + " WHERE employee_id=? ORDER BY id DESC LIMIT ?", (actor_id, limit)).fetchall()
    return [_row_request(r) for r in rows]


def pending_for_approval(actor_id: str) -> list:
    """Requests this person may decide, oldest start first. Each carries context for the decision:
    the requester's department, what is left of that leave type once this request is granted, and
    which department colleagues are already away on those dates."""
    actor = _actor(actor_id)
    if not actor or actor["role"] not in ("hr_admin", "manager"):
        return []
    base = ("SELECT l.id, l.employee_id, l.leave_type, l.start_date, l.end_date, l.days, l.reason, l.status, a.name "
            "FROM leave_requests l JOIN auth.employees a ON a.employee_id=l.employee_id WHERE l.status='pending' AND ")
    out = []
    with hr_conn() as conn:
        if actor["role"] == "hr_admin":
            rows = conn.execute(base + "l.employee_id != ? ORDER BY l.start_date LIMIT 50", (actor_id,)).fetchall()
        else:
            rows = conn.execute(base + "a.manager_id=? ORDER BY l.start_date LIMIT 50", (actor_id,)).fetchall()
        for r in rows:
            req = {**_row_request(r[:8]), "name": r[8], "department": None, "remaining": None, "also_away": []}
            d = conn.execute("SELECT department FROM employee_profile WHERE employee_id=?", (req["employee_id"],)).fetchone()
            req["department"] = d[0] if d else None
            if req["leave_type"] != "unpaid":
                year = req["start"].year
                used = _sum_days(conn, req["employee_id"], req["leave_type"], year, "approved")
                held = _sum_days(conn, req["employee_id"], req["leave_type"], year, "pending")
                req["remaining"] = _allotment(conn, req["employee_id"], year, req["leave_type"]) - used - held
            if req["department"]:
                req["also_away"] = [n[0] for n in conn.execute(
                    "SELECT DISTINCT a.name FROM leave_requests l JOIN auth.employees a ON a.employee_id=l.employee_id "
                    "JOIN employee_profile p ON p.employee_id=l.employee_id WHERE l.status='approved' AND a.active=1 "
                    "AND p.department=? AND l.employee_id != ? AND l.start_date <= ? AND l.end_date >= ? ORDER BY a.name LIMIT 5",
                    (req["department"], req["employee_id"], req["end"].isoformat(), req["start"].isoformat()))]
            out.append(req)
    return out


def leave_days_by_month(employee_id: str, year: Optional[int] = None) -> list:
    """Approved working days of leave in each month of `year` (12 numbers)."""
    year = year or today().year
    out = [0.0] * 12
    with hr_conn() as conn:
        hol = _holidays(conn)
        rows = conn.execute(
            "SELECT start_date, end_date FROM leave_requests WHERE employee_id=? AND status='approved' "
            "AND start_date <= ? AND end_date >= ?", (employee_id, f"{year}-12-31", f"{year}-01-01")).fetchall()
    for s_, e_ in rows:
        d, end = max(_d(s_), date(year, 1, 1)), min(_d(e_), date(year, 12, 31))
        while d <= end:
            if is_working_day(d, hol):
                out[d.month - 1] += 1
            d += timedelta(days=1)
    return out


THEMES = ("light", "dark")


def get_theme(employee_id: str) -> str:
    with hr_conn() as conn:
        r = conn.execute("SELECT theme FROM user_prefs WHERE employee_id=?", (employee_id,)).fetchone()
    return r[0] if r and r[0] in THEMES else "light"


def set_theme(employee_id: str, theme: str) -> bool:
    if theme not in THEMES or not sec.get_user(employee_id):
        return False
    with hr_conn() as conn:
        with conn:
            conn.execute("INSERT INTO user_prefs (employee_id, theme) VALUES (?,?) "
                         "ON CONFLICT(employee_id) DO UPDATE SET theme=excluded.theme", (employee_id, theme))
    return True


# --------------------------------------------------------------------------- profile updates
def _creates_cycle(conn, employee_id: str, new_manager: str) -> bool:
    seen, cur = set(), new_manager
    while cur and cur not in seen:
        if cur == employee_id:
            return True
        seen.add(cur)
        r = conn.execute("SELECT manager_id FROM auth.employees WHERE employee_id=?", (cur,)).fetchone()
        cur = r[0] if r else None
    return False


def update_profile(actor_id: str, target_id: str, changes: dict, via: str = "chat"):
    """Apply {field: value}. Permission, validation and audit all happen here. Returns (ok, message)."""
    actor = _actor(actor_id)
    if not actor:
        return False, "Your account isn't active."
    target = get_person(target_id)
    if not target or (not target["active"] and actor["role"] != "hr_admin"):
        return False, "I couldn't find that employee."
    is_self = actor_id == target_id
    is_hr = actor["role"] == "hr_admin"
    if not changes:
        return False, "Nothing to change."
    allowed = set(SELF_EDITABLE) if is_self else (set(HR_EDITABLE) if is_hr else set())
    denied = [f for f in changes if f not in allowed]
    if denied:
        audit(actor_id, "profile_update", target=target_id, outcome="denied", detail="fields=" + ",".join(sorted(denied)))
        if is_self:
            return False, ("You can update your phone, address and emergency contact yourself. "
                           "Other details, including your own job title, department, manager and status, must be changed by another HR admin.")
        return False, "Only HR admins can change other employees' records."

    clean = {}
    for f, v in changes.items():
        val, err = validate_field(f, v)
        if err:
            return False, err
        clean[f] = val

    with hr_conn() as conn:
        if "email" in clean:
            dup = conn.execute("SELECT employee_id FROM employee_profile WHERE lower(email)=? AND employee_id != ?",
                               (clean["email"], target_id)).fetchone()
            if dup:
                return False, "Another employee already uses that email address."
        if "manager_id" in clean:
            m = conn.execute("SELECT active FROM auth.employees WHERE employee_id=?", (clean["manager_id"],)).fetchone()
            if not m or not m[0]:
                return False, "I couldn't find an active employee with that ID to be the manager."
            if clean["manager_id"] == target_id or _creates_cycle(conn, target_id, clean["manager_id"]):
                return False, "That would make someone their own manager (directly or indirectly)."
        if clean.get("status") == "terminated":
            if is_self:
                return False, "You can't deactivate your own record."
            if target["role"] == "hr_admin":
                n = conn.execute("SELECT COUNT(*) FROM auth.employees WHERE role='hr_admin' AND active=1").fetchone()[0]
                if n <= 1:
                    return False, "That is the last active HR admin, so it can't be deactivated."
        with conn:
            conn.execute("INSERT OR IGNORE INTO employee_profile (employee_id) VALUES (?)", (target_id,))
            for f, v in clean.items():
                if f in _PROFILE_COLUMN:
                    col = _PROFILE_COLUMN[f]  # from whitelist
                    conn.execute(f"UPDATE employee_profile SET {col}=?, updated_at=?, updated_by=? WHERE employee_id=?",
                                 (v, time.time(), actor_id, target_id))
            if "manager_id" in clean:
                conn.execute("UPDATE auth.employees SET manager_id=? WHERE employee_id=?", (clean["manager_id"], target_id))
            if "status" in clean:
                conn.execute("UPDATE auth.employees SET active=?, session_epoch=session_epoch+1 WHERE employee_id=?",
                             (1 if clean["status"] == "active" else 0, target_id))
    private = {"address", "phone", "emergency_contact_name", "emergency_contact_phone", "salary_band", "email"}
    detail = "; ".join(
        f"{f}: changed" if f in private else f"{f}: {str(target.get(f))[:40]} -> {str(v)[:40]}" for f, v in clean.items())
    audit(actor_id, "profile_update", target=target_id, detail=f"via={via}; {detail}")
    return True, "Updated " + ", ".join(FIELD_LABELS[f].lower() for f in clean) + "."


# --------------------------------------------------------------------------- bootstrap + synthetic data
_FIXED = [  # id, name, role, department, title, manager, band
    ("E001", "Alice Admin", "hr_admin", "HR", "HR Director", None, "B5"),
    ("E002", "Bob Manager", "manager", "Engineering", "Engineering Manager", None, "B4"),
    ("E003", "Carol Employee", "employee", "Engineering", "Software Engineer", "E002", "B2"),
    ("E004", "Dana Whitfield", "hr_admin", "HR", "HR Business Partner", "E001", "B3"),
    ("E005", "Priya Nair", "manager", "Finance", "Finance Manager", None, "B4"),
    ("E006", "Liam Johnson", "manager", "Sales", "Sales Manager", None, "B4"),
    ("E007", "Sofia Rossi", "manager", "Marketing", "Marketing Manager", None, "B4"),
    ("E008", "Omar Haddad", "manager", "Operations", "Operations Manager", None, "B4"),
]
_DEPT_MANAGER = {"Engineering": "E002", "Finance": "E005", "Sales": "E006", "Marketing": "E007", "Operations": "E008", "HR": "E001"}
_TITLES = {
    "Engineering": ["Software Engineer", "QA Engineer", "DevOps Engineer", "Data Engineer"],
    "Finance": ["Accountant", "Financial Analyst", "Payroll Specialist"],
    "Sales": ["Account Executive", "Sales Associate", "Business Development Rep"],
    "Marketing": ["Content Strategist", "Brand Designer", "Marketing Analyst"],
    "Operations": ["Operations Analyst", "Logistics Coordinator", "Facilities Lead"],
    "HR": ["Recruiter", "HR Generalist", "Learning Partner"],
}
_FIRST = ["Aarav", "Noah", "Mei", "Elena", "Kofi", "Hannah", "Diego", "Yuki", "Sven", "Amara", "Ravi", "Chloe",
          "Mateo", "Isha", "Tariq", "Nora", "Lucas", "Fatima", "Ethan", "Zara", "Jonas", "Leila"]
_LAST = ["Sharma", "Chen", "Okafor", "Petrova", "Mensah", "Schmidt", "Alvarez", "Tanaka", "Lindgren", "Patel", "Dubois",
         "Silva", "Mehta", "Rahman", "Larsen", "Costa", "Ahmed", "Brown", "Khan", "Novak", "Reyes", "Fischer"]
_CITIES = ["New Delhi", "Bengaluru", "London", "Berlin", "New York", "Remote"]
_DEPT_CYCLE = ["Engineering", "Finance", "Sales", "Marketing", "Operations", "Engineering", "Sales", "HR", "Operations", "Engineering", "Marketing"]


def _seed_holidays(conn) -> None:
    y = today().year
    for yr in (y - 1, y, y + 1):
        for md, name in (("01-01", "New Year's Day"), ("05-01", "Labour Day"), ("08-15", "Independence Day"),
                         ("10-02", "Founders' Day"), ("12-25", "Year-end Holiday")):
            conn.execute("INSERT OR IGNORE INTO holidays (date, name) VALUES (?,?)", (f"{yr}-{md}", name))


def seed_synthetic_data() -> list:
    """Create ~30 fictional employees, balances and leave. Returns [(id, one-time password)] for new accounts."""
    rng = random.Random(42)
    t = today()
    people = [dict(id=i, name=n, role=r, dept=d, title=ti, mgr=m, band=b) for i, n, r, d, ti, m, b in _FIXED]
    for k in range(22):  # E009..E030
        dept = _DEPT_CYCLE[k % len(_DEPT_CYCLE)]
        people.append(dict(id=f"E{9 + k:03d}", name=f"{_FIRST[k]} {_LAST[k]}", role="employee", dept=dept,
                           title=_TITLES[dept][k % len(_TITLES[dept])], mgr=_DEPT_MANAGER[dept], band=f"B{rng.randint(1, 3)}"))
    creds = []
    existing = {u["employee_id"] for u in list_people(include_inactive=True)}
    for p in people:
        if p["id"] not in existing:
            pw = secrets.token_urlsafe(12)
            sec.create_employee(p["id"], p["name"], pw, role=p["role"], manager_id=p["mgr"], must_change=True)
            creds.append((p["id"], pw))
    with hr_conn() as conn:
        with conn:
            for idx, p in enumerate(people):
                first = p["name"].split()[0].lower()
                last = p["name"].split()[-1].lower()
                hired = t - timedelta(days=rng.randint(90, 3300))
                conn.execute(
                    "INSERT OR IGNORE INTO employee_profile (employee_id, email, phone, department, job_title, location, hire_date, "
                    "address, emergency_contact_name, emergency_contact_phone, salary_band, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (p["id"], f"{first}.{last}@globalcorp.example", f"+1-555-01{idx:02d}", p["dept"], p["title"],
                     _CITIES[idx % len(_CITIES)], hired.isoformat(),
                     f"{rng.randint(10, 999)} Sample Street, Testville (synthetic)",
                     f"{_FIRST[(idx + 7) % len(_FIRST)]} {_LAST[(idx + 3) % len(_LAST)]}", f"+1-555-02{idx:02d}",
                     p["band"], time.time(), "seed"))
                for lt, days in DEFAULT_ALLOTMENT.items():
                    conn.execute("INSERT OR IGNORE INTO leave_allotments VALUES (?,?,?,?)", (p["id"], t.year, lt, days))
            _seed_holidays(conn)
            hol = _holidays(conn)

            def leave(eid, ltype, s_off, e_off, status, reason=None):
                s, e = t + timedelta(days=s_off), t + timedelta(days=e_off)
                days = count_working_days(s, e, hol)
                if days:
                    conn.execute(
                        "INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, days, reason, status, created_at, decided_by, decided_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (eid, ltype, s.isoformat(), e.isoformat(), float(days), reason, status, time.time(),
                         None if status == "pending" else "E001", None if status == "pending" else time.time()))

            # on leave right now
            leave("E003", "annual", -1, 3, "approved", "Family trip")
            leave("E011", "sick", -3, 2, "approved")
            leave("E014", "annual", 0, 7, "approved")
            leave("E019", "casual", -5, 1, "approved")
            # back-to-back blocks (tests the merged return date)
            leave("E016", "annual", -2, 2, "approved")
            leave("E016", "casual", 5, 8, "approved")
            # upcoming, past, pending, rejected
            leave("E023", "annual", 3, 6, "approved")
            leave("E026", "annual", 10, 14, "approved")
            leave("E009", "annual", -30, -26, "approved")
            leave("E030", "sick", -20, -19, "approved")
            leave("E012", "annual", 14, 16, "pending", "Wedding")
            leave("E017", "casual", 5, 5, "pending")
            leave("E021", "annual", -10, -8, "rejected")
    sec.harden(sec.HR_DB, 0o600)
    audit("system", "synthetic_data_seeded", detail=f"{len(people)} employees, {len(creds)} new accounts")
    return creds


def bootstrap(seed_demo: Optional[bool] = None) -> list:
    """Idempotent start-up. Creates schemas, migrates old installs, and seeds demo data on an empty HR database.

    Demo seeding is on by default so the project works out of the box. For a real company set
    HR_SEED_DEMO=0 (the importer in manage.py never seeds demo data).
    """
    if seed_demo is None:
        seed_demo = os.environ.get("HR_SEED_DEMO", "1") != "0"
    sec.secure_runtime()
    rotated = sec.init_auth_db()
    init_hr_db()
    new_creds = []
    with hr_conn() as conn:
        empty = conn.execute("SELECT COUNT(*) FROM employee_profile").fetchone()[0] == 0
    if empty and seed_demo:
        new_creds = seed_synthetic_data()
        if new_creds:
            sec.write_credentials(new_creds, note="Synthetic demo accounts.")
    elif not empty:  # an older install: make sure every login has a profile row
        with hr_conn() as conn:
            with conn:
                conn.execute("INSERT OR IGNORE INTO employee_profile (employee_id) SELECT employee_id FROM auth.employees")
    sec.secure_runtime()
    return rotated + new_creds
