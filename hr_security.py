"""Authentication, sessions, MFA, audit log and file hardening for the HR assistant.

Standard library only. Nothing in here imports Streamlit, so it can be tested on its own.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import struct
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote

log = logging.getLogger("hr.security")

# --------------------------------------------------------------------------- paths
DATA_DIR = Path(os.environ.get("HR_DATA_DIR", "."))
AUTH_DB = DATA_DIR / "auth.db"
DB_DIR = DATA_DIR / "employee_dbs"
HR_DB = DB_DIR / "hr.db"
AUDIT_DB = DB_DIR / "audit.db"
CREDENTIALS_FILE = DATA_DIR / "initial_credentials.txt"

# --------------------------------------------------------------------------- tunables
PBKDF2_ITERS = 600_000            # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
LEGACY_ITERS = 200_000            # what the old app4.py used
MAX_FAILS = 5                     # failures before a temporary lock
LOCK_BASE_SECONDS = 30            # first lock; doubles each time, capped below
LOCK_MAX_SECONDS = 900
IDLE_TIMEOUT = int(os.environ.get("HR_IDLE_TIMEOUT_MIN", "30")) * 60
ABSOLUTE_TIMEOUT = int(os.environ.get("HR_SESSION_MAX_HOURS", "8")) * 3600
PENDING_AUTH_TTL = 300            # seconds to finish MFA / forced password change

GENERIC_FAIL = "Invalid Employee ID or Password."
LOCKED_MSG = "Too many failed attempts. Please wait a few minutes and try again."
VALID_ROLES = ("employee", "manager", "hr_admin")
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{2,20}$")


# --------------------------------------------------------------------------- filesystem
def harden(path, mode: int) -> None:
    """Best-effort chmod. Silently ignored where the OS does not support it."""
    try:
        os.chmod(path, mode)
    except (OSError, NotImplementedError):
        pass


def secure_runtime() -> None:
    """Private-by-default permissions for anything this process creates from now on."""
    try:
        os.umask(0o077)
    except (OSError, AttributeError):
        pass
    DB_DIR.mkdir(parents=True, exist_ok=True)
    harden(DB_DIR, 0o700)
    for p in (AUTH_DB, HR_DB, AUDIT_DB, CREDENTIALS_FILE):
        if Path(p).exists():
            harden(p, 0o600)


def connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# --------------------------------------------------------------------------- audit log
_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_GENESIS = "0" * 64


def _clip(value, n: int) -> str:
    return _CTRL.sub(" ", "" if value is None else str(value))[:n]


def _audit_hash(prev: str, ts: float, actor: str, action: str, target: str, outcome: str, detail: str) -> str:
    raw = "|".join([prev, f"{ts:.6f}", actor, action, target, outcome, detail])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def audit(actor, action, target=None, detail=None, outcome="ok") -> None:
    """Append one tamper-evident entry. Never raises: logging must not break the app.

    Never pass passwords, MFA codes or free-text personal data in `detail`.
    """
    try:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(AUDIT_DB), timeout=10, isolation_level=None)
        try:
            conn.executescript(_AUDIT_SCHEMA)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else _GENESIS
            ts = round(time.time(), 6)
            a, ac, tg, oc, dt = _clip(actor, 64), _clip(action, 64), _clip(target, 64), _clip(outcome, 16), _clip(detail, 500)
            h = _audit_hash(prev, ts, a, ac, tg, oc, dt)
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, target, outcome, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                (ts, a, ac, tg, oc, dt, prev, h),
            )
            conn.execute("COMMIT")
        finally:
            conn.close()
        harden(AUDIT_DB, 0o600)
    except Exception:  # pragma: no cover - last resort
        log.exception("audit write failed")


def verify_audit_chain():
    """Return (ok, entry_count, first_bad_id)."""
    if not AUDIT_DB.exists():
        return True, 0, None
    prev = _GENESIS
    n = 0
    with closing(connect(AUDIT_DB)) as conn:
        for (i, ts, actor, action, target, outcome, detail, p, h) in conn.execute(
            "SELECT id, ts, actor, action, target, outcome, detail, prev_hash, hash FROM audit_log ORDER BY id"
        ):
            n += 1
            expect = _audit_hash(prev, ts, actor, action, target or "", outcome, detail or "")
            if p != prev or h != expect:
                return False, n, i
            prev = h
    return True, n, None


def recent_audit(limit: int = 50):
    if not AUDIT_DB.exists():
        return []
    with closing(connect(AUDIT_DB)) as conn:
        rows = conn.execute(
            "SELECT ts, actor, action, target, outcome, detail FROM audit_log ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [
        {
            "time": datetime.fromtimestamp(r[0]).strftime("%Y-%m-%d %H:%M:%S"),
            "actor": r[1], "action": r[2], "target": r[3] or "", "result": r[4], "detail": r[5] or "",
        }
        for r in rows
    ]


# --------------------------------------------------------------------------- passwords
def hash_password(password: str, salt: Optional[bytes] = None, iters: Optional[int] = None) -> str:
    iters = iters or PBKDF2_ITERS
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"


def _split(stored: str, salt_col: str):
    if stored.startswith("pbkdf2_sha256$"):
        _, it, salt, digest = stored.split("$")
        return int(it), bytes.fromhex(salt), digest
    return LEGACY_ITERS, bytes.fromhex(salt_col), stored  # legacy: separate salt column


def verify_password(salt_col: str, stored: str, password: str) -> bool:
    try:
        iters, salt, digest = _split(stored, salt_col)
        cand = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters).hex()
    except Exception:
        return False
    return hmac.compare_digest(cand, digest)


def needs_rehash(stored: str) -> bool:
    return (not stored.startswith("pbkdf2_sha256$")) or int(stored.split("$")[1]) < PBKDF2_ITERS


_DUMMY: Optional[str] = None


def _burn(password: str) -> None:
    """Spend the same CPU as a real check so unknown IDs and real IDs take equal time."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("burn-" + secrets.token_hex(8))
    verify_password("", _DUMMY, password)


_COMMON_FRAGMENTS = ("changeme", "password", "qwerty", "letmein", "welcome", "globalcorp", "123456", "iloveyou", "admin")


def validate_new_password(pw: str, employee_id: str = "", name: str = "") -> Optional[str]:
    """Return an error message, or None if the password is acceptable."""
    if not isinstance(pw, str) or len(pw) < 12:
        return "Use at least 12 characters."
    if len(pw) > 128:
        return "Use at most 128 characters."
    low = pw.lower()
    if any(f in low for f in _COMMON_FRAGMENTS):
        return "That password is too easy to guess. Avoid common words and patterns."
    if employee_id and employee_id.lower() in low:
        return "Your password must not contain your Employee ID."
    for part in re.findall(r"[A-Za-z]{4,}", name or ""):
        if part.lower() in low:
            return "Your password must not contain your name."
    if len(set(pw)) < 6:
        return "Use a more varied password."
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 3 and len(pw) < 16:
        return "Mix upper and lower case, numbers and symbols, or use 16 or more characters."
    return None


# --------------------------------------------------------------------------- schema / users
_NEW_COLUMNS = {
    "active": "INTEGER NOT NULL DEFAULT 1",
    "must_change": "INTEGER NOT NULL DEFAULT 0",
    "session_epoch": "INTEGER NOT NULL DEFAULT 0",
    "mfa_secret": "TEXT",
    "mfa_enabled": "INTEGER NOT NULL DEFAULT 0",
    "mfa_last_step": "INTEGER NOT NULL DEFAULT 0",
    "last_login": "REAL",
    "pw_changed": "REAL",
}
_USER_SQL = "SELECT employee_id, name, role, manager_id, active, must_change, session_epoch, mfa_enabled FROM employees"


def _user(r) -> dict:
    return {
        "employee_id": r[0], "name": r[1], "role": r[2], "manager_id": r[3],
        "active": bool(r[4]), "must_change": bool(r[5]), "epoch": r[6], "mfa_enabled": bool(r[7]),
    }


def get_user(employee_id: str) -> Optional[dict]:
    with closing(connect(AUTH_DB)) as conn:
        r = conn.execute(_USER_SQL + " WHERE employee_id = ?", (employee_id,)).fetchone()
    return _user(r) if r else None


def init_auth_db() -> list:
    """Create / migrate auth.db. Returns [(employee_id, temp_password)] for any rotated accounts."""
    secure_runtime()
    with closing(connect(AUTH_DB)) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS employees (
                employee_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('employee','manager','hr_admin')),
                manager_id TEXT,
                salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until REAL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                key TEXT PRIMARY KEY,
                fails INTEGER NOT NULL DEFAULT 0,
                level INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0,
                updated REAL NOT NULL
            );
            """
        )
        have = {r[1] for r in conn.execute("PRAGMA table_info(employees)")}
        for col, ddl in _NEW_COLUMNS.items():  # constants only, never user input
            if col not in have:
                conn.execute(f"ALTER TABLE employees ADD COLUMN {col} {ddl}")
        conn.commit()
    harden(AUTH_DB, 0o600)
    return rotate_known_default_passwords()


def rotate_known_default_passwords() -> list:
    """Accounts created by the old app4.py still have ChangeMe!N. Replace those with random passwords."""
    rotated = []
    with closing(connect(AUTH_DB)) as conn:
        rows = conn.execute(
            "SELECT employee_id, salt, pw_hash FROM employees WHERE pw_hash NOT LIKE 'pbkdf2_sha256$%'"
        ).fetchall()
    for eid, salt, pw_hash in rows:  # legacy-format hashes only
        if any(verify_password(salt, pw_hash, f"ChangeMe!{n}") for n in (1, 2, 3)):
            temp = secrets.token_urlsafe(12)
            _set_password(eid, temp, must_change=True)
            rotated.append((eid, temp))
            audit("system", "default_password_rotated", target=eid)
    if rotated:
        write_credentials(rotated, note="Default passwords from the old version were replaced.")
    return rotated


def write_credentials(entries, note: str = "") -> None:
    """Append one-time passwords to a private file. Delete it after handing them out."""
    fd = os.open(str(CREDENTIALS_FILE), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(f"# {datetime.now():%Y-%m-%d %H:%M} {note}\n# One-time passwords: every user must change theirs at first sign-in.\n")
        for eid, pw in entries:
            f.write(f"{eid}\t{pw}\n")
    harden(CREDENTIALS_FILE, 0o600)


def _set_password(employee_id: str, password: str, must_change: bool) -> int:
    hashed = hash_password(password)
    salt = hashed.split("$")[2]
    with closing(connect(AUTH_DB)) as conn:
        conn.execute(
            "UPDATE employees SET salt=?, pw_hash=?, must_change=?, pw_changed=?, session_epoch=session_epoch+1 WHERE employee_id=?",
            (salt, hashed, int(must_change), time.time(), employee_id),
        )
        conn.commit()
        return conn.execute("SELECT session_epoch FROM employees WHERE employee_id=?", (employee_id,)).fetchone()[0]


def create_employee(employee_id, name, password, role="employee", manager_id=None, must_change=True) -> None:
    """Insert a new account. Refuses to overwrite an existing one (the old INSERT OR REPLACE was a backdoor)."""
    if not _ID_RE.match(employee_id or ""):
        raise ValueError("Invalid employee id")
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    hashed = hash_password(password)
    with closing(connect(AUTH_DB)) as conn:
        conn.execute(
            "INSERT INTO employees (employee_id, name, role, manager_id, salt, pw_hash, must_change, pw_changed) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (employee_id, name, role, manager_id, hashed.split("$")[2], hashed, int(must_change), time.time()),
        )
        conn.commit()


def user_count() -> int:
    with closing(connect(AUTH_DB)) as conn:
        return conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]


# --------------------------------------------------------------------------- lockout
def _lock_remaining(conn, key: str, now: float) -> float:
    r = conn.execute("SELECT locked_until FROM login_attempts WHERE key=?", (key,)).fetchone()
    return max(0.0, r[0] - now) if r else 0.0


def _record_failure(key: str) -> None:
    now = time.time()
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("DELETE FROM login_attempts WHERE updated < ? AND locked_until < ?", (now - 86400, now))
        r = conn.execute("SELECT fails, level, locked_until FROM login_attempts WHERE key=?", (key,)).fetchone()
        fails, level = (r[0], r[1]) if r else (0, 0)
        fails += 1
        locked_until = 0.0
        if fails >= MAX_FAILS:
            locked_until = now + min(LOCK_MAX_SECONDS, LOCK_BASE_SECONDS * (2 ** level))
            fails, level = 0, level + 1
        conn.execute(
            "INSERT INTO login_attempts (key, fails, level, locked_until, updated) VALUES (?,?,?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET fails=excluded.fails, level=excluded.level, "
            "locked_until=excluded.locked_until, updated=excluded.updated",
            (key, fails, level, locked_until, now),
        )
        conn.commit()


def _clear_failures(key: str) -> None:
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("DELETE FROM login_attempts WHERE key=?", (key,))
        conn.commit()


def clear_lock(employee_id: str) -> None:
    for prefix in ("pw:", "mfa:", "chg:"):
        _clear_failures(prefix + employee_id.lower())


# --------------------------------------------------------------------------- login
def next_stage(user: dict, mfa_verified: bool) -> str:
    if user["mfa_enabled"] and not mfa_verified:
        return "mfa"
    if user["must_change"]:
        return "change_password"
    return "done"


def authenticate(employee_id: str, password: str) -> dict:
    """Check credentials. Returns {"ok": bool, "error": str, "stage": str, "user": dict}.

    * Unknown IDs, wrong passwords and disabled accounts give the same message and cost the same CPU.
    * Failures are counted per ID string, whether or not the ID exists, so lockout does not reveal accounts.
    """
    eid = (employee_id or "").strip()[:64]
    pw = (password or "")[:256]
    key = "pw:" + eid.lower()
    with closing(connect(AUTH_DB)) as conn:
        locked = _lock_remaining(conn, key, time.time()) > 0
        row = conn.execute(_USER_SQL.replace("FROM employees", ", salt, pw_hash FROM employees") + " WHERE employee_id = ?", (eid,)).fetchone()
    if locked:
        _burn(pw)
        audit(eid or "-", "login_blocked", outcome="denied")
        return {"ok": False, "error": LOCKED_MSG}
    if row is None or not row[4]:
        _burn(pw)
        _record_failure(key)
        audit(eid or "-", "login_failed", outcome="denied", detail="unknown or disabled")
        return {"ok": False, "error": GENERIC_FAIL}
    user = _user(row[:8])
    salt, stored = row[8], row[9]
    if not verify_password(salt, stored, pw):
        _record_failure(key)
        audit(eid, "login_failed", outcome="denied", detail="bad password")
        return {"ok": False, "error": GENERIC_FAIL}
    _clear_failures(key)
    if needs_rehash(stored):
        _set_password_keep_flags(eid, pw)
        user = get_user(eid)
    audit(eid, "password_ok", detail="stage=" + next_stage(user, False))
    return {"ok": True, "user": user, "stage": next_stage(user, False)}


def _set_password_keep_flags(employee_id: str, password: str) -> None:
    """Upgrade an old hash to the current cost without bumping the session epoch."""
    hashed = hash_password(password)
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET salt=?, pw_hash=? WHERE employee_id=?", (hashed.split("$")[2], hashed, employee_id))
        conn.commit()


def finish_login(employee_id: str) -> dict:
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET last_login=? WHERE employee_id=?", (time.time(), employee_id))
        conn.commit()
    audit(employee_id, "login_success")
    return new_session(get_user(employee_id))


def change_password(employee_id: str, new_password: str, current_password: Optional[str] = None) -> dict:
    """current_password=None is only for the forced first-login change, after the caller authenticated this session."""
    with closing(connect(AUTH_DB)) as conn:
        row = conn.execute("SELECT name, salt, pw_hash, active FROM employees WHERE employee_id=?", (employee_id,)).fetchone()
    if not row or not row[3]:
        return {"ok": False, "error": "Unable to change the password."}
    if current_password is not None:
        key = "chg:" + employee_id.lower()
        with closing(connect(AUTH_DB)) as conn:
            if _lock_remaining(conn, key, time.time()) > 0:
                return {"ok": False, "error": LOCKED_MSG}
        if not verify_password(row[1], row[2], current_password[:256]):
            _record_failure(key)
            audit(employee_id, "password_change", outcome="denied", detail="wrong current password")
            return {"ok": False, "error": "Your current password is incorrect."}
        _clear_failures(key)
    err = validate_new_password(new_password, employee_id, row[0])
    if err:
        return {"ok": False, "error": err}
    if verify_password(row[1], row[2], new_password):
        return {"ok": False, "error": "Choose a password you are not already using."}
    epoch = _set_password(employee_id, new_password, must_change=False)
    audit(employee_id, "password_changed")
    return {"ok": True, "epoch": epoch}


def admin_reset_password(employee_id: str) -> Optional[str]:
    """Used by manage.py. Returns a one-time password, or None if the account does not exist."""
    if not get_user(employee_id):
        return None
    temp = secrets.token_urlsafe(12)
    _set_password(employee_id, temp, must_change=True)
    clear_lock(employee_id)
    audit("cli", "password_reset", target=employee_id)
    return temp


# --------------------------------------------------------------------------- TOTP (RFC 6238)
def totp_at(secret_b32: str, t: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper(), casefold=True)
    counter = int((time.time() if t is None else t) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30) -> Optional[int]:
    """Return the matching time-step number, or None."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    now = int(time.time() // step)
    for off in range(-window, window + 1):
        if hmac.compare_digest(totp_at(secret_b32, (now + off) * step), code):
            return now + off
    return None


def otpauth_uri(employee_id: str, secret: str) -> str:
    return f"otpauth://totp/GlobalCorp:{quote(employee_id)}?secret={secret}&issuer=GlobalCorp"


def start_mfa_enrollment(employee_id: str) -> str:
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET mfa_secret=?, mfa_enabled=0, mfa_last_step=0 WHERE employee_id=?", (secret, employee_id))
        conn.commit()
    audit(employee_id, "mfa_enroll_started")
    return secret


def pending_mfa_secret(employee_id: str) -> Optional[str]:
    with closing(connect(AUTH_DB)) as conn:
        r = conn.execute("SELECT mfa_secret, mfa_enabled FROM employees WHERE employee_id=?", (employee_id,)).fetchone()
    return r[0] if r and r[0] and not r[1] else None


def _check_mfa(employee_id: str, code: str, require_enabled: bool, key_prefix: str = "mfa:"):
    key = key_prefix + employee_id.lower()
    with closing(connect(AUTH_DB)) as conn:
        if _lock_remaining(conn, key, time.time()) > 0:
            return False, LOCKED_MSG
        r = conn.execute("SELECT mfa_secret, mfa_enabled, mfa_last_step FROM employees WHERE employee_id=?", (employee_id,)).fetchone()
    if not r or not r[0] or (require_enabled and not r[1]):
        return False, "Two-step verification is not set up."
    step = verify_totp(r[0], code)
    if step is None or step <= r[2]:  # wrong code, or the same code used twice
        _record_failure(key)
        audit(employee_id, "mfa_failed", outcome="denied")
        return False, "That code is not valid. Check your authenticator app and try again."
    _clear_failures(key)
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET mfa_last_step=? WHERE employee_id=?", (step, employee_id))
        conn.commit()
    return True, None


def verify_mfa_login(employee_id: str, code: str):
    ok, err = _check_mfa(employee_id, code, require_enabled=True)
    if ok:
        audit(employee_id, "mfa_ok")
    return ok, err


def confirm_mfa_enrollment(employee_id: str, code: str):
    ok, err = _check_mfa(employee_id, code, require_enabled=False)
    if not ok:
        return False, err
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET mfa_enabled=1 WHERE employee_id=?", (employee_id,))
        conn.commit()
    audit(employee_id, "mfa_enabled")
    return True, None


def disable_mfa(employee_id: str, password: str, code: str):
    with closing(connect(AUTH_DB)) as conn:
        r = conn.execute("SELECT salt, pw_hash FROM employees WHERE employee_id=?", (employee_id,)).fetchone()
    if not r or not verify_password(r[0], r[1], (password or "")[:256]):
        _record_failure("chg:" + employee_id.lower())
        audit(employee_id, "mfa_disable", outcome="denied", detail="bad password")
        return False, "Your password is incorrect."
    ok, err = _check_mfa(employee_id, code, require_enabled=True)
    if not ok:
        return False, err
    with closing(connect(AUTH_DB)) as conn:
        conn.execute("UPDATE employees SET mfa_enabled=0, mfa_secret=NULL, mfa_last_step=0 WHERE employee_id=?", (employee_id,))
        conn.commit()
    audit(employee_id, "mfa_disabled")
    return True, None


def reset_mfa(employee_id: str) -> bool:
    """Used by manage.py when someone loses their device."""
    if not get_user(employee_id):
        return False
    with closing(connect(AUTH_DB)) as conn:
        conn.execute(
            "UPDATE employees SET mfa_enabled=0, mfa_secret=NULL, mfa_last_step=0, session_epoch=session_epoch+1 WHERE employee_id=?",
            (employee_id,),
        )
        conn.commit()
    audit("cli", "mfa_reset", target=employee_id)
    return True


# --------------------------------------------------------------------------- sessions
def new_session(user: dict) -> dict:
    now = time.time()
    return {"employee_id": user["employee_id"], "epoch": user["epoch"], "login_at": now, "last_seen": now}


def validate_session(sess: dict):
    """Return (fresh_user, None) or (None, reason). Role and status are re-read from the DB every call."""
    try:
        now = time.time()
        if now - sess["last_seen"] > IDLE_TIMEOUT or now - sess["login_at"] > ABSOLUTE_TIMEOUT:
            return None, "expired"
        user = get_user(sess["employee_id"])
        if not user or not user["active"] or user["epoch"] != sess["epoch"] or user["must_change"]:
            return None, "ended"
        sess["last_seen"] = now
        return user, None
    except Exception:
        return None, "ended"
