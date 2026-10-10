"""Operator tool for things the web app deliberately cannot do.

    python manage.py list
    python manage.py reset-password E001      # prints a one-time password; user must change it at next sign-in
    python manage.py reset-mfa E001           # when someone loses their authenticator device
    python manage.py unlock E001              # clear a login lockout
    python manage.py verify-audit             # check the audit log has not been altered
"""
import sys
from contextlib import closing

import hr_security as sec
import hr_data


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    hr_data.bootstrap()
    cmd, args = argv[0], argv[1:]
    if cmd == "list":
        with closing(sec.connect(sec.AUTH_DB)) as c:
            for r in c.execute("SELECT employee_id, name, role, active, mfa_enabled, must_change FROM employees ORDER BY employee_id"):
                print(f"{r[0]:8} {r[1]:24} {r[2]:9} {'active' if r[3] else 'DISABLED':8} mfa={'on' if r[4] else 'off'} {'(must change password)' if r[5] else ''}")
    elif cmd == "reset-password" and args:
        pw = sec.admin_reset_password(args[0])
        print(f"One-time password for {args[0]}: {pw}" if pw else "No such employee.")
    elif cmd == "reset-mfa" and args:
        print("Two-step sign-in reset." if sec.reset_mfa(args[0]) else "No such employee.")
    elif cmd == "unlock" and args:
        sec.clear_lock(args[0])
        print("Lockout cleared.")
    elif cmd == "verify-audit":
        ok, n, bad = sec.verify_audit_chain()
        print(f"OK, {n} entries intact." if ok else f"TAMPERING DETECTED at entry {bad}.")
        return 0 if ok else 2
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
