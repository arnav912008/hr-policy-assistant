"""Operator tool for things the web app deliberately cannot do.

Accounts
    python manage.py list
    python manage.py reset-password E001      # prints a one-time password; user must change it at next sign-in
    python manage.py reset-mfa E001           # when someone loses their authenticator device
    python manage.py unlock E001              # clear a login lockout
    python manage.py verify-audit             # check the audit log has not been altered

Loading real company data (see docs/IMPORTING_DATA.md). Add --dry-run to any of these to check a file first.
    python manage.py import-employees employees.csv [--update]
    python manage.py import-holidays holidays.csv [--replace]
    python manage.py import-allotments leave_allotments.csv
    python manage.py import-leave leave_history.csv
"""
import argparse
import sys
from contextlib import closing

import hr_data
import hr_import
import hr_security as sec


def _print_report(rep, what: str) -> int:
    for w in rep.warnings[:20]:
        print(f"  warning: {w}")
    if len(rep.warnings) > 20:
        print(f"  ... and {len(rep.warnings) - 20} more warnings")
    if rep.errors:
        print(f"\nNothing was imported. {len(rep.errors)} problem(s) found:")
        for e in rep.errors[:50]:
            print(f"  {e}")
        if len(rep.errors) > 50:
            print(f"  ... and {len(rep.errors) - 50} more")
        return 2
    verb = "Would import" if rep.dry_run else "Imported"
    parts = [f"{rep.created} new"] if rep.created else []
    if rep.updated:
        parts.append(f"{rep.updated} updated")
    if rep.skipped:
        parts.append(f"{rep.skipped} skipped")
    print(f"{verb} {what}: {', '.join(parts) or 'nothing to do'}.")
    if rep.credentials:
        print(f"\n{len(rep.credentials)} one-time passwords were written to {sec.CREDENTIALS_FILE}.")
        print("Give each person theirs privately, then DELETE that file. Everyone must set their own password at first sign-in.")
    if rep.dry_run:
        print("Dry run: no changes were made.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="HR assistant operator tool", usage=__doc__, add_help=True)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list")
    sub.add_parser("verify-audit")
    for name in ("reset-password", "reset-mfa", "unlock"):
        sub.add_parser(name).add_argument("employee_id")
    p = sub.add_parser("import-employees")
    p.add_argument("file"); p.add_argument("--update", action="store_true"); p.add_argument("--dry-run", action="store_true")
    p = sub.add_parser("import-holidays")
    p.add_argument("file"); p.add_argument("--replace", action="store_true"); p.add_argument("--dry-run", action="store_true")
    for name in ("import-allotments", "import-leave"):
        p = sub.add_parser(name)
        p.add_argument("file"); p.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not args.cmd:
        print(__doc__)
        return 1

    # Never seed demo people into a database that is about to receive real data.
    hr_data.bootstrap(seed_demo=False)

    if args.cmd == "list":
        with closing(sec.connect(sec.AUTH_DB)) as c:
            for r in c.execute("SELECT employee_id, name, role, active, mfa_enabled, must_change FROM employees ORDER BY employee_id"):
                print(f"{r[0]:8} {r[1]:24} {r[2]:9} {'active' if r[3] else 'DISABLED':8} mfa={'on' if r[4] else 'off'} {'(must change password)' if r[5] else ''}")
    elif args.cmd == "reset-password":
        pw = sec.admin_reset_password(args.employee_id)
        print(f"One-time password for {args.employee_id}: {pw}" if pw else "No such employee.")
    elif args.cmd == "reset-mfa":
        print("Two-step sign-in reset." if sec.reset_mfa(args.employee_id) else "No such employee.")
    elif args.cmd == "unlock":
        sec.clear_lock(args.employee_id)
        print("Lockout cleared.")
    elif args.cmd == "verify-audit":
        ok, n, bad = sec.verify_audit_chain()
        print(f"OK, {n} entries intact." if ok else f"TAMPERING DETECTED at entry {bad}.")
        return 0 if ok else 2
    elif args.cmd == "import-employees":
        return _print_report(hr_import.import_employees(args.file, update=args.update, dry_run=args.dry_run), "employees")
    elif args.cmd == "import-holidays":
        return _print_report(hr_import.import_holidays(args.file, replace=args.replace, dry_run=args.dry_run), "holidays")
    elif args.cmd == "import-allotments":
        return _print_report(hr_import.import_allotments(args.file, dry_run=args.dry_run), "leave entitlements")
    elif args.cmd == "import-leave":
        return _print_report(hr_import.import_leave_history(args.file, dry_run=args.dry_run), "leave records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
