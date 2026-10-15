"""Tests for the bulk importer (hr_import.py). Run with: python -m unittest discover -s tests -v"""
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_hr import fresh_modules, FIXED_TODAY  # noqa: E402

HEADER = "employee_id,name,email,role,manager_id,department,job_title,location,hire_date,phone,status\n"
GOOD = HEADER + (
    "A001,Ada Admin,ada@acme.example,hr_admin,,People,Head of People,London,2019-03-01,+44 20 7946 0001,active\n"
    "A002,Ben Boss,ben@acme.example,manager,,Engineering,Engineering Lead,London,2020-01-13,,active\n"
    "A003,Cleo Dev,cleo@acme.example,employee,A002,Engineering,Developer,Remote,2022-06-20,,active\n"
    "A004,Dev Gone,dev@acme.example,employee,A002,Engineering,Developer,Remote,2018-02-01,,terminated\n"
)


class ImportBase(unittest.TestCase):
    def setUp(self):
        self.tmp, self.sec, self.hd, self.ag = fresh_modules()
        sys.modules.pop("hr_import", None)
        self.im = importlib.import_module("hr_import")
        self.hd.bootstrap(seed_demo=False)
        self.dir = tempfile.mkdtemp(prefix="csv_")

    def csv(self, text, name="f.csv", encoding="utf-8"):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding=encoding, newline="") as f:
            f.write(text)
        return p

    def users(self):
        return {u["employee_id"]: u for u in self.hd.all_people()}


class TestEmployees(ImportBase):
    def test_empty_install_has_no_demo_people(self):
        self.assertEqual(self.sec.user_count(), 0)

    def test_dry_run_changes_nothing(self):
        r = self.im.import_employees(self.csv(GOOD), dry_run=True)
        self.assertTrue(r.ok)
        self.assertEqual(r.created, 4)
        self.assertEqual(self.sec.user_count(), 0)

    def test_import_creates_accounts_profiles_and_credentials(self):
        r = self.im.import_employees(self.csv(GOOD))
        self.assertTrue(r.ok, r.errors)
        u = self.users()
        self.assertEqual(set(u), {"A001", "A002", "A003", "A004"})
        self.assertEqual(u["A003"]["manager_id"], "A002")
        self.assertEqual(u["A003"]["job_title"], "Developer")
        self.assertEqual(u["A001"]["hire_date"], "2019-03-01")
        self.assertEqual(u["A004"]["status"], "terminated")
        creds = dict(r.credentials)
        self.assertEqual(set(creds), {"A001", "A002", "A003"})          # none for the terminated person
        self.assertEqual(self.sec.authenticate("A003", creds["A003"])["stage"], "change_password")
        self.assertFalse(self.sec.authenticate("A004", "anything-at-all")["ok"])
        if os.name == "posix":
            self.assertEqual(os.stat(self.sec.CREDENTIALS_FILE).st_mode & 0o077, 0)

    def test_nothing_is_written_when_any_row_is_bad(self):
        bad = GOOD + "A005,Eve Bad,not-an-email,employee,A002,Eng,Dev,Remote,2022-01-01,,active\n"
        r = self.im.import_employees(self.csv(bad))
        self.assertFalse(r.ok)
        self.assertTrue(any("line 6" in e and "email" in e for e in r.errors))
        self.assertEqual(self.sec.user_count(), 0)

    def test_validation_errors(self):
        cases = {
            "duplicate id": GOOD + "A003,Again,again@acme.example,employee,A002,E,D,L,2022-01-01,,active\n",
            "duplicate email": GOOD + "A005,Eve,ada@acme.example,employee,A002,E,D,L,2022-01-01,,active\n",
            "unknown manager": GOOD + "A005,Eve,eve@acme.example,employee,NOPE,E,D,L,2022-01-01,,active\n",
            "terminated manager": GOOD + "A005,Eve,eve@acme.example,employee,A004,E,D,L,2022-01-01,,active\n",
            "bad role": GOOD + "A005,Eve,eve@acme.example,superuser,A002,E,D,L,2022-01-01,,active\n",
            "bad date": GOOD + "A005,Eve,eve@acme.example,employee,A002,E,D,L,01/02/2022,,active\n",
            "bad id": GOOD + "A 5!,Eve,eve@acme.example,employee,A002,E,D,L,2022-01-01,,active\n",
            "markup in text": GOOD + "A005,Eve,eve@acme.example,employee,A002,<b>E</b>,D,L,2022-01-01,,active\n",
        }
        for label, text in cases.items():
            r = self.im.import_employees(self.csv(text, name=label.replace(" ", "_") + ".csv"))
            self.assertFalse(r.ok, label)
        self.assertEqual(self.sec.user_count(), 0)

    def test_reporting_loop_and_missing_admin(self):
        loop = HEADER + ("A001,Ada,ada@acme.example,hr_admin,A002,P,H,L,2019-03-01,,active\n"
                         "A002,Ben,ben@acme.example,manager,A001,E,L,L,2020-01-13,,active\n")
        self.assertTrue(any("loop" in e for e in self.im.import_employees(self.csv(loop)).errors))
        noadmin = HEADER + "A002,Ben,ben@acme.example,manager,,E,L,L,2020-01-13,,active\n"
        self.assertTrue(any("hr_admin" in e for e in self.im.import_employees(self.csv(noadmin, "n.csv")).errors))

    def test_file_level_errors(self):
        self.assertFalse(self.im.import_employees(self.csv("employee_id,name,emial\nA1,x,y\n")).ok)       # unknown + missing column
        self.assertFalse(self.im.import_employees(self.csv(HEADER, "empty.csv")).ok)                      # no rows
        self.assertFalse(self.im.import_employees(os.path.join(self.dir, "missing.csv")).ok)
        p = self.csv("employee_id,name,email\nA1,Zoë,z@x.example\n", "latin.csv", encoding="latin-1")
        self.assertFalse(self.im.import_employees(p).ok)                                                  # not UTF-8
        self.assertFalse(self.im.import_employees(self.csv(HEADER + "A1,N,n@x.example,employee,,a,b,c,2020-01-01,,active,EXTRA\n", "x.csv")).ok)

    def test_excel_bom_and_quoted_commas(self):
        text = "\ufeff" + HEADER + 'A001,"Admin, Ada",ada@acme.example,hr_admin,,People,"Head of People, EMEA",London,2019-03-01,,active\n'
        r = self.im.import_employees(self.csv(text, encoding="utf-8"))
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(self.users()["A001"]["name"], "Admin, Ada")

    def test_existing_people_are_skipped_unless_update(self):
        self.im.import_employees(self.csv(GOOD))
        again = self.im.import_employees(self.csv(GOOD, "again.csv"))
        self.assertTrue(again.ok)
        self.assertEqual((again.created, again.skipped), (0, 4))

    def test_update_changes_data_keeps_passwords_and_ends_sessions_on_access_change(self):
        first = self.im.import_employees(self.csv(GOOD))
        pw = dict(first.credentials)["A003"]
        self.sec.change_password("A003", "Correct-Horse-Battery-9")
        sess = self.sec.new_session(self.sec.get_user("A003"))
        upd = HEADER + "A003,Cleo Dev,cleo@acme.example,manager,A002,Platform,Senior Developer,,,,\n"
        r = self.im.import_employees(self.csv(upd, "u.csv"), update=True)
        self.assertTrue(r.ok, r.errors)
        p = self.users()["A003"]
        self.assertEqual((p["department"], p["job_title"], p["role"]), ("Platform", "Senior Developer", "manager"))
        self.assertEqual(p["location"], "Remote")                       # blank cell = unchanged
        self.assertEqual(self.sec.authenticate("A003", "Correct-Horse-Battery-9")["stage"], "done")   # password untouched
        self.assertEqual(self.sec.validate_session(sess)[0], None)       # role changed, so old session ended
        self.assertFalse(self.sec.authenticate("A003", pw)["ok"])

    def test_large_import_uses_parallel_hashing(self):
        lines = [HEADER, "B000,Boss,boss@big.example,hr_admin,,Ops,Head,HQ,2015-01-01,,active\n"]
        lines += [f"B{i:03d},Person {i},p{i}@big.example,employee,B000,Ops,Staff,HQ,2021-01-01,,active\n" for i in range(1, 60)]
        r = self.im.import_employees(self.csv("".join(lines)))
        self.assertTrue(r.ok, r.errors)
        self.assertEqual((r.created, len(r.credentials)), (60, 60))
        self.assertEqual(self.sec.authenticate("B042", dict(r.credentials)["B042"])["stage"], "change_password")


class TestLeaveData(ImportBase):
    def setUp(self):
        super().setUp()
        self.im.import_employees(self.csv(GOOD))

    def test_holidays_change_return_dates(self):
        # Ben is on approved leave Mon 12 - Thu 15 Oct 2026; Fri 16 Oct is a company holiday
        self.im.import_leave_history(self.csv("employee_id,leave_type,start_date,end_date\nA002,annual,2026-10-12,2026-10-15\n", "l.csv"))
        before = self.hd.current_leave("A002", date(2026, 10, 13))["return_date"]
        self.assertEqual(before, date(2026, 10, 16))
        r = self.im.import_holidays(self.csv("date,name\n2026-10-16,Founders Day\n", "h.csv"))
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(self.hd.current_leave("A002", date(2026, 10, 13))["return_date"], date(2026, 10, 19))

    def test_holiday_validation_and_replace(self):
        self.assertFalse(self.im.import_holidays(self.csv("date,name\n16/10/2026,X\n", "bad.csv")).ok)
        self.im.import_holidays(self.csv("date,name\n2026-12-25,Christmas\n2026-01-01,New Year\n", "a.csv"))
        self.im.import_holidays(self.csv("date,name\n2026-05-01,Labour Day\n", "b.csv"), replace=True)
        with self.hd.hr_conn() as c:
            self.assertEqual([r[0] for r in c.execute("SELECT date FROM holidays")], ["2026-05-01"])

    def test_allotments_override_defaults(self):
        r = self.im.import_allotments(self.csv("employee_id,year,leave_type,days\nA003,2026,annual,25\nA003,2026,sick,7.5\n", "a.csv"))
        self.assertTrue(r.ok, r.errors)
        bal = self.hd.leave_balance("A003", 2026)
        self.assertEqual((bal["annual"]["allotted"], bal["sick"]["allotted"]), (25.0, 7.5))
        self.assertEqual(self.hd.leave_balance("A002", 2026)["annual"]["allotted"], self.hd.DEFAULT_ALLOTMENT["annual"])
        self.assertFalse(self.im.import_allotments(self.csv("employee_id,year,leave_type,days\nNOPE,2026,annual,5\n", "b.csv")).ok)
        self.assertFalse(self.im.import_allotments(self.csv("employee_id,year,leave_type,days\nA003,2026,annual,5.3\n", "c.csv")).ok)

    def test_leave_history_feeds_balances_and_cannot_be_imported_twice(self):
        text = ("employee_id,leave_type,start_date,end_date,status,reason\n"
                "A003,annual,2026-03-02,2026-03-06,approved,Holiday\n"
                "A003,sick,2026-04-14,2026-04-14,approved,\n"
                "A003,annual,2026-05-04,2026-05-05,rejected,\n")
        p = self.csv(text, "hist.csv")
        r = self.im.import_leave_history(p)
        self.assertTrue(r.ok, r.errors)
        bal = self.hd.leave_balance("A003", 2026)
        self.assertEqual(bal["annual"]["used"], 5.0)          # rejected row does not count
        self.assertEqual(bal["sick"]["used"], 1.0)
        again = self.im.import_leave_history(p)
        self.assertFalse(again.ok)
        self.assertTrue(any("already imported" in e for e in again.errors))

    def test_leave_history_validation(self):
        base = "employee_id,leave_type,start_date,end_date\n"
        for label, row in {
            "unknown employee": "NOPE,annual,2026-03-02,2026-03-03\n",
            "bad type": "A003,holiday,2026-03-02,2026-03-03\n",
            "end before start": "A003,annual,2026-03-05,2026-03-02\n",
            "weekend only": "A003,annual,2026-03-07,2026-03-08\n",
            "spans years": "A003,annual,2026-12-28,2027-01-04\n",
        }.items():
            self.assertFalse(self.im.import_leave_history(self.csv(base + row, label.replace(" ", "_") + ".csv")).ok, label)


class TestConfig(unittest.TestCase):
    def test_default_allotment_env_override(self):
        os.environ["HR_DEFAULT_ALLOTMENT"] = "annual=24, sick=12 ,casual=bad,unknown=5"
        try:
            _, _, hd, _ = fresh_modules()
            self.assertEqual(hd.DEFAULT_ALLOTMENT, {"annual": 24.0, "sick": 12.0, "casual": 6.0})
        finally:
            del os.environ["HR_DEFAULT_ALLOTMENT"]

    def test_seed_demo_switch(self):
        os.environ["HR_SEED_DEMO"] = "0"
        try:
            _, sec, hd, _ = fresh_modules()
            self.assertEqual(hd.bootstrap(), [])
            self.assertEqual(sec.user_count(), 0)
        finally:
            del os.environ["HR_SEED_DEMO"]


if __name__ == "__main__":
    unittest.main()
