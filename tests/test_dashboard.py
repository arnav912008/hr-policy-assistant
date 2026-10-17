"""Tests for the data behind the dashboard. Run with: python -m unittest discover -s tests -v"""
import os
import sys
import unittest
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_hr import Base  # noqa: E402


class TestDashboardData(Base):
    def test_leave_days_by_month_counts_working_days_only(self):
        # E003 is on approved leave Fri 9 Oct to Tue 13 Oct 2026: Fri, Mon, Tue = 3 working days, all in October
        months = self.hd.leave_days_by_month("E003", 2026)
        self.assertEqual(len(months), 12)
        self.assertEqual(months[9], 3.0)
        self.assertEqual(sum(months), 3.0)

    def test_monthly_chart_ignores_pending_and_rejected_leave(self):
        self.assertEqual(sum(self.hd.leave_days_by_month("E012", 2026)), 0.0)   # only a pending request
        self.assertEqual(sum(self.hd.leave_days_by_month("E021", 2026)), 0.0)   # only a rejected request

    def test_monthly_chart_splits_leave_across_months(self):
        ok, msg, rid = self.hd.request_leave("E003", "annual", date(2026, 10, 29), date(2026, 11, 3))
        self.assertTrue(ok, msg)
        self.hd.decide_leave("E002", rid, True)
        months = self.hd.leave_days_by_month("E003", 2026)
        self.assertEqual((months[9], months[10]), (3.0 + 2.0, 2.0))   # Oct: 3 + Thu, Fri;  Nov: Mon, Tue

    def test_approver_sees_context_for_the_decision(self):
        ok, msg, rid = self.hd.request_leave("E009", "annual", date(2026, 10, 14), date(2026, 10, 15), "dentist")
        self.assertTrue(ok, msg)
        item = next(r for r in self.hd.pending_for_approval("E002") if r["id"] == rid)
        self.assertEqual(item["name"], self.hd.get_person("E009")["name"])
        self.assertEqual(item["department"], "Engineering")
        self.assertEqual(item["reason"], "dentist")
        self.assertEqual(item["remaining"], 13.0)                       # 18 a year, 3 already taken (seed data), 2 held by this request
        self.assertEqual(item["also_away"], [self.hd.get_person("E014")["name"]])   # a colleague in Engineering is away then

    def test_unpaid_leave_has_no_balance_figure(self):
        ok, msg, rid = self.hd.request_leave("E009", "unpaid", date(2026, 10, 14), date(2026, 10, 14))
        item = next(r for r in self.hd.pending_for_approval("E002") if r["id"] == rid)
        self.assertIsNone(item["remaining"])

    def test_who_can_see_which_requests(self):
        ok, msg, rid = self.hd.request_leave("E003", "annual", date(2026, 11, 2), date(2026, 11, 2))
        self.assertIn(rid, [r["id"] for r in self.hd.pending_for_approval("E002")])      # her manager
        self.assertIn(rid, [r["id"] for r in self.hd.pending_for_approval("E001")])      # HR
        self.assertNotIn(rid, [r["id"] for r in self.hd.pending_for_approval("E005")])   # another team's manager
        self.assertEqual(self.hd.pending_for_approval("E003"), [])                       # an employee sees none
        ok, msg, mine = self.hd.request_leave("E001", "annual", date(2026, 11, 9), date(2026, 11, 9))
        self.assertNotIn(mine, [r["id"] for r in self.hd.pending_for_approval("E001")])  # never your own
        self.assertIn(mine, [r["id"] for r in self.hd.pending_for_approval("E004")])     # the other HR admin can

    def test_theme_preference_is_stored_per_person(self):
        self.assertEqual(self.hd.get_theme("E003"), "light")
        self.assertTrue(self.hd.set_theme("E003", "dark"))
        self.assertEqual(self.hd.get_theme("E003"), "dark")
        self.assertEqual(self.hd.get_theme("E002"), "light")
        self.assertTrue(self.hd.set_theme("E003", "light"))
        self.assertEqual(self.hd.get_theme("E003"), "light")

    def test_theme_rejects_bad_values(self):
        self.assertFalse(self.hd.set_theme("E003", "purple"))
        self.assertFalse(self.hd.set_theme("NOBODY", "dark"))
        self.assertFalse(self.hd.set_theme("E003", "dark'; DROP TABLE user_prefs; --"))
        self.assertEqual(self.hd.get_theme("E003"), "light")


if __name__ == "__main__":
    unittest.main()
