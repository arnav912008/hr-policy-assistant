# Contributing

Thanks for your interest! Bug reports, ideas and pull requests are welcome.

## Set up

```bash
git clone https://github.com/<your-username>/hr-policy-assistant.git
cd hr-policy-assistant
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make test
```

The unit tests need only the standard library, so they run without Ollama or Streamlit.

## Ground rules

- **Never use real employee data** in tests, issues or screenshots.
- Keep the rule that **the language model never reads or writes HR data**. New chat actions go in `hr_agent.py`
  as fixed patterns, with the permission check in `hr_data.py`, confirmation before any write, and an audit entry.
- All SQL is parameterised. Column names in SQL must come from a fixed whitelist, never from user input.
- Anything shown from the database goes through `md()` (escaping) and answers pass through `sanitize_answer()`.
- Add or update a test for every behaviour change. A change to who may see or change what needs a permission test.
- Do not log passwords, MFA codes or free-text personal data (audit `detail` included).

## Pull requests

1. Branch from `main`, keep the change focused.
2. Run `make test`. CI runs the same tests.
3. Update `CHANGELOG.md` under "Unreleased" and the README if behaviour changes.
4. Describe what changed and why, and how you tested it.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not file them as public issues.
