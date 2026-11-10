# breach_and_climb_ctf
CTF challenge from Istanbul Hackerspace

## ECorpNet — E Corp employee portal (Flask)

Internal intranet of E Corp (Mr. Robot universe):

| Module | Who | What it does |
|---|---|---|
| Auth | everyone | Sign in; external contractors self-register with limited access |
| Dashboard | all | Announcements, E Coin balance, open tickets, new colleagues |
| Directory | all | Search staff, profiles, org chart (manager / direct reports), edit own profile & password |
| IT Helpdesk | all / IT | Open tickets, conversation thread; IT staff triage (status, priority, assignee) |
| HR Documents | all / managers | Documents filtered by clearance (all → employee → manager → admin); preview, download, upload |
| E Coin Wallet | all | Balance, history, instant transfers to colleagues |
| Report Builder | managers, admin | Headcount / tickets / payroll / E Coin reports, saved, CSV export, print |
| Admin | admin | Users (role, salary, manager, disable, reset password), announcements, monthly payroll run |
| JSON API | logged in | `/api/v1/` — me, employees, wallet, tickets |

Roles: `contractor` < `employee` / `it` < `manager` < `admin`.

### Run (development)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
flask --app ecorpnet init-db      # recreates DB + seed data, prints demo accounts
flask --app ecorpnet run --debug  # http://127.0.0.1:5000
```

> **Never use `--debug` on the CTF server**: the Werkzeug debugger is remote code execution.

Data lives in `instance/` (SQLite DB, uploaded documents, generated `secret_key`).
`init-db` wipes and reseeds everything — handy for resetting the box between CTF rounds.

### Run (server, port 80)

```bash
gunicorn -w 4 -b 0.0.0.0:80 'ecorpnet:create_app()'
```

(or bind gunicorn to 127.0.0.1:8000 behind nginx).

### Tests

```bash
python3 tests/smoke_test.py      # every page / workflow for each role
python3 tests/security_test.py   # security regression checks (all must be OK)
```

Both run against a throw-away database, the real `instance/` is not touched.
