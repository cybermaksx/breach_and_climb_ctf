#!/usr/bin/env bash
# ECorpNet "Breach & Climb" — build the training box on a fresh Debian 13 host.
#
#   Usage (as root, from the repo root on the target machine):
#       sudo ./box/provision.sh
#
# Idempotent: re-running redeploys the app and resets the box, but keeps the
# generated flags (/root/.ctf-flags). Delete that file to rotate flags.
#
# What it builds:
#   web    nginx :80 -> gunicorn 127.0.0.1:8000 (ECorpNet, runs as `ecorpnet`)
#   stage1 SQLi (/api/v1/employees) -> MD5 crack -> admin -> SSTI RCE as ecorpnet
#   stage2 /etc/ecorpnet/backup.conf (group ecorpnet) leaks pnair's password -> su pnair
#   stage3 sudo NOPASSWD steelmountain-backup -> `tar ... *` wildcard injection -> root
#
# SPOILERS: this script and WALKTHROUGH.md describe the solution. Never copy the
# repo itself onto a box players can reach — only what this script installs.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$SRC/ecorpnet/__init__.py" ]] || { echo "run from the breach_and_climb_ctf repo" >&2; exit 1; }

APP_ROOT=/opt/ecorpnet
APP=$APP_ROOT/app
PNAIR_PASS='SteelMountain-Backup#2015'
FLAGS=/root/.ctf-flags

log() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------- packages
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv nginx sudo tar >/dev/null

# --------------------------------------------------------------------------- host hygiene
log "Headless server: no suspend, no GUI"
systemctl mask -q sleep.target suspend.target hibernate.target hybrid-sleep.target
install -d /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/nosleep.conf <<'EOF'
[Login]
IdleAction=ignore
HandleSuspendKey=ignore
HandleLidSwitch=ignore
HandleLidSwitchExternalPower=ignore
EOF
systemctl set-default -q multi-user.target

log "sshd: no root login (players who get root must not escape the service sandbox)"
install -d /etc/ssh/sshd_config.d
echo 'PermitRootLogin no' > /etc/ssh/sshd_config.d/10-ctf.conf
sshd -t && systemctl reload ssh

# --------------------------------------------------------------------------- users
log "Users: ecorpnet (service), pnair (stage 2)"
id ecorpnet &>/dev/null || useradd --system --home-dir "$APP" --no-create-home \
    --shell /usr/sbin/nologin ecorpnet
id pnair &>/dev/null || useradd --create-home --shell /bin/bash \
    --comment "Priya Nair,IT Operations" pnair
echo "pnair:$PNAIR_PASS" | chpasswd

# --------------------------------------------------------------------------- app deploy
log "Deploying ECorpNet to $APP (code only: no README, tests or solution notes)"
systemctl stop ecorpnet 2>/dev/null || true
rm -rf "$APP"
install -d -o root -g ecorpnet -m 750 "$APP_ROOT"
install -d -o root -g root -m 755 "$APP"
cp -r "$SRC/ecorpnet" "$APP/ecorpnet"
cp "$SRC/requirements.txt" "$SRC/LICENSE" "$APP/"
rm -f "$APP/ecorpnet/command.txt"
find "$APP/ecorpnet" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$APP"
find "$APP" -type d -exec chmod 755 {} +
find "$APP" -type f -exec chmod 644 {} +

log "Python venv"
python3 -m venv "$APP/.venv"
if [[ -d "$SRC/vendor" ]]; then   # optional offline wheels
    "$APP/.venv/bin/pip" install -q --no-index --find-links "$SRC/vendor" -r "$APP/requirements.txt"
else
    "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"
fi

# --------------------------------------------------------------------------- services
log "systemd unit + nginx"
cat > /etc/systemd/system/ecorpnet.service <<EOF
[Unit]
Description=ECorpNet CTF (gunicorn)
After=network.target

[Service]
User=ecorpnet
Group=ecorpnet
WorkingDirectory=$APP
ExecStart=$APP/.venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 'ecorpnet:create_app()'
Restart=always
RestartSec=3
# NoNewPrivileges is deliberately NOT set: players must be able to su/sudo
# from the web shell. The sandbox below only stops them wrecking the box.
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ReadOnlyPaths=$APP
ReadWritePaths=$APP/instance

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/nginx/sites-available/ecorpnet <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
EOF
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/ecorpnet /etc/nginx/sites-enabled/ecorpnet
nginx -t -q && systemctl reload-or-restart nginx
systemctl daemon-reload
systemctl enable -q ecorpnet nginx

# --------------------------------------------------------------------------- stage 2: creds leak
log "Stage 2: Steel Mountain backup config (readable by ecorpnet)"
install -d -o root -g root -m 755 /etc/ecorpnet
cat > /etc/ecorpnet/backup.conf <<EOF
# ECorpNet -> Steel Mountain nightly backup
# Owner: Priya Nair (IT Operations) - see helpdesk ticket #4172
# TODO(pnair): move to a service account, this is my login for now
BACKUP_HOST=steelmountain.e-corp.local
BACKUP_USER=pnair
BACKUP_PASS=$PNAIR_PASS
DB_PATH=$APP/instance/ecorpnet.db
REPORTS_DIR=/srv/reports
# archive step runs as root:  sudo /usr/local/bin/steelmountain-backup
EOF
chown root:ecorpnet /etc/ecorpnet/backup.conf
chmod 640 /etc/ecorpnet/backup.conf

# --------------------------------------------------------------------------- stage 3: sudo + tar wildcard
log "Stage 3: sudo steelmountain-backup (tar wildcard)"
cat > /usr/local/bin/steelmountain-backup <<'EOF'
#!/bin/bash
# Steel Mountain report archiver - P. Nair, IT Operations
# Packs every report in /srv/reports for the nightly off-site backup.
set -e
cd /srv/reports
tar czf /var/backups/steelmountain-reports.tgz *
echo "[+] reports archived to /var/backups/steelmountain-reports.tgz"
EOF
chown root:root /usr/local/bin/steelmountain-backup
chmod 755 /usr/local/bin/steelmountain-backup

SUDOERS=/etc/sudoers.d/steelmountain
echo 'pnair ALL=(root) NOPASSWD: /usr/local/bin/steelmountain-backup' > "$SUDOERS.tmp"
visudo -cqf "$SUDOERS.tmp"
install -o root -g root -m 440 "$SUDOERS.tmp" "$SUDOERS"
rm -f "$SUDOERS.tmp"

# --------------------------------------------------------------------------- flags + reset
if [[ ! -f $FLAGS ]]; then
    log "Generating flags"
    gen() { python3 -c 'import secrets; print("flag{" + secrets.token_hex(16) + "}")'; }
    umask 077
    printf 'USER_FLAG=%s\nROOT_FLAG=%s\n' "$(gen)" "$(gen)" > "$FLAGS"
fi

install -o root -g root -m 700 "$SRC/box/ctf-reset.sh" /usr/local/sbin/ctf-reset
/usr/local/sbin/ctf-reset

log "Done. Box is up on :80"
echo "    flags:  $FLAGS"
echo "    reset between rounds:  sudo ctf-reset"
echo
echo "    !! Before players connect: make sure no account other than pnair is"
echo "    !! reachable with a weak password (admin users in the sudo group = free root)."
