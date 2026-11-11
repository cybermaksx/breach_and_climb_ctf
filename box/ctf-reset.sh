#!/usr/bin/env bash
# Reset the ECorpNet box to a clean state between CTF rounds.
# Installed by provision.sh as /usr/local/sbin/ctf-reset (root only).
#
# Kills every player shell (web shells live in the ecorpnet.service cgroup,
# su/sudo children included), reseeds the database and restores all
# stage 2/3 files and flags.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

APP=/opt/ecorpnet/app
FLAGS=/root/.ctf-flags
# shellcheck source=/dev/null
source "$FLAGS"

systemctl stop ecorpnet
pkill -KILL -u pnair 2>/dev/null || true

# Player leftovers outside the service's PrivateTmp (SSH sessions as pnair)
find /tmp /var/tmp /dev/shm -mindepth 1 \( -user pnair -o -user ecorpnet \) -delete 2>/dev/null || true
rm -f /var/backups/steelmountain-reports.tgz

# Database, uploads, secret key
rm -rf "$APP/instance"
install -d -o ecorpnet -g ecorpnet -m 700 "$APP/instance"
(cd "$APP" && runuser -u ecorpnet -- .venv/bin/flask --app ecorpnet init-db >/dev/null)

# Reports directory abused for the tar wildcard injection
rm -rf /srv/reports
install -d -o pnair -g pnair -m 755 /srv/reports
for q in 2015Q1 2015Q2 2015Q3; do
    printf 'department,headcount,opex_usd\nTechnology,412,18200000\nRisk Management,96,4100000\nFinance,154,6900000\n' \
        > "/srv/reports/headcount-$q.csv"
done
printf 'Steel Mountain DR test: PASSED\nRestore time: 3h12m\nNext test: Q4\n' > /srv/reports/dr-test-2015.txt
chown pnair:pnair /srv/reports/*
chmod 644 /srv/reports/*

# pnair home + user flag
rm -rf /home/pnair
install -d -o pnair -g pnair -m 750 /home/pnair
cp -rT /etc/skel /home/pnair
chown -R pnair:pnair /home/pnair
echo "$USER_FLAG" > /home/pnair/user.txt
chown root:pnair /home/pnair/user.txt
chmod 440 /home/pnair/user.txt

# root flag
echo "$ROOT_FLAG" > /root/root.txt
chmod 400 /root/root.txt

systemctl start ecorpnet
echo "[+] box reset"
