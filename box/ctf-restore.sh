#!/usr/bin/env bash
# Roll the box back to the last `ctf-snapshot`, then run `ctf-reset`.
# Installed as /usr/local/sbin/ctf-restore. Safe to run any number of times.
#
#   1. kills every player process (web shells, pnair sessions, root children)
#   2. deletes files created after the snapshot in /etc /root /home /srv ...
#   3. restores the snapshot's file contents, owners and modes
#   4. removes any new SUID/SGID binary anywhere on / and player junk in tmp dirs
#   5. ctf-reset: fresh DB, reports dir, pnair home, flags
set -uo pipefail
export LC_ALL=C
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

BASE=/var/lib/ctf-baseline
[[ -f $BASE/base.tgz && -f $BASE/paths.list ]] || { echo "no baseline: run ctf-snapshot first" >&2; exit 1; }
TREES=(/etc /root /home /srv /usr/local /opt/ecorpnet /var/spool/cron /var/spool/at)
PRUNE=(/opt/ecorpnet/app/instance /home/philipp)
log() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }

log "Killing player processes"
systemctl stop ecorpnet                         # web shells + everything they spawned (cgroup)
loginctl terminate-user pnair 2>/dev/null        # pnair SSH sessions incl. root children
pkill -KILL -u pnair 2>/dev/null; pkill -KILL -U pnair 2>/dev/null
pkill -KILL -u ecorpnet 2>/dev/null
sleep 1

log "Removing files created since the snapshot"
existing=(); for t in "${TREES[@]}"; do [[ -e $t ]] && existing+=("$t"); done
prune_expr=(); for p in "${PRUNE[@]}"; do prune_expr+=(-path "$p" -prune -o); done
now=$(mktemp)
{ find "${existing[@]}" -xdev "${prune_expr[@]}" -print 2>/dev/null
  find /home/philipp/.ssh -print 2>/dev/null; } | sort > "$now"
extra=$(comm -13 "$BASE/paths.list" "$now")
if [[ -n $extra ]]; then
    printf '%s\n' "$extra" | sed 's/^/    - /'
    printf '%s\n' "$extra" | sort -r | while IFS= read -r p; do rm -rf -- "$p"; done
fi
rm -f "$now"

log "Restoring snapshot contents and permissions"
tar --xattrs --acls -xpzf "$BASE/base.tgz" -C / --overwrite 2>/dev/null || true
[[ -f $BASE/ssh.tgz ]] && tar --xattrs --acls -xpzf "$BASE/ssh.tgz" -C / --overwrite 2>/dev/null

log "Sweeping new SUID/SGID binaries"
find / -xdev -type f -perm /6000 2>/dev/null | sort | comm -13 "$BASE/suid.list" - \
    | while IFS= read -r f; do echo "    - $f"; rm -f -- "$f"; done
for d in /tmp /var/tmp /dev/shm; do
    find "$d" -perm /6000 -type f -exec rm -f {} + 2>/dev/null
    find "$d" -mindepth 1 -maxdepth 1 -newer "$BASE/stamp" ! -name 'systemd-private-*' \
         ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.XIM-unix' \
         -exec rm -rf {} + 2>/dev/null
done

log "Reloading configs"
systemctl daemon-reload
systemctl reload ssh 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true

/usr/local/sbin/ctf-reset
log "Box restored to the snapshot of $(date -r "$BASE/stamp" '+%F %T')"
