#!/usr/bin/env bash
# Take a "known good" baseline of everything a player (up to root) is likely to
# touch, so `ctf-restore` can roll the box back to exactly this state.
# Installed as /usr/local/sbin/ctf-snapshot. Run it once the box is final
# (after hardening, after changing admin passwords), and again after any
# intentional change — ctf-restore reverts everything to the last snapshot.
set -euo pipefail
export LC_ALL=C
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

BASE=/var/lib/ctf-baseline
# Trees restored file-for-file. The admin's home is deliberately not included
# (only its .ssh), the app's runtime instance is rebuilt by ctf-reset.
TREES=(/etc /root /home /srv /usr/local /opt/ecorpnet /var/spool/cron /var/spool/at)
PRUNE=(/opt/ecorpnet/app/instance /home/philipp)

install -d -o root -g root -m 700 "$BASE"
existing=(); for t in "${TREES[@]}"; do [[ -e $t ]] && existing+=("$t"); done
excl=(); for p in "${PRUNE[@]}"; do excl+=(--exclude="${p#/}"); done

# 1) contents + owners + modes
tar --xattrs --acls -cpzf "$BASE/base.tgz.new" -C / "${excl[@]}" \
    "${existing[@]#/}" 2>/dev/null || [[ $? -eq 1 ]]
mv "$BASE/base.tgz.new" "$BASE/base.tgz"
# the admin's SSH keys (their home is excluded above)
tar --xattrs --acls -cpzf "$BASE/ssh.tgz" -C / home/philipp/.ssh 2>/dev/null || true

# 2) list of every path that exists now (anything not in it gets deleted on restore)
prune_expr=(); for p in "${PRUNE[@]}"; do prune_expr+=(-path "$p" -prune -o); done
find "${existing[@]}" -xdev "${prune_expr[@]}" -print 2>/dev/null | sort > "$BASE/paths.list"
find /home/philipp/.ssh -print 2>/dev/null | sort >> "$BASE/paths.list"
sort -o "$BASE/paths.list" "$BASE/paths.list"

# 3) every SUID/SGID binary on the root filesystem
find / -xdev -type f -perm /6000 2>/dev/null | sort > "$BASE/suid.list"

touch "$BASE/stamp"
echo "[+] baseline saved: $(du -h "$BASE/base.tgz" | cut -f1), $(wc -l < "$BASE/paths.list") paths, $(wc -l < "$BASE/suid.list") suid/sgid"
