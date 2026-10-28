#!/usr/bin/env bash
# pan-backup-auto.sh - run by systemd timer: daily Palo Alto config backup, device-state on the 1st of the month,
# commit the encrypted results to git (the offsite timer then pushes them), log every result to journald
# (tag pan-backup) so Wazuh can alert on "CONFIG CHANGED" and on failures.
set -uo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
cd "$HOME/infra/ansible" || exit 1
log() { logger -t pan-backup -p "user.$1" -- "$2" 2>/dev/null || true; echo "[$1] $2"; }
TAGS="all"; [ "$(date +%d)" = "01" ] && TAGS="all,devicestate"

OUT=$(ansible-playbook playbooks/pan-backup.yml --tags "$TAGS" 2>&1); RC=$?
# one journald line per firewall result (no secrets are ever printed by the playbook)
echo "$OUT" | grep -E '^ +"[a-z0-9-]+: (CONFIG|FIRST|DEVICE)' | sed -E 's/^ +"//; s/",?$//' | while read -r l; do
  case "$l" in *"CONFIG CHANGED"*|*"NOT EXPORTED"*) log warning "$l";; *) log info "$l";; esac
done
echo "$OUT" | grep -E '^(fatal|failed):' | while read -r l; do log err "${l:0:300}"; done
[ $RC -eq 0 ] || log err "pan-backup playbook FAILED (rc=$RC)"

ansible-playbook playbooks/firewall-changes.yml 2>&1 | grep -oE "firewall change records added: .*" | logger -t firewall-change
cd "$HOME/infra"
if [ -n "$(git status --porcelain -- backups/paloalto)" ]; then
  git add backups/paloalto docs/changes && git -c user.name=ctl-01 -c user.email=ctl-01@localhost commit -qm "auto: Palo Alto backup $(date -u +%FT%TZ)" \
    && log info "backup committed" || log err "git commit of backups failed"
fi
exit $RC
