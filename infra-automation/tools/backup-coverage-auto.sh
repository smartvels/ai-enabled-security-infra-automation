#!/usr/bin/env bash
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
cd "$HOME/infra/ansible" || exit 1
OUT=$(ansible-playbook playbooks/backup-coverage.yml 2>&1)
echo "$OUT" | grep -oE 'guests: [0-9]+ \| OK: [0-9]+ \| STALE: [0-9]+ \| MISSING: [0-9]+[^"]*' | logger -t backup-coverage
echo "$OUT" | grep -oE '"[a-z0-9]+ [0-9]+ [^"]+ (MISSING|STALE)"' | tr -d '"' | while read -r l; do logger -t backup-coverage -p user.warning "GAP: $l"; done
cd "$HOME/infra" && git add docs/reports && git -c user.name=ctl-01 -c user.email=ctl-01@localhost commit -qm "auto: backup coverage $(date +%F)" 2>/dev/null
exit 0
