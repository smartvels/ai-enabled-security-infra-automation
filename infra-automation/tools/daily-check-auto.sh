#!/usr/bin/env bash
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
cd "$HOME/infra/ansible" || exit 1
OUT=$(ansible-playbook playbooks/daily-check.yml 2>&1); RC=$?
echo "$OUT" | grep -oE "sheets written: [^\"]*" | logger -t daily-check
[ $RC -eq 0 ] || logger -t daily-check -p user.err "daily-check FAILED (rc=$RC)"
cd "$HOME/infra" && git add docs/evidence/daily-checks && git -c user.name=ctl-01 -c user.email=ctl-01@localhost commit -qm "auto: daily checklist $(date +%F)" 2>/dev/null
exit 0
