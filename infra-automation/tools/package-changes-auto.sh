#!/usr/bin/env bash
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
cd "$HOME/infra/ansible" || exit 1
ansible-playbook playbooks/package-changes.yml 2>&1 | grep -oE "change records added: [0-9]+" | logger -t package-changes
cd "$HOME/infra" && git add docs/changes && git -c user.name=ctl-01 -c user.email=ctl-01@localhost commit -qm "auto: package change records $(date +%F)" 2>/dev/null
exit 0
