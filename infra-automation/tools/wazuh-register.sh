#!/usr/bin/env bash
# wazuh-register.sh - register an agent on the Wazuh master, put it in its groups, show its key ONCE.
#   tools/wazuh-register.sh <agent-name> <group,group,...>
#   e.g. tools/wazuh-register.sh dc-site-c acme,domain-controllers,servers-windows,site-c
# Allowed groups: company (acme|companyb|companyc|infrastructure) + role + site. One company group is required.
# The key is printed only to this terminal (never logged); import it on the machine with manage_agents -i.
set -euo pipefail
cd "$(dirname "$0")/../ansible"
NAME="${1:-}"; AGROUPS="${2:-}"
COMPANIES="acme companyb companyc infrastructure"
ROLES="domain-controllers proxmox servers-linux servers-windows endpoints"
SITES="site-a site-b site-c"
[[ "$NAME" =~ ^[A-Za-z0-9._-]{2,64}$ ]] || { echo "usage: $0 <agent-name> <groups>  (name: letters, digits, . _ -)"; exit 1; }
[ -n "$AGROUPS" ] || { echo "groups missing"; exit 1; }
nc=0
for g in ${AGROUPS//,/ }; do
  case " $COMPANIES $ROLES $SITES " in *" $g "*) ;; *) echo "unknown group: $g"; exit 1;; esac
  case " $COMPANIES " in *" $g "*) nc=$((nc+1));; esac
done
[ $nc -eq 1 ] || { echo "exactly one company group required (acme|companyb|companyc|infrastructure)"; exit 1; }

echo "Registering '$NAME' in groups: $AGROUPS"
OUT=$(ansible wazuh-01 -b -m ansible.builtin.shell -a "
B=/var/ossec/bin
if \$B/manage_agents -l | grep -q 'Name: $NAME,'; then echo 'EXISTS'; fi
\$B/manage_agents -l | grep -q 'Name: $NAME,' || \$B/manage_agents -a any -n '$NAME' >/dev/null
id=\$(\$B/manage_agents -l | grep 'Name: $NAME,' | sed -E 's/.*ID: ([0-9]+),.*/\1/')
for g in ${AGROUPS//,/ }; do \$B/agent_groups -l | grep -qw \$g || \$B/agent_groups -a -g \$g -q >/dev/null; \$B/agent_groups -a -i \$id -g \$g -q >/dev/null 2>&1 || true; done
echo ID=\$id
echo KEY=\$(\$B/manage_agents -e \$id | tail -1)
" 2>&1)
echo "$OUT" | grep -q 'EXISTS' && echo "NOTE: '$NAME' was already registered - reusing its ID and key"
ID=$(echo "$OUT" | sed -n 's/^ID=//p'); KEY=$(echo "$OUT" | sed -n 's/^KEY=//p')
[ -n "$ID" ] && [ -n "$KEY" ] || { echo "FAILED:"; echo "$OUT" | grep -v '^KEY=' | tail -5; exit 1; }
logger -t wazuh-register "registered agent $NAME id=$ID groups=$AGROUPS"
cat <<EOF

Agent '$NAME' = ID $ID, groups: $AGROUPS
On the machine (PowerShell as Administrator):
  Set-PSReadLineOption -HistorySaveStyle SaveNothing
  Stop-Service WazuhSvc
  'y' | & "C:\\Program Files (x86)\\ossec-agent\\manage_agents.exe" -i '<KEY BELOW>'
  Start-Service WazuhSvc; Start-Sleep 20; Get-Content "C:\\Program Files (x86)\\ossec-agent\\ossec.log" -Tail 5; Clear-Host
On Linux:  sudo /var/ossec/bin/manage_agents -i '<KEY>' && sudo systemctl restart wazuh-agent

KEY (this agent's secret - copy it, then run 'clear'):
$KEY
EOF
