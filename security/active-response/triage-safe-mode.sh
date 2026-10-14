#!/bin/bash
# Wazuh active response: turn ON the triage kill switch.
#
# Creates the SAFE_MODE flag file that the triage container checks on every
# request. Effect is immediate: the LLM is taken out of the decision path and
# every alert creates a ticket. Turning it OFF is deliberately manual
# (rm the file) after a human has checked what happened.
#
# Install (on the agent running the triage container):
#   sudo cp triage-safe-mode.sh /var/ossec/active-response/bin/
#   sudo chown root:wazuh /var/ossec/active-response/bin/triage-safe-mode.sh
#   sudo chmod 750 /var/ossec/active-response/bin/triage-safe-mode.sh

set -u
FLAG="${TRIAGE_SAFE_MODE_FLAG:-/opt/triage/deploy/control/SAFE_MODE}"
LOG="${AR_LOG:-/var/ossec/logs/active-responses.log}"

read -r INPUT || exit 0
if ! printf '%s' "$INPUT" | grep -q '"command"[[:space:]]*:[[:space:]]*"add"'; then
    exit 0
fi

if touch "$FLAG"; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') triage-safe-mode: kill switch ENABLED ($FLAG)" >> "$LOG"
else
    echo "$(date '+%Y/%m/%d %H:%M:%S') triage-safe-mode: FAILED to create $FLAG" >> "$LOG"
    exit 1
fi
