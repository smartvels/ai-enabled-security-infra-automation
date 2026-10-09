# AI Assistant Chatbot Source

The actual production source for the AI IT Assistant (`ai-chatbot.service`
on <server-ip>), now version-controlled here going forward rather than
living only on the VM.

## Frontend structure (`index.html`)

Split into 7 isolated `<script>` blocks so a syntax error in one area
cannot take down the others:

1. **Core** — login, session, chat, AI query handling (all 350 users touch this)
2. **Dispatcher + Core Admin** — tab routing, dashboard, settings, reports
3. **Endpoint Management** — inventory, software, patch, services, USB, etc.
4. **Security Tools** — Wazuh, DLP, OpenVAS, threat intel, security ops
5. **AI/Remediation** — AI recommendations, quick-fix actions
6. **ITSM** — incidents, change management
7. **Infra/Monitoring** — PBS, Zabbix, remote access (RustDesk/Guacamole)

A syntax error in, say, block 4 (Security Tools) now only breaks the
Security Tools admin tabs -- login, chat, and every other admin section
keep working normally.

## Backend (`chatbot.py`)

Not split -- FastAPI already isolates each endpoint's runtime errors
naturally, and `deploy_check.sh` catches syntax errors before deploy.
Splitting would add complexity without a corresponding safety benefit
here (see `docs/LESSONS.md` in the repo root for the reasoning).

## Deploying a change

Always follow the process in `docs/ENGINEERING_STANDARDS.md`:
1. Test the change, run `deploy_check.sh` on the target VM
2. Only restart/reload if all checks pass
3. Never edit these files by hand only on the VM -- update here first,
   then deploy, so the source of truth stays in Git
