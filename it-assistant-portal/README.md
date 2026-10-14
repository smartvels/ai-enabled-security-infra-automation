# IT Operations Portal (Proof of Concept)

FastAPI backend (`chatbot.py`) and single-page frontend (`index.html`) for
an AI-assisted IT operations portal: AI chat, endpoint inventory and remote
commands, ITSM (incidents, changes), DLP, vulnerability scanning (OpenVAS),
threat intel, and monitoring views (Wazuh, Zabbix, Proxmox Backup Server).

Built and piloted on 10 endpoints as a proof of concept; development has
since stopped. The code is kept here as a reference and was security-reviewed
before publication (see below).

## Security model

| Control | Implementation |
|---|---|
| **Server-side access control, default deny** | `AccessControlMiddleware` classifies every path. Admin APIs (`/api/admin/*`, Wazuh, PBS, Zabbix views) require a session with the `admin` permission; other APIs require a valid session; unknown paths (including FastAPI's `/docs`) are denied. |
| **Machine-to-machine auth** | Endpoint agents send `X-Agent-Token`; the Wazuh/n8n webhook sends `X-Webhook-Token`. Constant-time comparison; fails closed if the token is not configured. |
| **No command injection** | The OpenVAS integration quotes every remote argument with `shlex.quote`; scan targets must be a single private IP or a private CIDR of at most 1,024 addresses; task IDs must be UUIDs. |
| **SSH host verification** | `StrictHostKeyChecking=yes` with a pinned `known_hosts` file. |
| **Password storage** | Salted PBKDF2-HMAC-SHA256 (600,000 iterations); legacy unsalted SHA-256 hashes are upgraded automatically at the next login. |
| **No secrets in code** | All credentials come from environment variables / `.env`. |
| **Safe XML parsing** | `defusedxml` for scanner responses. |
| **No error leakage** | Exception details are logged server-side; callers get a generic message. |
| **Same-origin by default** | CORS disabled unless `PORTAL_CORS_ORIGINS` names allowed origins. |
| **Local binding** | Listens on `127.0.0.1` unless `PORTAL_HOST` is set; expose via a TLS reverse proxy. |
| **Security headers** | CSP, frame denial, nosniff, and others on every response, including 401s. |

Regression tests for every control: `tests/test_security.py` (run in CI).

### Security review history

A review before publication found and fixed: admin APIs with no server-side
authentication (the login screen protected only the UI), shell command
injection through the OpenVAS scan target, disabled SSH host-key checking,
a hardcoded service credential, unsalted password hashes, wide-open CORS,
and exception text returned to callers. Each fix is pinned by a test.

## Configuration

Environment variables (in `$PORTAL_BASE_DIR/.env`, never committed):

| Variable | Purpose |
|---|---|
| `PORTAL_BASE_DIR` | Data directory (database, reports); default `/home/chatbot/chatbot` |
| `ADMIN_INITIAL_PASSWORD` | Password for the first `itadmin` account (random if unset; printed once) |
| `AGENT_TOKEN` | Shared secret for endpoint agents (`X-Agent-Token`) |
| `WEBHOOK_TOKEN` | Shared secret for the Wazuh/n8n webhook (`X-Webhook-Token`) |
| `WAZUH_USER`, `WAZUH_PASS`, `GLPI_*`, `PBS_*`, `ZABBIX_*`, `OPENVAS_*`, `OPENCTI_TOKEN` | Integration credentials |
| `OPENVAS_KNOWN_HOSTS` | `known_hosts` file pinning the scanner's SSH host key |
| `PORTAL_CORS_ORIGINS` | Comma-separated allowed origins (empty = same-origin only) |
| `PORTAL_HOST`, `PORTAL_PORT` | Bind address and port (default `127.0.0.1:7000`) |

Generate tokens with `openssl rand -hex 32`.

## Running the tests

```bash
cd it-assistant-portal
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt httpx pytest
python -m pytest tests/ -v
```

## Frontend structure (`index.html`)

Split into isolated `<script>` blocks so a syntax error in one area cannot
take down the others: a small fetch wrapper (attaches the session token to
same-origin API calls), core (login, chat), dispatcher and core admin,
endpoint management, security tools, AI remediation, ITSM, and
infrastructure monitoring.
