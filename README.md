# SOC Alert Triage & RAG Automation (Reference Architecture)

A reference implementation of an LLM-assisted SOC (Security Operations
Center) automation pipeline, built with self-hosted, open-source
components end to end -- no data leaves the local network.

This is a sanitized version of a pattern I designed and deployed in a
production security environment. Hostnames, internal IPs, and credentials
have been replaced with environment-variable placeholders.

## What it does

**Pipeline 1 -- Alert triage and ticketing**
```
SIEM alert (e.g. Wazuh)
   |  webhook
   v
n8n workflow
   |  builds a classification prompt
   v
Self-hosted LLM (e.g. LocalAI + Qwen2.5)
   |  returns { verdict, confidence, reason, source_ip }
   v
n8n branches on verdict:
   true_positive  -> creates a ticket in a service desk (e.g. GLPI)
   false_positive -> logged, no action taken
```

**Pipeline 2 -- Retrieval-Augmented Generation (RAG)**
```
Document -> chunked -> embedded (LocalAI) -> stored in pgvector
Question -> embedded -> similarity search in pgvector -> top matches
         -> fed to LLM as context -> grounded answer + cited sources
```

## Platform pillars

This repo covers the **SOC automation and AI/RAG layer** of a larger
reference architecture. For the full picture — dashboard, endpoint
agents, DLP, remote access, correlation engine, and every integrated
tool this pattern is designed to work alongside — see
**[docs/PLATFORM-OVERVIEW.md](docs/PLATFORM-OVERVIEW.md)**.

| Pillar | Tooling | Status in this repo |
|---|---|---|
| **SOC automation** | SIEM -> LLM -> ITSM ticket | ✅ Live (see below) |
| **Incident management** | Case management + ticketing | ✅ Ticket creation live |
| **Asset management** | ITSM tool | Reference — separate component |
| **Change management** | ITSM tool | Planned — same pattern as incident tickets |
| **Endpoint control** | Cross-platform agent, remote-desktop relay | Reference — separate component |
| **DLP** | Endpoint agent + dashboard | Reference — separate component |
| **General automation** | n8n | ✅ Core orchestration engine for all of the above |
| **Knowledge / RAG** | pgvector + self-hosted LLM | ✅ Live |

## Key design decisions (and why)

- **LLM request bodies are built in code (n8n Code nodes / Python), never
  templated as strings.** Raw LLM text or user input can contain quotes
  and newlines that corrupt a hand-built JSON string. Letting the
  language's own serializer (`JSON.stringify`, `json.dumps`) handle
  escaping avoids an entire class of hard-to-diagnose "invalid JSON"
  errors. See `docs/LESSONS.md` for the specific failure modes this
  avoids.
- **Vector storage (pgvector) runs on its own isolated host**, separate
  from the LLM inference host and the orchestration host, so a
  compromise of one component doesn't automatically expose the others.
- **CI enforces security scanning on every change** (SAST via Bandit,
  secrets scanning via Gitleaks, dependency auditing via pip-audit)
  before anything merges.

## Stack

| Layer | Example tool used | Swappable for |
|---|---|---|
| SIEM | Wazuh | Any SIEM with webhook/integration support |
| Orchestration | n8n | Any workflow engine with reliable HTTP handling |
| LLM inference | LocalAI (Qwen2.5-7B) | Any OpenAI-compatible local or hosted LLM |
| Vector store | PostgreSQL + pgvector | Any vector DB |
| Ticketing | GLPI | Any ITSM tool with a REST API |

## Repository layout

```
triage-service/       Standalone Python/Flask reference triage service
n8n-workflows/         Importable n8n workflow JSON (env-var driven, no secrets)
.github/workflows/     CI: security scanning + unit tests on every change
docs/                  Design notes and lessons learned
```

## Platform context

This repo represents one layer (automation + AI) of a larger reference
architecture unifying SIEM, vulnerability scanning, threat intel,
ticketing, incident response, endpoint control, and remote access. See
`docs/PLATFORM_OVERVIEW.md` for the full picture and how the pieces fit
together.

## Running the triage service standalone

```bash
cd triage-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
LOCALAI_URL=http://localhost:8080/v1/chat/completions python3 triage.py
```

## Importing the n8n workflows

1. Import the JSON files in `n8n-workflows/` via n8n's UI
2. Set these environment variables on your n8n instance:
   ```
   GLPI_URL=<your ticketing API URL>
   GLPI_APP_TOKEN=<your app token>
   GLPI_USER_TOKEN=<your user token>
   N8N_BLOCK_ENV_ACCESS_IN_NODE=false
   ```
3. Create a Postgres credential in n8n pointing at your pgvector instance
4. Replace the `${LOCALAI_HOST}`, `${GLPI_HOST}`, `${PGVECTOR_HOST}`
   placeholders in the workflow JSON with your actual hosts (or convert
   them to n8n environment expressions)

## License

MIT -- use freely, adapt to your own environment.
