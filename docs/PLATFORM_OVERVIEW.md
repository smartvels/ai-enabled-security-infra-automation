# Platform Overview

The full reference platform this repo's automation/AI layer is designed
to plug into. This document exists to show the complete architecture
context, not just the automation pieces implemented here.

## Design goal

A single-pane security & IT operations console plus a lightweight
endpoint agent, unifying SIEM, vulnerability scanning, threat intel,
ticketing, incident response, monitoring, and remote access — built
in-house rather than bought as a commercial suite.

## Platform components (reference architecture)

| Component | Role |
|---|---|
| Web dashboard & backend | Central console, RBAC login |
| SIEM/EDR | Alert detection and endpoint telemetry |
| Vulnerability scanner | Scheduled scans, GMP-style protocol integration |
| Threat intelligence platform | IOC/TTP correlation feed |
| Correlation & auto-resolution engine | Cross-tool alert correlation |
| Endpoint agent (Linux/Windows/Mac) | Telemetry + remote control hooks |
| Remote access (self-hosted relay) | Support/remote troubleshooting |
| DLP (Data Loss Prevention) | Data exfiltration monitoring/controls |
| Asset management / ticketing | Inventory + service desk |
| Incident case management | Structured investigation workflow |
| Infrastructure monitoring | Network/host health |
| Backup infrastructure | Scheduled backup + retention |

## How this repo fits in

This repo contains the automation and AI layer, the IT operations portal
(backend and dashboard), and the detection and response pack. Endpoint
agent binaries and the remote-access relay setup are not included.

- SIEM alert -> LLM triage -> ticketing automation pipeline (n8n)
- Vector-store-backed RAG ingestion and retrieval pipeline
- A standalone, hardened Python triage service (containerised)
- The IT operations portal (`it-assistant-portal/`): endpoints, ITSM, DLP,
  vulnerability scanning, monitoring views
- Detection and automated response (`security/`): Wazuh rules, kill
  switch, firewall IP blocking
- Ansible project skeleton with Vault-encrypted secrets

## Functional pillars and where each is handled

| Pillar | Typically handled by | In this repo? |
|---|---|---|
| Asset management | Endpoint agent + inventory | **Yes** — server side in `it-assistant-portal/` (agent not included) |
| Incident management | Case management + ticketing | **Yes** — ticket creation and incident tracking |
| Change management | ITSM workflow | **Yes** — approve / reject / execute workflow in the portal |
| SOC automation | SIEM + orchestration + LLM | **Yes** — the core triage pipeline |
| Endpoint control / DLP | Endpoint agent | **Yes** — server side in the portal (agent not included) |
| Remote access | Self-hosted relay | Partial — the portal links to a self-hosted relay; relay setup not included |
| Auto-block IPs | SIEM active response + firewall API | **Yes** — `security/` (Wazuh rules, Palo Alto blocking) |
| Knowledge / RAG | Vector DB + LLM + orchestration | **Yes** — the RAG pipeline |

All of the above was piloted as a proof of concept on 10 endpoints; none
of it is currently running in production.

## Core technology stack (reference platform)

| Layer | Example technology |
|---|---|
| Backend | FastAPI (Python), SQLite |
| Frontend | Single-page HTML/JS dashboard |
| Desktop client | Electron + React |
| Endpoint agent | Python, compiled to standalone binaries |
| SIEM/EDR | Open-source SIEM with active response |
| Vulnerability scanning | Open-source scanner (GMP-style protocol) |
| Threat intelligence | Open-source TIP (GraphQL API) |
| Remote access | Self-hosted remote-desktop relay |
| Antivirus (Linux) | ClamAV |
| Workflow automation | n8n |
| Asset/ticketing | Open-source ITSM tool |
| Incident response | Open-source case management |
| Monitoring | Zabbix |
| Backup | Proxmox Backup Server |
| AI/LLM | Self-hosted LLM inference, pgvector (RAG) |
| Security scanning | Bandit (SAST), OWASP ZAP (DAST) |
