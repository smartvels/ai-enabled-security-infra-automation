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

This repo is the **automation and AI layer** specifically: it does not
include dashboard, endpoint agent, DLP, or remote-access source (those
are separate components in the reference architecture, described here
for context only). What this repo contains:

- SIEM alert -> LLM triage -> ticketing automation pipeline
- Vector-store-backed RAG ingestion and retrieval pipeline
- A standalone Python triage service (reference/fallback implementation)

## Functional pillars and where each is handled

| Pillar | Typically handled by | In this repo? |
|---|---|---|
| Asset management | Ticketing/ITSM tool | No — external tool |
| Incident management | Case management + ticketing | Partial — ticket creation; case-management integration is a natural extension |
| Change management | ITSM tool | Not yet — planned, same orchestration pattern |
| SOC automation | SIEM + orchestration + LLM | **Yes** — this repo's core pipeline |
| Endpoint control / DLP | Endpoint agent | No — separate component |
| Remote access | Self-hosted relay | No — separate component |
| Auto-block IPs | SIEM active response + firewall API | Not yet — planned extension |
| Knowledge / RAG | Vector DB + LLM + orchestration | **Yes** — this repo's RAG pipeline |

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
