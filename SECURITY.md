# Security Policy

Security is the point of this project, so reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: **Security tab → Report a vulnerability**
(private vulnerability reporting). Include:

- What is affected (file, component, workflow)
- How to reproduce it
- The impact you expect

## What to expect

This is a personal project maintained on a best-effort basis:

- Acknowledgement within **7 days**
- An assessment and, for confirmed issues, a fix or mitigation plan within **30 days**
- Credit in the release notes if you would like it

## Scope

In scope: code, CI workflows, container images, policies, and documentation
in this repository, including the published `triage-service` image.

Out of scope: third-party tools and services this project integrates with
(Wazuh, n8n, LocalAI, Palo Alto, GLPI); please report those to their
maintainers.

## Supported versions

Only the latest release on `main` receives security fixes.

## Verifying what you run

Every published image is signed and carries SBOM and SLSA provenance
attestations. See [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) to verify
an image before running it.
