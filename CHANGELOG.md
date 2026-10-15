# Changelog

## v1.0.0 (2026-10)

First stable release of the sanitized reference platform.

### AI-assisted SOC automation
- Wazuh -> self-hosted LLM -> threat intel -> ticket triage pipeline (n8n and Python service)
- Prompt-injection defences: fenced untrusted data, injection-marker short-circuit,
  severity guardrails, strict output validation, fail-safe ticketing
- RAG ingestion and retrieval with pgvector

### Detection and response
- Custom Wazuh rules (brute force, honeytoken, repeated injection, LLM outage, tampering)
- Instant kill switch (safe mode), honeytoken, automatic IP blocking on host and Palo Alto
- Incident response playbook with CERT-In reporting

### IT operations portal (proof of concept)
- Server-side default-deny access control, PBKDF2 passwords, command-injection fixes,
  33 security regression tests

### Software supply chain
- CI gates: Gitleaks (with custom password rule), Bandit, pip-audit, Trivy, policy as code (OPA)
- Hardened, non-root, read-only container runtime
- Signed images (Sigstore Cosign, keyless), SBOM and SLSA provenance attestations,
  tamper tests, deployment verification gate
- All actions pinned by commit SHA; least-privilege workflow tokens

### Project
- Apache-2.0 license, security policy, Dependabot with 14-day cooldown, OpenSSF Scorecard
