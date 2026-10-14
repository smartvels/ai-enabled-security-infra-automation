# Incident Response Playbook: AI Triage Platform

What to do, in order, when the platform is attacked. Automated steps run
in seconds; human steps are listed with who decides.

> Principle: **contain, evict, preserve evidence, recover.** Never attack
> back. Counter-attacking an attacker's systems is illegal (IT Act 2000)
> even when you are the victim.

## 1. Severity levels

| Level | Examples | Response time |
|---|---|---|
| **SEV-1 Critical** | Honeytoken used (rule 100503), code/config tampering (100520), confirmed compromise | Immediately, any hour |
| **SEV-2 High** | Brute force on the API (100502), repeated prompt injection (100505) | Within 1 hour |
| **SEV-3 Medium** | Sustained LLM outage (100507), single injection marker (100504) | Same working day |
| **SEV-4 Low** | Single auth failure, oversized payload | Weekly review |

## 2. What happens automatically

| Trigger | Automatic action | Time |
|---|---|---|
| Brute force (100502) or honeytoken (100503) | Source IP blocked for 1 hour on the host (`firewall-drop`) and on the Palo Alto (`pan-block-ip`, tag with timeout) | Seconds |
| Repeated injection (100505) or tampering (100520) | **Kill switch ON**: `SAFE_MODE` flag created; LLM removed from decisions, every alert ticketed | Seconds |
| Any single injection marker | That alert skips the LLM and is ticketed | Instant |
| LLM down | Every alert ticketed (fail-safe) | Instant |

Allowlisted addresses (office gateways, management hosts, Docker bridge,
n8n host) are never blocked automatically.

## 3. Manual kill switches

| Action | Command / step |
|---|---|
| Triage kill switch ON | `touch /opt/triage/deploy/control/SAFE_MODE` (instant, no restart) |
| Triage kill switch OFF | `rm /opt/triage/deploy/control/SAFE_MODE` (only after investigation) |
| n8n kill switch | Workflow → *Parse Verdict* → `const SAFE_MODE = true;` → Save |
| Stop the service | `cd /opt/triage/deploy && docker compose stop` |
| Revoke the API token | New value in `.env` → `docker compose up -d` → update n8n / Wazuh callers |
| Block an IP permanently | Add to a static address group in the Palo Alto deny rule (human decision) |
| Isolate a host | Move it to a quarantine zone on the Palo Alto, or shut down its VM in Proxmox |

## 4. Step-by-step response

### Step 1: Detect and triage (first 15 minutes)
1. Open the Wazuh alert. Note rule ID, source IP, time, affected host.
2. Check the automatic response ran: `/var/ossec/logs/active-responses.log`
   on the manager and the agent; on the firewall:
   `show object registered-ip all`.
3. Assign a severity (section 1) and an incident owner.

### Step 2: Contain (first hour)
1. Confirm the kill switch is ON for SEV-1/SEV-2: `curl -s localhost:5050/healthz`
   should show `"safe_mode": true`.
2. If the host itself may be compromised: isolate it (section 3). Do **not**
   power it off yet if you need memory evidence.
3. Rotate the API token if there is any chance it leaked.

### Step 3: Preserve evidence (before changing anything else)
Copy to a separate, access-controlled location and record SHA-256 hashes:
- `docker logs triage > triage-container.log`
- `/opt/triage/deploy/logs/security.json`
- Wazuh alerts for the incident window (export from the dashboard)
- Palo Alto traffic and threat logs for the attacker IP
- `docker inspect triage` and `docker image ls --digests`
- For tampering: `git -C /opt/triage status` and `git -C /opt/triage diff`

### Step 4: Report (within 6 hours for reportable incidents)
CERT-In directions (April 2022) require reporting specified cyber incidents
within **6 hours** of noticing them (incident@cert-in.org.in) and retaining
logs for **180 days**. Check the current CERT-In directions for the exact
list of reportable incidents and the reporting format. Inform management
and, if customer data may be involved, legal/compliance.

### Step 5: Eradicate
**Rebuild, don't clean.** A compromised system is never trusted again:
1. `git -C /opt/triage fetch && git -C /opt/triage reset --hard origin/main`
   (restores code to the reviewed version in Git)
2. `docker compose build --no-cache && docker compose up -d`
3. Rotate every secret in `.env` (API token, honeytoken) and any
   credentials found on the host.
4. If the host OS is suspect: rebuild the VM from a clean template or a
   Proxmox Backup Server snapshot taken **before** the incident.

### Step 6: Recover
1. Verify: CI green for the deployed commit, `healthz` OK, test alert creates a ticket.
2. Keep safe mode ON for an observation period (for example 24 hours).
3. Turn the kill switch OFF only when the incident owner signs off.

### Step 7: Learn (within 1 week)
Write a short post-incident review: timeline, root cause, what detection
and response worked, what failed, and the fixes (new rules, new tests).
Add a test to the repo for every new attack pattern found.

## 5. Contacts

Fill in for your organisation:

| Role | Name | Phone |
|---|---|---|
| Incident owner (IT lead) | | |
| Backup | | |
| Management escalation | | |
| Firewall / ISP support | | |
