# Security-first infrastructure automation

Automation used to run a small multi-site estate (Proxmox VE/PBS, Palo Alto firewalls, Active Directory,
Wazuh, Zabbix) from one hardened **control server**, with people working through a request/approval **portal**.
All names, addresses and domains in this folder are **placeholders**; real inventories, vaults, evidence and
change records are never published.

## Design principles

- **One control server does the work.** Every host has a single, key-only automation account that accepts
  connections from the control server only. Credentials live in Ansible Vault; write keys sit in a separate
  vault whose password is typed at run time.
- **Read-only by default.** Monitoring, backups, reports and audits use read-only accounts (firewall API,
  LDAPS, Wi-Fi controller). Write access is separate, narrower, and used only through guarded change tools.
- **Guarded changes.** Preview and diff, device-side validation, explicit `YES`, post-change health checks,
  and **automatic rollback** when a check fails. Nothing is ever deleted by automation.
- **The portal never holds credentials.** It stores requests and approvals; the control server *pulls*
  approved jobs and re-checks them against its own catalog and approver list.
- **Everything is evidence.** Results, changes and approvals land in git, journald and the SIEM.

## Architecture

```
 people ──► Ops portal (requests, approvals, reports)          no credentials, auth guard on every API
                 ▲   │  approved jobs (pull, every minute)
                 │   ▼
          control server (Ansible, vaults, runner, change tools, timers) ──► git + encrypted off-site copy
            │ SSH (key-only)        │ HTTPS API (pinned)       │ LDAPS (pinned)        │ SFTP (write-only inbox)
            ▼                       ▼                          ▼                       ▼
     Proxmox VE / PBS         Palo Alto firewalls        Active Directory      immutable log archive (PBS)
```

## Contents

| Path | What it does |
|---|---|
| `ansible/playbooks/pan-backup.yml` + `tools/pan-backup-auto.sh` | Nightly encrypted firewall config backups with diffs; monthly device-state export |
| `ansible/playbooks/firewall-changes.yml` | Builds a change register from the firewalls' own config audit logs |
| `ansible/playbooks/pa-vpn-diag.yml` | Read-only site-to-site tunnel diagnostics (events by day/hour/tunnel + current state) |
| `tools/pan_change.py` | Guarded firewall change: pending-change check, prechecks, snapshot, candidate diff, validation, partial commit, settle-and-observe postchecks, automatic rollback |
| `ansible/playbooks/pve-pbs-backup.yml` | Per-host, backup-only PBS tokens and namespaces (hosts cannot delete backups); one standard job per host |
| `ansible/playbooks/backup-coverage.yml` | Every guest vs its newest backup (OK / STALE / MISSING) |
| `ansible/playbooks/log-archive.yml` | Tamper-resistant 180-day raw-log archive: write-only push, checksum verification, immutable files, snapshots, retention |
| `ansible/playbooks/daily-check.yml` + `tools/checklist_render.py` | Automated daily infrastructure checklist per company/site, checksummed evidence, reviewer sign-off lines |
| `tools/ad_report.py` | Daily read-only AD report over pinned LDAPS: inactive, never-expire, locked, empty groups, privileged members with change alerts |
| `tools/ad_change.py` | Guarded AD change: preview, safety checks (protected accounts, never-empty groups), admin login typed at run time, verify, rollback file |
| `ansible/playbooks/update-policy.yml`, `package-changes.yml` | Security-only unattended updates (no automatic service restarts); package changes recorded as change records |
| `ansible/playbooks/wazuh-*.yml`, `tools/wazuh-register.sh` | Agent install/rename/registration with groups, coverage report, guarded server upgrade |
| `ansible/catalog/`, `tools/runner.py`, `ops-portal/` | Request → approval → execution: job catalog, approver list, runner, portal API module and auth guard |
| `tools/change` | Confirmation gate for direct changes: reason, check-mode preview, `YES`, change record |
| `tools/host-bootstrap-ansible.sh` | The one-time manual step per host (automation account, restricted key) |
| `systemd/` | Timers for the nightly/daily jobs |

## Adapting it

1. Copy `ansible/inventory/EXAMPLE-inventory.yml` and the `*.example.yml` files, and fill in your own values.
2. Keep secrets in Ansible Vault (`ro` on disk for unattended read-only jobs, `admin` prompted for write keys).
3. Run every playbook with `--check` first, and against a lab before production.

## Security notes

This is published as a reference. Review before use; nothing here should be run against production without
testing. Never commit inventories, `host_vars`, vaults, keys, backups, evidence or change records (see `.gitignore`).
