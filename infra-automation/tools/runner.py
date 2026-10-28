#!/usr/bin/env python3
"""runner.py - ctl-01 job runner (run every minute by ops-runner.timer).
Pulls APPROVED jobs from Ops Portal, and re-checks everything itself before running:
  * job type exists in ctl-01's catalog.yml (git) - nothing else can ever run
  * parameters valid (types, ranges, inventory membership)
  * approvals: enough DISTINCT approvers, each listed in approvers.yml for that risk, none = requester
Then: claim -> ansible-playbook -> report result -> journald (tag ops-runner) + docs/jobs/<YYYY>/<MM>/<id>.json
Config: ~/.config/ops-runner/{key,pin}  (key 0600; pin = base64 sha256 of Ops Portal's TLS public key)
"""
import hashlib, json, os, socket, ssl, subprocess, sys, syslog, tempfile, time, urllib.request
import yaml

BASE = os.path.expanduser("~/infra")
ANS = os.path.join(BASE, "ansible")
CFG = os.path.expanduser("~/.config/ops-runner")
URL = os.environ.get("OPS_PORTAL_URL", "https://10.10.1.11")


def log(msg, prio=syslog.LOG_INFO):
    syslog.openlog("ops-runner"); syslog.syslog(prio, msg); print(msg)


def pinned_context():
    """Pin Ops Portal's TLS *public key* (sha256 of SPKI): survives certificate renewals that reuse the key."""
    pin = open(os.path.join(CFG, "pin")).read().strip()
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    host = URL.split("//", 1)[1].split("/")[0]
    with socket.create_connection((host, 443), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    pub = subprocess.run("openssl x509 -inform der -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64",
                         shell=True, input=der, capture_output=True).stdout.decode().strip()
    if pub != pin:
        log("TLS public-key pin mismatch for %s - refusing (got %s)" % (URL, pub), syslog.LOG_ERR)
        raise SystemExit(2)
    return ctx


def api(ctx, method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Runner-Key": open(os.path.join(CFG, "key")).read().strip(),
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return json.loads(r.read())


def inventory_groups():
    out = subprocess.run(["ansible-inventory", "--list"], cwd=ANS, capture_output=True, text=True, timeout=120).stdout
    data = json.loads(out or "{}")
    return {g: set(v.get("hosts", [])) for g, v in data.items() if isinstance(v, dict)}


def validate(job, cat, approvers, groups):
    spec = cat["jobs"].get(job["job_type"])
    if not spec:
        return None, "job type not in ctl-01 catalog"
    p = job.get("params") or {}
    if set(p) != set(spec.get("params", {})):
        return None, "unexpected parameters"
    for name, s in spec.get("params", {}).items():
        v = str(p[name])
        if s["type"] == "int" and not (v.isdigit() and s.get("min", 0) <= int(v) <= s.get("max", 10**10)):
            return None, "%s invalid" % name
        if s["type"] == "choice" and v not in s.get("values", []):
            return None, "%s invalid" % name
        if s["type"] == "inventory" and v not in groups.get(s["group"], set()):
            return None, "%s not in inventory group %s" % (name, s["group"])
    need = int(spec.get("approvals", 0))
    if need:
        allowed = set(approvers.get(spec["risk"], []) or [])
        ok = {a["user"] for a in job.get("approvals", []) if a.get("user") in allowed and a.get("user") != job["requested_by"]}
        if len(ok) < need:
            return None, "needs %d valid approval(s) from approvers.yml, has %d" % (need, len(ok))
    extra = dict(p); extra.update(spec.get("fixed", {})); extra["change_id"] = "REQ-%s" % job["id"]
    return (spec, extra), None


def record(job, status, output):
    d = os.path.join(BASE, "docs", "jobs", time.strftime("%Y"), time.strftime("%m")); os.makedirs(d, exist_ok=True)
    json.dump({"id": job["id"], "job_type": job["job_type"], "params": job.get("params"), "requested_by": job["requested_by"],
               "approvals": job.get("approvals"), "reason": job.get("reason"), "status": status,
               "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "output_tail": output[-4000:]},
              open(os.path.join(d, "REQ-%s.json" % job["id"]), "w"), indent=1)


def main():
    cat = yaml.safe_load(open(os.path.join(ANS, "catalog", "catalog.yml")))
    approvers = yaml.safe_load(open(os.path.join(ANS, "catalog", "approvers.yml"))) or {}
    ctx = pinned_context()
    jobs = api(ctx, "GET", "/api/runner/jobs").get("jobs", [])
    if not jobs:
        return 0
    groups = inventory_groups()
    for job in jobs:
        tag = "REQ-%s %s by %s" % (job["id"], job["job_type"], job["requested_by"])
        ok, why = validate(job, cat, approvers, groups)
        if not ok:
            api(ctx, "POST", "/api/runner/jobs/%s/result" % job["id"], {"status": "refused", "output": "refused by ctl-01: " + why})
            record(job, "refused", why); log("REFUSED %s: %s" % (tag, why), syslog.LOG_WARNING); continue
        if not api(ctx, "POST", "/api/runner/jobs/%s/claim" % job["id"]).get("claimed"):
            continue
        spec, extra = ok
        log("RUNNING %s params=%s approvals=%s" % (tag, json.dumps(job.get("params")), [a["user"] for a in job.get("approvals", [])]))
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(extra, f); ev = f.name
        try:
            r = subprocess.run(["ansible-playbook", spec["playbook"], "-e", "@" + ev], cwd=ANS, capture_output=True, text=True, timeout=1800)
            out, rc = (r.stdout + r.stderr), r.returncode
        except subprocess.TimeoutExpired:
            out, rc = "timeout after 30 min", 124
        finally:
            os.unlink(ev)
        status = "done" if rc == 0 else "failed"
        tail = "\n".join(l for l in out.splitlines() if l.strip() and not l.startswith("PLAY") and "*****" not in l)[-3000:]
        api(ctx, "POST", "/api/runner/jobs/%s/result" % job["id"], {"status": status, "output": tail})
        record(job, status, tail)
        log("%s %s (rc=%d)" % (status.upper(), tag, rc), syslog.LOG_INFO if rc == 0 else syslog.LOG_ERR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
