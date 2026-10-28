#!/usr/bin/env python3
"""pan_change.py - guarded Palo Alto configuration change from ctl-01.
  tools/pan_change.py ansible/changes/<CHANGE>.yml
Flow: no foreign pending changes -> prechecks (on the RUNNING config) -> safety snapshot -> apply to the CANDIDATE
      -> show before/after per setting -> firewall validation -> you type YES -> partial commit (only svc-ctl01-rw's
      changes, change ID in the description) -> postchecks -> on failure: AUTOMATIC ROLLBACK (load snapshot + commit)
      -> record in docs/changes/manual/<YYYY-MM>.csv and docs/jobs/<YYYY>/<MM>/<ID>.json, journald tag pan-change.
Keys: read-only key from the ro vault (checks), write key from the ADMIN vault (asks for its password). Never printed.
"""
import csv, json, os, re, subprocess, sys, tempfile, time, xml.etree.ElementTree as ET
import yaml

INFRA = os.path.expanduser("~/infra"); ANS = os.path.join(INFRA, "ansible")
RO = "ro@" + os.path.expanduser("~/.ansible-vault/ro.pass")


def log(msg):
    subprocess.run(["logger", "-t", "pan-change", msg]); print(msg, flush=True)


def vault_value(path, vault_id, key):
    out = subprocess.run(["ansible-vault", "view", "--vault-id", vault_id, path], cwd=ANS, capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit("cannot open %s: %s" % (path, out.stderr.strip()[:200]))
    v = (yaml.safe_load(out.stdout) or {}).get(key)
    if not v:
        sys.exit("%s not found in %s" % (key, path))
    return v


class FW:
    def __init__(self, host, pin, key):
        self.host, self.pin, self.key = host, pin, key

    def call(self, params, timeout=120):
        hf = tempfile.NamedTemporaryFile("w", delete=False); os.chmod(hf.name, 0o600)
        hf.write("X-PAN-KEY: %s\n" % self.key); hf.close()
        try:
            args = ["curl", "-sS", "-k", "--max-time", str(timeout), "--pinnedpubkey", self.pin, "-H", "@" + hf.name, "-G",
                    "https://%s/api/" % self.host]
            for k, v in params.items():
                args += ["--data-urlencode", "%s=%s" % (k, v)]
            r = subprocess.run(args, capture_output=True, text=True)
        finally:
            os.unlink(hf.name)
        if r.returncode != 0:
            raise RuntimeError("API call failed: %s" % r.stderr.strip()[:200])
        root = ET.fromstring(r.stdout)
        return root

    def ok(self, root):
        return root.get("status") == "success"

    def op(self, cmd):
        return self.call({"type": "op", "cmd": cmd})

    def wait_job(self, job, limit=900):
        t0 = time.time()
        while time.time() - t0 < limit:
            j = self.op("<show><jobs><id>%s</id></jobs></show>" % job).find(".//job")
            if j is not None and j.findtext("status") == "FIN":
                msgs = " ".join((m.text or "").strip() for m in j.iter("line") if (m.text or "").strip())
                return j.findtext("result"), msgs[:1500]
            time.sleep(5)
        return "TIMEOUT", ""


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


def text_of(node):
    return "(not set)" if node is None or len(node) == 0 and not (node.text or "").strip() else \
        re.sub(r"\s+", " ", ET.tostring(node, encoding="unicode"))[:400]


def run_checks(checks, ro, label, since=None):
    for c in checks or []:
        name = c.get("name", c.get("shell", "check"))
        tries = int(c.get("retries", 1))
        for i in range(tries):
            if "shell" in c:
                good, out = sh(c["shell"])
            elif "no_syslog" in c:     # settle, then no matching system-log events during the observation window
                ns = c["no_syslog"]; time.sleep(60 * int(ns.get("settle_minutes", 0)))
                since = time.strftime("%Y/%m/%d %H:%M:%S"); time.sleep(60 * int(ns.get("observe_minutes", 0)))
                q = "(eventid eq %s) and (receive_time geq '%s')" % (ns["eventid"], since)
                j = ro.call({"type": "log", "log-type": "system", "nlogs": "200", "query": q}).findtext(".//job")
                time.sleep(8)
                res = ro.call({"type": "log", "action": "get", "job-id": j})
                hits = [e for e in res.iter("entry") if any(t in (e.findtext("object") or "") + (e.findtext("opaque") or "")
                                                             for t in ns["match"])]
                good, out = (len(hits) == 0), "%d matching events" % len(hits)
            elif "api_ok" in c:
                good = ro.ok(ro.op("<show><system><info></info></system></show>")); out = "read-only API answered" if good else "no answer"
            else:
                good, out = False, "unknown check type"
            if good:
                break
            if i < tries - 1:
                time.sleep(int(c.get("wait", 20)))
        log("  %s %s: %s" % (label, "OK  " if good else "FAIL", name + (" (" + out + ")" if out else "")))
        if not good:
            return False
    return True


def record(ch, status, details):
    m = time.strftime("%Y-%m"); f = os.path.join(INFRA, "docs", "changes", "manual", m + ".csv"); os.makedirs(os.path.dirname(f), exist_ok=True)
    new = not os.path.exists(f)
    with open(f, "a", newline="") as fh:
        w = csv.writer(fh)
        if new: w.writerow(["type", "date", "user", "source", "key", "playbook", "options", "reason", "change_id", "result", "git"])
        w.writerow(["firewall-change", time.strftime("%Y-%m-%dT%H:%M:%S%z"), os.environ.get("USER"), (os.environ.get("SSH_CLIENT") or "local").split()[0],
                    "", "tools/pan_change.py", ch["firewall"], ch["reason"], ch["id"], status,
                    subprocess.run(["git", "-C", INFRA, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()])
    d = os.path.join(INFRA, "docs", "jobs", time.strftime("%Y"), time.strftime("%m")); os.makedirs(d, exist_ok=True)
    json.dump({"change": ch, "status": status, "details": details}, open(os.path.join(d, ch["id"] + ".json"), "w"), indent=1, default=str)
    subprocess.run(["git", "-C", INFRA, "add", "docs/changes", "docs/jobs"])
    subprocess.run(["git", "-C", INFRA, "commit", "-qm", "change: %s %s" % (ch["id"], status)])


def main(path):
    ch = yaml.safe_load(open(path))
    for k in ("id", "firewall", "reason", "operations"):
        if not ch.get(k): sys.exit("change file needs: %s" % k)
    if not re.fullmatch(r"CHG-[A-Za-z0-9-]{1,60}", str(ch["id"])): sys.exit("change id must look like CHG-<letters/digits/->")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", str(ch["firewall"])): sys.exit("invalid firewall name")
    hv = json.loads(subprocess.run(["ansible-inventory", "--host", ch["firewall"]], cwd=ANS, capture_output=True, text=True).stdout or "{}")
    host, pin = hv.get("ansible_host"), hv.get("pan_pin")
    if not host or not pin: sys.exit("firewall %s not in inventory (ansible_host/pan_pin)" % ch["firewall"])
    hvdir = os.path.join(ANS, "inventory", "host_vars", ch["firewall"])
    ro_key = vault_value(os.path.join(hvdir, "vault_ro.yml"), RO, "vault_%s_api_key" % ch["firewall"].replace("-", "_"))
    print("Admin vault password (for the WRITE key):", flush=True)
    rw_key = vault_value(os.path.join(ANS, "vault", "admin", ch["firewall"] + "-rw.yml"), "admin@prompt", "vault_pan_rw_key")
    ro, rw = FW(host, pin, ro_key), FW(host, pin, rw_key)
    details = {"before": {}, "after": {}}
    log("== %s on %s: %s" % (ch["id"], ch["firewall"], ch["reason"]))

    # 1 nobody else has uncommitted changes
    pend = (rw.op("<check><pending-changes></pending-changes></check>").findtext(".//result") or "").strip()
    if pend != "no":
        log("STOP: the firewall has uncommitted changes (%s) - commit or revert them first" % pend); return 1
    # 2 prechecks on the running config
    if not run_checks(ch.get("prechecks"), ro, "precheck"):
        log("STOP: precheck failed - nothing changed"); return 1
    # 3 safety snapshot
    snap = "pre-%s.xml" % ch["id"]
    if not rw.ok(rw.op("<save><config><to>%s</to></config></save>" % snap)):
        log("STOP: could not save snapshot"); return 1
    log("  snapshot saved on the firewall: %s" % snap)
    # 4 apply to the candidate, show before/after
    def discard():
        rw.op("<load><config><from>running-config.xml</from></config></load>")
    for o in ch["operations"]:
        before = ro.call({"type": "config", "action": "show", "xpath": o["xpath"]}).find(".//result")
        r = rw.call({"type": "config", "action": o["action"], "xpath": o["xpath"], **({"element": o["element"]} if "element" in o else {})})
        if not rw.ok(r):
            log("STOP: %s failed: %s - candidate discarded" % (o["action"], ET.tostring(r, encoding="unicode")[:300])); discard(); return 1
        after = rw.call({"type": "config", "action": "get", "xpath": o["xpath"]}).find(".//result")
        details["before"][o["xpath"]], details["after"][o["xpath"]] = text_of(before), text_of(after)
        print("\n  %s\n    BEFORE (running):   %s\n    AFTER  (candidate): %s" % (o["xpath"].split("/network/")[-1], text_of(before), text_of(after)))
    # 5 validation by the firewall
    vj = rw.op("<validate><full></full></validate>").findtext(".//job")
    res, msg = rw.wait_job(vj) if vj else ("FAIL", "no validation job")
    log("  validation: %s %s" % (res, msg[:300]))
    if res != "OK":
        log("STOP: validation failed - candidate discarded"); discard(); return 1
    # 6 human confirmation
    if input("\nCommit this change on %s? Type YES: " % ch["firewall"]).strip() != "YES":
        discard(); log("CANCELLED %s - candidate discarded" % ch["id"]); record(ch, "cancelled", details); return 1
    # 7 partial commit (only our admin's changes)
    since = time.strftime("%Y/%m/%d %H:%M:%S")
    cj = rw.call({"type": "commit", "action": "partial",
                  "cmd": "<commit><partial><admin><member>svc-ctl01-rw</member></admin></partial><description>%s: %s</description></commit>"
                         % (ch["id"], ch["reason"][:200])}).findtext(".//job")
    res, msg = rw.wait_job(cj) if cj else ("FAIL", "no commit job")
    log("  commit: %s %s" % (res, msg[:300]))
    if res != "OK":
        discard(); record(ch, "commit-failed", details); return 1
    # 8 postchecks, automatic rollback on failure
    if run_checks(ch.get("postchecks"), ro, "postcheck", since):
        log("DONE %s: applied and verified" % ch["id"]); record(ch, "applied-verified", details); return 0
    log("POSTCHECK FAILED - ROLLING BACK %s" % ch["id"])
    rw.op("<load><config><from>%s</from></config></load>" % snap)
    rj = rw.call({"type": "commit", "cmd": "<commit><description>ROLLBACK %s</description></commit>" % ch["id"]}).findtext(".//job")
    res, msg = rw.wait_job(rj) if rj else ("FAIL", "")
    log("  rollback commit: %s" % res)
    record(ch, "rolled-back" if res == "OK" else "ROLLBACK-FAILED", details)
    return 2


if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("usage: pan_change.py ansible/changes/<CHANGE>.yml")
    sys.exit(main(sys.argv[1]))
