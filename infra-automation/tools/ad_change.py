#!/usr/bin/env python3
"""ad_change.py - guarded Active Directory change from ctl-01 (LDAPS, server key pinned).
  python3 tools/ad_change.py ansible/changes/<CHANGE>.yml
Flow: read-only preview of every target (svc-auto-adro) -> safety checks -> admin login typed now (never stored)
      -> you type YES -> apply -> verify (re-read) -> record (docs/changes/manual + docs/jobs) + journald (tag ad-change)
      -> writes ansible/changes/<ID>-ROLLBACK.yml (the exact inverse; run it with this tool to undo).
Operations: remove_member {group, member} | add_member {group, member} | disable_user {user, note} | enable_user {user} | info {user}
Members/users are matched on exact name (cn) or sAMAccountName and must be unique. Never deletes anything.
"""
import base64, csv, datetime, getpass, hashlib, json, os, re, ssl, subprocess, sys, time
import ldap3, yaml
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

INFRA = os.path.expanduser("~/infra"); ANS = os.path.join(INFRA, "ansible")
RO = "ro@" + os.path.expanduser("~/.ansible-vault/ro.pass")
PROTECTED_USERS = {"administrator", "krbtgt", "guest"}
NEVER_EMPTY = {"domain admins"}


def log(m):
    subprocess.run(["logger", "-t", "ad-change", m]); print(m, flush=True)


class AD:
    def __init__(self, conn, base):
        self.c, self.base = conn, base

    def find(self, name, cls):
        if name.upper().startswith("CN="):                      # exact DN given in the change file
            self.c.search(name, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["cn", "sAMAccountName", "userAccountControl", "member", "description"])
            if not self.c.response: raise SystemExit("STOP: DN not found: %s" % name)
            return self.c.response[0]["dn"], self.c.response[0]["attributes"]
        flt = "(&(objectClass=%s)(|(cn=%s)(sAMAccountName=%s)))" % (cls, ldap3.utils.conv.escape_filter_chars(name), ldap3.utils.conv.escape_filter_chars(name))
        self.c.search(self.base, flt, attributes=["cn", "sAMAccountName", "userAccountControl", "member", "description", "lastLogonTimestamp"])
        hits = [e for e in self.c.response if e.get("type") == "searchResEntry"] if hasattr(self.c, "response") and self.c.response else []
        if len(hits) != 1:
            raise SystemExit("STOP: '%s' (%s) matched %d objects - must be exactly 1" % (name, cls, len(hits)))
        return hits[0]["dn"], hits[0]["attributes"]

    @staticmethod
    def one(v):
        return (v[0] if v else None) if isinstance(v, list) else v

    def members(self, gdn):
        self.c.search(gdn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["member"])
        return [m.lower() for m in (self.c.response[0]["attributes"].get("member") or [])]

    def uac(self, udn):
        self.c.search(udn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=["userAccountControl", "description"])
        a = self.c.response[0]["attributes"]
        return int(self.one(a.get("userAccountControl")) or 0), self.one(a.get("description")) or ""


def plan(ro, ops):
    """Resolve and check every operation against the current state (read-only)."""
    steps, rollback = [], []
    for o in ops:
        t = o["op"]
        if t in ("remove_member", "add_member"):
            gdn, _ = ro.find(o["group"], "group"); mdn, ma = ro.find(o["member"], "*")
            cur = ro.members(gdn); has = mdn.lower() in cur
            if t == "remove_member":
                if not has: print("  SKIP  %s is not in %s" % (o["member"], o["group"])); continue
                if o["group"].lower() in NEVER_EMPTY and len(cur) <= 1: raise SystemExit("STOP: %s would become empty" % o["group"])
                steps.append((t, gdn, mdn, o)); rollback.append({"op": "add_member", "group": o["group"], "member": o["member"]})
                print("  WILL  remove %-20s from %-18s (now %d members)" % (o["member"], o["group"], len(cur)))
            else:
                if has: print("  SKIP  %s already in %s" % (o["member"], o["group"])); continue
                steps.append((t, gdn, mdn, o)); rollback.append({"op": "remove_member", "group": o["group"], "member": o["member"]})
                print("  WILL  add    %-20s to   %s" % (o["member"], o["group"]))
        elif t in ("disable_user", "enable_user"):
            if o["user"].lower() in PROTECTED_USERS: raise SystemExit("STOP: %s is a protected built-in account" % o["user"])
            udn, a = ro.find(o["user"], "user"); uac, desc = ro.uac(udn); disabled = bool(uac & 2)
            if t == "disable_user":
                if disabled: print("  SKIP  %s already disabled" % o["user"]); continue
                steps.append((t, udn, uac, o)); rollback.append({"op": "enable_user", "user": o["user"], "restore_description": desc})
                print("  WILL  disable %-20s (description now: %s)" % (o["user"], desc[:40] or "-"))
            else:
                if not disabled: print("  SKIP  %s already enabled" % o["user"]); continue
                steps.append((t, udn, uac, o)); rollback.append({"op": "disable_user", "user": o["user"], "note": "rollback"})
                print("  WILL  enable  %s" % o["user"])
        elif t == "info":
            udn, a = ro.find(o["user"], "user"); uac, desc = ro.uac(udn)
            print("  INFO  %s: %s, %s, description '%s'" % (o["user"], udn, "disabled" if uac & 2 else "enabled", desc))
        else:
            raise SystemExit("STOP: unknown operation %s" % t)
    return steps, rollback


def apply(rw, ro, steps, chg):
    results = []
    for t, dn1, x, o in steps:
        if t == "remove_member":
            ok = rw.c.modify(dn1, {"member": [(MODIFY_DELETE, [x])]}); verify = x.lower() not in ro.members(dn1)
        elif t == "add_member":
            ok = rw.c.modify(dn1, {"member": [(MODIFY_ADD, [x])]}); verify = x.lower() in ro.members(dn1)
        elif t == "disable_user":
            note = "DISABLED %s %s %s" % (time.strftime("%Y-%m-%d"), chg, o.get("note", ""))
            ok = rw.c.modify(dn1, {"userAccountControl": [(MODIFY_REPLACE, [str(x | 2)])], "description": [(MODIFY_REPLACE, [note[:250]])]})
            verify = bool(ro.uac(dn1)[0] & 2)
        elif t == "enable_user":
            ch = {"userAccountControl": [(MODIFY_REPLACE, [str(x & ~2)])]}
            if o.get("restore_description") is not None:
                ch["description"] = [(MODIFY_REPLACE, [o["restore_description"]])] if o["restore_description"] else [(MODIFY_DELETE, [])]
            ok = rw.c.modify(dn1, ch); verify = not (ro.uac(dn1)[0] & 2)
        res = "OK" if ok and verify else "FAILED (%s)" % (rw.c.result.get("description") if not ok else "verify")
        results.append((t, o, res)); log("  %s %s: %s" % (t, o.get("member") or o.get("user"), res))
    return results


def spki_pin(der):
    """base64 sha256 of the certificate's public key (SPKI) - same value as the openssl pipeline, no shell."""
    pub = subprocess.run(["openssl", "x509", "-inform", "der", "-pubkey", "-noout"], input=der, capture_output=True, check=True).stdout
    spki = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, capture_output=True, check=True).stdout
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def pinned_ldap(host, pin, user, pw, **kw):
    """Open LDAPS, check the public-key pin on THIS connection, and only then send the password."""
    srv = ldap3.Server(host, port=636, use_ssl=True, get_info=None,
                       tls=ldap3.Tls(validate=ssl.CERT_NONE,  # identity = public-key pin, checked below on this socket
                                     ssl_options=[ssl.OP_NO_TLSv1, ssl.OP_NO_TLSv1_1]))
    c = ldap3.Connection(srv, user=user, password=pw, **kw)
    c.open()
    if "sha256//" + spki_pin(c.socket.getpeercert(binary_form=True)) != pin:
        c.unbind(); raise SystemExit("STOP: LDAPS certificate does not match the pin")
    if not c.bind():
        raise SystemExit("LDAP bind failed: %s" % c.result.get("description"))
    return c


def connect(host, pin, user, pw):
    return pinned_ldap(host, pin, user, pw)


def main(path):
    ch = yaml.safe_load(open(path))
    if not re.fullmatch(r"CHG-[A-Za-z0-9-]{1,60}", str(ch.get("id", ""))): sys.exit("change id must look like CHG-<letters/digits/->")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", str(ch.get("dc", ""))): sys.exit("invalid dc name")
    hv = json.loads(subprocess.run(["ansible-inventory", "--host", ch["dc"]], cwd=ANS, capture_output=True, text=True).stdout or "{}")
    host, pin, dom = hv["ansible_host"], hv["ldaps_pin"], hv["ad_domain"]; base = ",".join("DC=" + p for p in dom.split("."))
    rpw = yaml.safe_load(subprocess.run(["ansible-vault", "view", "--vault-id", RO, os.path.join(ANS, "inventory", "host_vars", ch["dc"], "vault_ro.yml")],
                                        capture_output=True, text=True).stdout)["vault_ad_ro_password"]
    ro = AD(connect(host, pin, "svc-auto-adro@" + dom, rpw), base)
    log("== %s on %s: %s" % (ch["id"], dom, ch["reason"]))
    steps, rollback = plan(ro, ch["operations"])
    if not steps:
        log("nothing to change"); return 0
    print("\nAdmin login for this change (typed now, never stored), e.g. adm-name@%s" % dom)
    au = input("  admin user: ").strip(); ap = getpass.getpass("  password: ")
    rw = AD(connect(host, pin, au, ap), base); ap = None
    print()
    for i, (t, a1, a2, o) in enumerate(steps, 1):
        print("  %2d. %s %s%s" % (i, t, o.get("member") or o.get("user"), (" (" + o["group"] + ")") if "group" in o else ""))
    ans = input("\nApply %d change(s) to %s? Type YES for all, 'skip 3,5' to leave items out, anything else cancels: " % (len(steps), dom)).strip()
    if ans.lower().startswith("skip"):
        drop = {int(x) for x in ans[4:].replace(" ", "").split(",") if x.isdigit()}
        keep = [(s_, r_) for i, (s_, r_) in enumerate(zip(steps, rollback), 1) if i not in drop]
        steps, rollback = [k[0] for k in keep], [k[1] for k in keep]
        if not steps or input("Apply the remaining %d? Type YES: " % len(steps)).strip() != "YES":
            log("CANCELLED %s" % ch["id"]); return 1
        log("%s: skipped items %s" % (ch["id"], sorted(drop)))
    elif ans != "YES":
        log("CANCELLED %s" % ch["id"]); return 1
    results = apply(rw, ro, steps, ch["id"])
    rb = dict(id=ch["id"] + "-RB", dc=ch["dc"], reason="ROLLBACK of " + ch["id"], operations=rollback)
    rbp = os.path.join(os.path.dirname(os.path.abspath(path)), ch["id"] + "-ROLLBACK.yml"); yaml.safe_dump(rb, open(rbp, "w"), sort_keys=False)
    status = "applied-verified" if all(r[2] == "OK" for r in results) else "PARTIAL - check"
    m = time.strftime("%Y-%m"); f = os.path.join(INFRA, "docs", "changes", "manual", m + ".csv"); os.makedirs(os.path.dirname(f), exist_ok=True)
    new = not os.path.exists(f)
    with open(f, "a", newline="") as fh:
        w = csv.writer(fh)
        if new: w.writerow(["type", "date", "user", "source", "key", "playbook", "options", "reason", "change_id", "result", "git"])
        w.writerow(["ad-change", time.strftime("%Y-%m-%dT%H:%M:%S%z"), os.environ.get("USER"), (os.environ.get("SSH_CLIENT") or "local").split()[0],
                    "admin=" + au, "tools/ad_change.py", dom, ch["reason"], ch["id"], status, ""])
    d = os.path.join(INFRA, "docs", "jobs", time.strftime("%Y"), time.strftime("%m")); os.makedirs(d, exist_ok=True)
    json.dump({"change": ch, "admin": au, "results": [[t, o, r] for t, o, r in results], "status": status}, open(os.path.join(d, ch["id"] + ".json"), "w"), indent=1)
    subprocess.run(["git", "-C", INFRA, "add", "-A", "docs", "ansible/changes"])
    subprocess.run(["git", "-C", INFRA, "commit", "-qm", "change: %s %s" % (ch["id"], status)])
    log("%s %s - rollback file: %s" % (status.upper(), ch["id"], rbp))
    return 0 if status == "applied-verified" else 2


if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("usage: ad_change.py ansible/changes/<CHANGE>.yml")
    sys.exit(main(sys.argv[1]))
