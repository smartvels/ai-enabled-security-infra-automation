#!/usr/bin/env python3
"""ad_report.py - READ-ONLY daily Active Directory report for every DC host in the inventory with ldaps_pin + ad_domain.
  python3 tools/ad_report.py                 # all domains
  python3 tools/ad_report.py dc-site-a      # one
Per domain -> ~/infra/docs/reports/ad/<domain>/<date>-<report>.csv + <date>-summary.json
Reports: inactive_90d, password_never_expires, disabled, locked, empty_groups, privileged_members.
Privileged group membership is compared with the previous run: any change -> journald WARNING (tag ad-report) -> Wazuh.
Connection: LDAPS 636, server public key pinned (ldaps_pin), read-only bind with svc-auto-adro (ro vault).
"""
import base64, csv, datetime, glob, hashlib, json, os, ssl, subprocess, sys
import ldap3, yaml

ANS = os.path.expanduser("~/infra/ansible"); OUT = os.path.expanduser("~/infra/docs/reports/ad")
RO = "ro@" + os.path.expanduser("~/.ansible-vault/ro.pass")
PRIV = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
        "Backup Operators", "Server Operators", "Print Operators", "Group Policy Creator Owners", "DnsAdmins"]


def log(msg, prio="info"):
    subprocess.run(["logger", "-t", "ad-report", "-p", "user." + prio, msg]); print(msg)


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


def one(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def ts(v):
    v = one(v)
    if isinstance(v, datetime.datetime):
        return v if v.year > 1601 else None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=n // 10)


def write(dom, day, name, rows, cols):
    d = os.path.join(OUT, dom); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "%s-%s.csv" % (day, name)), "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols); [w.writerow([r.get(c, "") for c in cols]) for r in rows]


def report(hostname, hv):
    host, dom = hv["ansible_host"], hv["ad_domain"]
    vf = os.path.join(ANS, "inventory", "host_vars", hostname, "vault_ro.yml")
    pw = yaml.safe_load(subprocess.run(["ansible-vault", "view", "--vault-id", RO, vf], capture_output=True, text=True).stdout)["vault_ad_ro_password"]
    try:
        c = pinned_ldap(host, hv["ldaps_pin"], "svc-auto-adro@" + dom, pw, read_only=True)
    except SystemExit as e:
        log("%s: %s - skipped" % (dom, e), "err"); return
    base = ",".join("DC=" + p for p in dom.split("."))
    now = datetime.datetime.now(datetime.timezone.utc); day = now.astimezone().strftime("%Y-%m-%d")

    def search(flt, attrs):
        c.extend.standard.paged_search(base, flt, attributes=attrs, paged_size=500, generator=False)
        out = []
        for e in c.response:
            if e.get("type") != "searchResEntry": continue
            a = {k: (v if k == "member" else one(v)) for k, v in e["attributes"].items()}
            a["dn"] = e["dn"]; out.append(a)
        return out

    users = search("(&(objectCategory=person)(objectClass=user))",
                   ["sAMAccountName", "displayName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "lockoutTime", "whenCreated"])
    for u in users:
        uac = int(u["userAccountControl"] or 0); ll = ts(u.get("lastLogonTimestamp"))
        u.update(enabled=not uac & 2, never_expires=bool(uac & 0x10000),
                 last_logon=ll.strftime("%Y-%m-%d") if ll else "never", days_inactive=(now - ll).days if ll else "")
    en = [u for u in users if u["enabled"]]
    rep = {
        "inactive_90d": [u for u in en if u["last_logon"] == "never" or u["days_inactive"] > 90],
        "password_never_expires": [u for u in en if u["never_expires"]],
        "disabled": [u for u in users if not u["enabled"]],
        "locked": [u for u in en if ts(u.get("lockoutTime"))],
    }
    cols = ["sAMAccountName", "displayName", "last_logon", "days_inactive", "dn"]
    for k, rows in rep.items():
        write(dom, day, k, rows, cols)
    groups = search("(objectClass=group)", ["cn", "member", "groupType"])
    empty = [g for g in groups if not g.get("member")]
    write(dom, day, "empty_groups", empty, ["cn", "dn"])
    priv = []
    for g in groups:
        if g["cn"] in PRIV:
            for m in g.get("member") or []:
                priv.append({"group": g["cn"], "member": m})
    write(dom, day, "privileged_members", priv, ["group", "member"])
    c.unbind()
    # change detection on privileged membership
    prev = sorted(glob.glob(os.path.join(OUT, dom, "*-privileged_members.csv")))
    prev = [p for p in prev if not os.path.basename(p).startswith(day)]
    if prev:
        old = {(r["group"], r["member"]) for r in csv.DictReader(open(prev[-1]))}
        new = {(r["group"], r["member"]) for r in priv}
        for g, m in sorted(new - old): log("%s: PRIVILEGED GROUP CHANGE: %s ADDED to %s" % (dom, m, g), "warning")
        for g, m in sorted(old - new): log("%s: PRIVILEGED GROUP CHANGE: %s REMOVED from %s" % (dom, m, g), "warning")
    summary = {"domain": dom, "date": day, "users": len(users), "enabled": len(en), **{k: len(v) for k, v in rep.items()},
               "empty_groups": len(empty), "privileged_members": len(priv)}
    json.dump(summary, open(os.path.join(OUT, dom, day + "-summary.json"), "w"), indent=1)
    log("%s: users %d, enabled %d, inactive>90d %d, never-expire %d, disabled %d, locked %d, empty groups %d, privileged members %d"
        % (dom, len(users), len(en), len(rep["inactive_90d"]), len(rep["password_never_expires"]), len(rep["disabled"]),
           len(rep["locked"]), len(empty), len(priv)))


def main(only=None):
    inv = json.loads(subprocess.run(["ansible-inventory", "--list"], cwd=ANS, capture_output=True, text=True).stdout or "{}")
    hv = inv.get("_meta", {}).get("hostvars", {})
    for h, v in sorted(hv.items()):
        if v.get("ldaps_pin") and v.get("ad_domain") and (not only or h == only):
            try:
                report(h, v)
            except Exception as e:
                log("%s (%s): FAILED %s" % (v.get("ad_domain"), h, str(e)[:200]), "err")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
