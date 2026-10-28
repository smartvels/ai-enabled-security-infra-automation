#!/usr/bin/env python3
"""checklist_render.py - render the daily infrastructure checklist from raw evidence JSON.
  python3 checklist_render.py <daily-checklist.yml> <evidence/YYYY/MM/YYYY-MM-DD.json>
Writes next to the JSON:
  <date>-<company>.html           daily sheet, one column per site (like the paper sheet)
  <YYYY-MM>-<company>-<site>.html month view, one column per day (like the paper sheet)
Status words: OK, ATTENTION, MANUAL (fill in by hand), N/A (not applicable / not configured yet).
"""
import glob, hashlib, html, json, os, sys
from datetime import datetime, timezone
import yaml

def age_hours(ts, ref):
    try:
        t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return (ref - t).total_seconds() / 3600
    except Exception:
        return None

def cell(status, text):
    return {"s": status, "t": text}

def compute(cfg, raw, company, site):
    sc, rows = cfg["sites"][site], []
    ref = datetime.fromisoformat(raw["generated_at"]).astimezone(timezone.utc)
    hosts = raw.get("hosts", {})
    # UPS (manual)
    rows.append(("UPS Health for Server", cell("manual", "")))
    # Room temperature: IPMI where available
    temps = []
    for h, sensor in (sc.get("temperature") or {}).items():
        for name, val in hosts.get(h, {}).get("temps", []):
            if sensor.lower() in name.lower() and "degrees" in val:
                temps.append("%s %s" % (val.replace(" degrees C", " °C"), h))
    rows.append(("Server Room Power and Temp", cell("ok", "; ".join(temps)) if temps else cell("manual", "")))
    # Servers
    hs = sc.get("hosts", [])
    up = [h for h in hs if hosts.get(h, {}).get("reachable")]
    vms = [v for h in up for v in hosts[h].get("vms", [])]
    run = [v for v in vms if len(v) > 2 and v[2] == "running"]
    txt = "%d/%d hosts up, %d VMs running" % (len(up), len(hs), len(run))
    down = [h for h in hs if h not in up]
    rows.append(("Server Status", cell("ok" if not down else "bad", txt + ("; DOWN: " + ", ".join(down) if down else ""))))
    # ISPs - one row per ISP name across all sites (keeps the sheet layout stable)
    fw = sc.get("firewall", {})
    links = raw.get("firewalls", {}).get(fw.get("host", ""), {}).get("links", {})
    all_isps = []
    for s in cfg["sites"].values():
        for i in s.get("isps", []):
            if i["name"] not in all_isps: all_isps.append(i["name"])
    for name in all_isps:
        i = next((x for x in sc.get("isps", []) if x["name"] == name), None)
        if not i:
            rows.append(("%s Internet Status" % name, cell("na", "—")))
        else:
            st = links.get(i["interface"], "unknown")
            rows.append(("%s Internet Status" % name, cell("ok" if st == "up" else "bad", "link %s (%s)" % (st, i["interface"]))))
    # Firewall
    if fw.get("type") == "panos":
        f = raw.get("firewalls", {}).get(fw["host"], {})
        rows.append(("Firewall Status", cell("ok", "up, uptime " + f.get("uptime", "?")) if f.get("reachable") else cell("bad", "NOT reachable")))
    elif fw.get("type") == "ping":
        st = raw.get("pings", {}).get(fw["ip"], "down")
        rows.append(("Firewall Status", cell("ok" if st == "up" else "bad", "reachable (ping only)" if st == "up" else "NOT reachable")))
    # Wi-Fi APs, other devices: reachability
    def reach(label, ips):
        if not ips:
            rows.append((label, cell("na", "not configured yet"))); return
        st = [raw.get("pings", {}).get(ip, "down") for ip in ips]
        n = st.count("up")
        rows.append((label, cell("ok" if n == len(ips) else "bad", "%d/%d reachable" % (n, len(ips)))))
    reach("Wi-Fi AP Status", sc.get("ap_ips", []))
    reach("Other Devices", sc.get("other_ips", []))
    reach("Network Device Health", [raw.get("switch_ips", {}).get(s) for s in sc.get("switches", []) if raw.get("switch_ips", {}).get(s)])
    # Our own tools (monitoring, SIEM, backup, Ops Portal, automation): services up + data flowing
    tl = sc.get("tools", [])
    if not tl:
        rows.append(("Monitoring & Tools", cell("na", "central tools (see Site-A)")))
    else:
        bad, parts = False, []
        for t in tl:
            ti = raw.get("tools", {}).get(t["host"], {})
            if not ti.get("reachable"):
                bad = True; parts.append("%s: NOT reachable" % t["name"]); continue
            down = [s for s in t.get("services", []) if ti.get("services", {}).get(s) != "active"]
            age = str(ti.get("data_age_min", ""))
            stale = t.get("data_file") and (not age.lstrip("-").isdigit() or int(age) < 0 or int(age) > 15)
            if down or stale:
                bad = True
                parts.append("%s: %s" % (t["name"], ", ".join([d + " DOWN" for d in down] + (["no new data (%s min)" % age] if stale else []))))
            else:
                parts.append("%s OK" % t["name"])
        rows.append(("Monitoring & Tools", cell("bad" if bad else "ok", "; ".join(parts))))
    # AD backup: newest PBS snapshot of each DC VM
    dcs = cfg["companies"][company].get("domain_controllers", {}).get(site, [])
    if not dcs:
        rows.append(("AD Backup Status", cell("na", "no DC at this site")))
    else:
        parts, bad = [], False
        snaps = {(a, b): c for a, b, c in raw.get("pbs_snapshots", [])}
        for dc in dcs:
            vmid = next((v[0] for v in hosts.get(dc["host"], {}).get("vms", []) if v[1] == dc["vm"]), None)
            ns = raw.get("pbs_ns", {}).get(dc["host"], "")
            ts = snaps.get((ns, str(vmid))) if vmid else None
            a = age_hours(ts, ref) if ts else None
            if dc.get("note"):
                parts.append("%s: %s" % (dc["vm"], dc["note"]) + ("" if a is None else ", backup %.0f h ago" % a))
                continue
            if a is None:
                bad = True; parts.append("%s: NO BACKUP FOUND" % dc["vm"])
            elif a > cfg.get("backup_max_age_hours", 26):
                bad = True; parts.append("%s: last backup %.0f h ago" % (dc["vm"], a))
            else:
                parts.append("%s: OK (%s)" % (dc["vm"], ts.replace("T", " ").replace("Z", " UTC")))
        rows.append(("AD Backup Status", cell("bad" if bad else "ok", "; ".join(parts))))
    return rows

CSS = """body{font-family:Arial,Helvetica,sans-serif;font-size:12px;margin:18px}h1{font-size:17px;margin:0}
h2{font-size:13px;font-weight:normal;margin:2px 0 10px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #444;padding:5px;vertical-align:top}th{background:#eee;text-align:left}
td.ok{background:#e7f6e7}td.bad{background:#fbe3e3;font-weight:bold}td.manual{background:#fff8dc}td.na{color:#777}
.st{font-size:10px;font-weight:bold;display:block}.audit{font-size:10px;color:#333;margin-top:10px}
.sig td{height:34px}@media print{@page{size:A4 landscape;margin:10mm}}"""
LABEL = {"ok": "OK", "bad": "ATTENTION", "manual": "MANUAL", "na": "N/A"}

def table(cols, rowsets, title, sub, audit):
    names = [r[0] for r in rowsets[0]] if rowsets else []
    out = ["<!doctype html><html><head><meta charset='utf-8'><title>%s</title><style>%s</style></head><body>" % (html.escape(title), CSS),
           "<h1>%s</h1><h2>%s</h2><table><tr><th style='width:22%%'>Check</th>" % (html.escape(title), html.escape(sub))]
    out += ["<th>%s</th>" % html.escape(c) for c in cols] + ["</tr>"]
    for i, n in enumerate(names):
        out.append("<tr><th>%s</th>" % html.escape(n))
        for rs in rowsets:
            c = rs[i][1]
            out.append("<td class='%s'><span class='st'>%s</span>%s</td>" % (c["s"], LABEL[c["s"]], html.escape(c["t"])))
        out.append("</tr>")
    for label in ("Checked by (name, sign, time)", "Reviewed by (name, sign, time)", "Remarks / incident ref."):
        out.append("<tr class='sig'><th>%s</th>%s</tr>" % (label, "<td></td>" * len(cols)))
    out.append("</table><div class='audit'>%s</div></body></html>" % audit)
    return "".join(out)

def main(cfgp, rawp):
    cfg = yaml.safe_load(open(cfgp))
    d = os.path.dirname(os.path.abspath(rawp))
    raw = json.load(open(rawp))
    sha = hashlib.sha256(open(rawp, "rb").read()).hexdigest()
    audit = ("Generated automatically %s by %s. Evidence file %s, SHA-256 %s (kept in git + off-site). "
             "MANUAL = to be filled by the person checking. Checked-by and Reviewed-by must be different people. "
             "Every ATTENTION item needs an incident reference in Remarks."
             % (raw["generated_at"], raw.get("generated_by", "ctl-01"), os.path.basename(rawp), sha))
    written = []
    for comp, cc in cfg["companies"].items():
        sites = cc["sites"]
        rowsets = [compute(cfg, raw, comp, s) for s in sites]
        f = os.path.join(d, "%s-%s.html" % (raw["date"], comp))
        open(f, "w").write(table([cfg["sites"][s]["label"] for s in sites], rowsets,
                                 "%s - Daily Infrastructure Checklist" % cc["label"], "Date: %s" % raw["date"], audit))
        written.append(os.path.basename(f))
        month = raw["date"][:7]
        days = sorted(glob.glob(os.path.join(d, "%s-??.json" % month)))
        for s in sites:
            rs, cols = [], []
            for p in days:
                r = json.load(open(p)); rs.append(compute(cfg, r, comp, s)); cols.append(r["date"][8:10] + "/" + r["date"][5:7])
            f = os.path.join(d, "%s-%s-%s.html" % (month, comp, s))
            open(f, "w").write(table(cols, rs, "%s - %s - Daily Checklist %s" % (cc["label"], cfg["sites"][s]["label"], month),
                                     "Location: %s" % cfg["sites"][s]["label"],
                                     "Month view of the automated daily checks; daily evidence files and checksums in the same folder."))
            written.append(os.path.basename(f))
    print("sheets written: " + ", ".join(written))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
