"""ops_requests.py - Ops Portal: change requests -> approvals -> (ctl-01 runner executes).
Ops Portal NEVER executes anything: it stores requests and approvals. ctl-01 pulls approved jobs and re-checks them
against its own catalog and approver list before running.
Registered from chatbot.py:  import ops_requests; ops_requests.register(app, verify_session, ROLES, DB_PATH)
Runner auth: header X-Runner-Key, compared (sha256) with env RUNNER_KEY_SHA256. nginx limits /api/runner/ to ctl-01.
"""
import hashlib, hmac, json, os, re, sqlite3
from datetime import datetime
from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_FILE = os.path.join(HERE, "ops_catalog.json")   # copy of ctl-01's catalog (deployed by ctl-01)


def register(app, verify_session, ROLES, DB_PATH):
    def db():
        c = sqlite3.connect(DB_PATH)
        c.execute("""CREATE TABLE IF NOT EXISTS job_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, job_type TEXT, params TEXT, reason TEXT, status TEXT,
            requested_by TEXT, approvals TEXT DEFAULT '[]', rejected_by TEXT, created_at TEXT,
            claimed_at TEXT, finished_at TEXT, result_status TEXT, result_text TEXT)""")
        return c

    def catalog():
        try:
            return json.load(open(CATALOG_FILE))
        except Exception:
            return {"jobs": {}, "approver_roles": []}

    def user(request):
        tok = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        return verify_session(tok) if tok else None

    def now():
        return datetime.now().isoformat(timespec="seconds")

    def row(r):
        k = ["id", "job_type", "params", "reason", "status", "requested_by", "approvals", "rejected_by",
             "created_at", "claimed_at", "finished_at", "result_status", "result_text"]
        d = dict(zip(k, r)); d["params"] = json.loads(d["params"] or "{}"); d["approvals"] = json.loads(d["approvals"] or "[]")
        return d

    def check_params(job, params):
        spec = job.get("params", {})
        if set(params) != set(spec):
            return "parameters must be exactly: %s" % ", ".join(sorted(spec)) or "none"
        for name, s in spec.items():
            v = str(params[name])
            if s["type"] == "int":
                if not re.fullmatch(r"[0-9]{1,10}", v) or not (s.get("min", 0) <= int(v) <= s.get("max", 10**10)):
                    return "%s: invalid number" % name
            elif s["type"] == "choice":
                if v not in s.get("values", []):
                    return "%s: not an allowed value" % name
            elif s["type"] == "inventory":
                if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", v) or v not in s.get("allowed", []):
                    return "%s: unknown host" % name
            else:
                return "%s: unsupported parameter type" % name
        return None

    def runner_ok(request):
        want = os.environ.get("RUNNER_KEY_SHA256", "")
        got = hashlib.sha256(request.headers.get("X-Runner-Key", "").encode()).hexdigest()
        return bool(want) and hmac.compare_digest(want, got)

    # ---------- people ----------
    @app.get("/api/requests/catalog")
    async def req_catalog(request: Request):
        if not user(request):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        c = catalog()
        return {k: {"label": v["label"], "risk": v["risk"], "approvals": v["approvals"],
                    "params": {p: {kk: vv for kk, vv in s.items()} for p, s in v.get("params", {}).items()}}
                for k, v in c["jobs"].items()}

    @app.post("/api/requests")
    async def req_create(request: Request):
        u = user(request)
        if not u:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        body = await request.json()
        jt, params, reason = body.get("job_type", ""), body.get("params", {}) or {}, (body.get("reason") or "").strip()[:500]
        job = catalog()["jobs"].get(jt)
        if not job:
            return JSONResponse({"error": "unknown job type"}, status_code=400)
        err = check_params(job, params)
        if err:
            return JSONResponse({"error": err}, status_code=400)
        if job["approvals"] > 0 and len(reason) < 5:
            return JSONResponse({"error": "a reason is required"}, status_code=400)
        status = "approved" if job["approvals"] == 0 else "pending"
        c = db(); cur = c.execute("INSERT INTO job_requests (job_type, params, reason, status, requested_by, created_at) VALUES (?,?,?,?,?,?)",
                                  (jt, json.dumps(params), reason, status, u["username"], now()))
        c.commit(); rid = cur.lastrowid; c.close()
        return {"id": rid, "status": status}

    @app.get("/api/requests")
    async def req_list(request: Request):
        u = user(request)
        if not u:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        is_approver = u["role"] in catalog().get("approver_roles", [])
        c = db()
        q = "SELECT * FROM job_requests %s ORDER BY id DESC LIMIT 100" % ("" if is_approver else "WHERE requested_by=?")
        rows = [row(r) for r in c.execute(q, () if is_approver else (u["username"],))]
        c.close()
        return {"me": u["username"], "approver": is_approver, "requests": rows}

    @app.post("/api/requests/{rid}/approve")
    async def req_approve(rid: int, request: Request):
        u = user(request)
        if not u or u["role"] not in catalog().get("approver_roles", []):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        c = db(); r = c.execute("SELECT * FROM job_requests WHERE id=?", (rid,)).fetchone()
        if not r:
            c.close(); return JSONResponse({"error": "not found"}, status_code=404)
        d = row(r); job = catalog()["jobs"].get(d["job_type"], {})
        if d["status"] != "pending":
            c.close(); return JSONResponse({"error": "not pending"}, status_code=409)
        if u["username"] == d["requested_by"]:
            c.close(); return JSONResponse({"error": "you cannot approve your own request"}, status_code=403)
        if any(a["user"] == u["username"] for a in d["approvals"]):
            c.close(); return JSONResponse({"error": "already approved by you"}, status_code=409)
        d["approvals"].append({"user": u["username"], "at": now()})
        st = "approved" if len(d["approvals"]) >= job.get("approvals", 99) else "pending"
        c.execute("UPDATE job_requests SET approvals=?, status=? WHERE id=?", (json.dumps(d["approvals"]), st, rid)); c.commit(); c.close()
        return {"id": rid, "status": st, "approvals": len(d["approvals"])}

    @app.post("/api/requests/{rid}/reject")
    async def req_reject(rid: int, request: Request):
        u = user(request)
        if not u or u["role"] not in catalog().get("approver_roles", []):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        c = db(); n = c.execute("UPDATE job_requests SET status='rejected', rejected_by=? WHERE id=? AND status='pending'",
                                (u["username"], rid)).rowcount
        c.commit(); c.close()
        return {"id": rid, "status": "rejected"} if n else JSONResponse({"error": "not pending"}, status_code=409)

    # ---------- ctl-01 runner (X-Runner-Key) ----------
    @app.get("/api/runner/jobs")
    async def run_list(request: Request):
        if not runner_ok(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        c = db(); rows = [row(r) for r in c.execute("SELECT * FROM job_requests WHERE status='approved' ORDER BY id LIMIT 20")]; c.close()
        return {"jobs": rows}

    @app.post("/api/runner/jobs/{rid}/claim")
    async def run_claim(rid: int, request: Request):
        if not runner_ok(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        c = db(); n = c.execute("UPDATE job_requests SET status='running', claimed_at=? WHERE id=? AND status='approved'", (now(), rid)).rowcount
        c.commit(); c.close()
        return {"claimed": bool(n)}

    @app.post("/api/runner/jobs/{rid}/result")
    async def run_result(rid: int, request: Request):
        if not runner_ok(request):
            return JSONResponse({"error": "Forbidden"}, status_code=403)
        b = await request.json(); st = b.get("status") if b.get("status") in ("done", "failed", "refused") else "failed"
        c = db(); c.execute("UPDATE job_requests SET status=?, result_status=?, result_text=?, finished_at=? WHERE id=? AND status IN ('running','approved')",
                            (st, st, str(b.get("output", ""))[-6000:], now(), rid)); c.commit(); c.close()
        return {"id": rid, "status": st}

    # ---------- simple page (uses the session token the main UI stores) ----------
    @app.get("/requests")
    async def req_page():
        return HTMLResponse(PAGE)


PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><title>Ops Portal - Requests</title>
<style>body{font-family:Arial,sans-serif;margin:20px;font-size:14px}table{border-collapse:collapse;width:100%;margin-top:12px}
td,th{border:1px solid #ccc;padding:6px;vertical-align:top}th{background:#f2f2f2}.pending{background:#fff8dc}.approved,.running{background:#e8f0ff}
.done{background:#e7f6e7}.failed,.refused,.rejected{background:#fbe3e3}button{margin:2px}pre{white-space:pre-wrap;font-size:11px;max-height:160px;overflow:auto}
#f input,#f select{margin:4px 8px 4px 0}</style></head><body>
<h2>Ops Portal - Change requests</h2><div id="who"></div>
<div id="f"><select id="jt"></select><span id="pp"></span><input id="rs" placeholder="reason (required if approval needed)" size="40">
<button onclick="sub()">Request</button> <span id="msg"></span></div>
<table><thead><tr><th>#</th><th>Job</th><th>Parameters</th><th>Requested by</th><th>Status</th><th>Approvals</th><th>Result</th><th></th></tr></thead><tbody id="tb"></tbody></table>
<script>
const T=localStorage.getItem('tq_tk')||'';const H={'Authorization':'Bearer '+T,'Content-Type':'application/json'};let CAT={};
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
async function j(u,o){const r=await fetch(u,Object.assign({headers:H},o||{}));return [r.status,await r.json().catch(()=>({}))]}
function pp(){const s=CAT[document.getElementById('jt').value]||{};document.getElementById('pp').innerHTML=Object.keys(s.params||{}).map(p=>'<input data-p="'+p+'" placeholder="'+p+'" size="12">').join('')}
async function load(){let [st,c]=await j('/api/requests/catalog');if(st!==200){document.getElementById('who').textContent='Please log in to Ops Portal first.';return}
CAT=c;document.getElementById('jt').innerHTML=Object.entries(c).map(([k,v])=>'<option value="'+k+'">'+esc(v.label)+' ('+v.risk+', '+v.approvals+' approval(s))</option>').join('');
document.getElementById('jt').onchange=pp;pp();list()}
async function list(){let [st,d]=await j('/api/requests');document.getElementById('who').textContent='Logged in as '+d.me+(d.approver?' (approver)':'');
document.getElementById('tb').innerHTML=(d.requests||[]).map(r=>'<tr class="'+r.status+'"><td>'+r.id+'</td><td>'+esc(r.job_type)+'<br><small>'+esc(r.reason)+'</small></td><td>'+esc(JSON.stringify(r.params))+'</td><td>'+esc(r.requested_by)+'<br><small>'+esc(r.created_at)+'</small></td><td>'+r.status+'</td><td>'+r.approvals.map(a=>esc(a.user)).join(', ')+'</td><td><pre>'+esc(r.result_text||'')+'</pre></td><td>'+
(d.approver&&r.status==='pending'&&r.requested_by!==d.me?'<button onclick="act('+r.id+',\'approve\')">Approve</button><button onclick="act('+r.id+',\'reject\')">Reject</button>':'')+'</td></tr>').join('')}
async function sub(){const p={};document.querySelectorAll('#pp input').forEach(i=>p[i.dataset.p]=i.value.trim());
let [st,d]=await j('/api/requests',{method:'POST',body:JSON.stringify({job_type:document.getElementById('jt').value,params:p,reason:document.getElementById('rs').value})});
document.getElementById('msg').textContent=st===200?('Request #'+d.id+': '+d.status):('Error: '+(d.error||st));list()}
async function act(id,a){let [st,d]=await j('/api/requests/'+id+'/'+a,{method:'POST'});if(st!==200)alert(d.error||st);list()}
load();setInterval(list,15000);
</script></body></html>"""
