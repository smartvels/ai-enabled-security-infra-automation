#!/usr/bin/env python3
"""portal-authguard-patch.py - add ONE central login/role check to Portal (chatbot.py).

Every /api/ route then needs a valid session (Authorization: Bearer <token>, the header the UI already
sends). Admin areas need a role permission from the existing ROLES table:
  /api/users...                          -> "users"
  /api/admin/command, .../execute, rollout/stage -> "commands"
  /api/admin/..., /api/pbs/, /api/zabbix/, /api/wazuh/ -> "admin"
Public (no session): /api/auth/login, /api/agent/* (agents; restricted by nginx, per-agent keys come next),
/api/wazuh/ar_webhook (restricted by nginx to the Wazuh master).

Mode (env PORTAL_AUTH_MODE): "report" (default) = log what WOULD be refused, let it through;
                            "enforce" = refuse with 401/403.
Log: journald / app log lines starting with "AUTHGUARD".
Usage:  python3 portal-authguard-patch.py /home/chatbot/chatbot/chatbot.py      (backup is taken first)
Rollback: cp chatbot.py.pre-authguard-<ts> chatbot.py ; restart the service.
"""
import re, shutil, sys, time, py_compile

MARK = "# ── AUTHGUARD (ctl-01 patch) ──"
GUARD = r'''
# ── AUTHGUARD (ctl-01 patch) ──────────────────────────────────
import os as _ag_os, logging as _ag_logging
from starlette.middleware.base import BaseHTTPMiddleware as _AG_Base
_ag_log = _ag_logging.getLogger("authguard")
_AG_MODE = _ag_os.environ.get("PORTAL_AUTH_MODE", "report").lower()
_AG_PUBLIC_EXACT = {"/api/auth/login", "/api/wazuh/ar_webhook"}
_AG_PUBLIC_PREFIX = ("/api/agent/",)
_AG_RULES = [  # (regex on path, permission) - first match wins
    (r"^/api/users", "users"),
    (r"^/api/admin/command/?$", "commands"),
    (r"^/api/admin/agent/", "commands"),
    (r"^/api/admin/changes/[^/]+/execute", "commands"),
    (r"^/api/admin/", "admin"),
    (r"^/api/(pbs|zabbix|wazuh)/", "admin"),
]
import re as _ag_re
_AG_RULES = [(_ag_re.compile(rx), perm) for rx, perm in _AG_RULES]

def _ag_needed(path):
    for rx, perm in _AG_RULES:
        if rx.search(path):
            return perm
    return None

class AuthGuard(_AG_Base):
    async def dispatch(self, request, call_next):
        p = request.url.path
        if (request.method == "OPTIONS" or not p.startswith("/api/")
                or p in _AG_PUBLIC_EXACT or p.startswith(_AG_PUBLIC_PREFIX)):
            return await call_next(request)
        token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        session = verify_session(token) if token else None
        src = request.headers.get("X-Real-IP") or (request.client.host if request.client else "-")
        problem, code = None, 0
        if not session:
            problem, code = "no valid session", 401
        else:
            need = _ag_needed(p)
            if need and need not in ROLES.get(session.get("role"), {}).get("permissions", []):
                problem, code = "role %s lacks %s" % (session.get("role"), need), 403
        if problem:
            _ag_log.warning("AUTHGUARD %s %s %s from %s user=%s: %s", _AG_MODE.upper(), request.method, p, src,
                            (session or {}).get("username", "-"), problem)
            if _AG_MODE == "enforce":
                return JSONResponse({"error": "Unauthorized" if code == 401 else "Forbidden"}, status_code=code)
        return await call_next(request)

app.add_middleware(AuthGuard)
# ── /AUTHGUARD ────────────────────────────────────────────────
'''

def main(path):
    src = open(path, encoding="utf-8").read()
    if MARK in src:
        print("already patched - nothing to do"); return 0
    for need in ("def verify_session(", "ROLES = {", "JSONResponse", "app = FastAPI("):
        if need not in src:
            print("STOP: expected '%s' not found - file differs from the reviewed version" % need); return 2
    # insert right after the last app.add_middleware(...) statement block
    m = list(re.finditer(r"^app\.add_middleware\(.*?\)\s*$", src, flags=re.M | re.S))
    if not m:
        print("STOP: no app.add_middleware(...) found"); return 2
    # end of the last add_middleware call (handles multi-line calls)
    start = m[-1].start()
    depth, i = 0, src.index("(", start)
    while True:
        if src[i] == "(": depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0: break
        i += 1
    end = src.index("\n", i) + 1
    new = src[:end] + GUARD + src[end:]
    ts = time.strftime("%Y%m%dT%H%M%S")
    bak = "%s.pre-authguard-%s" % (path, ts)
    shutil.copy2(path, bak)
    open(path, "w", encoding="utf-8").write(new)
    try:
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError as e:
        shutil.copy2(bak, path)
        print("STOP: patched file does not compile - original restored:", e); return 3
    print("patched OK; backup:", bak)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "chatbot.py"))
