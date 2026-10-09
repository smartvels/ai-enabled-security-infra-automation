from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse, Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import requests
import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv("/home/chatbot/chatbot/.env")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]           = "nosniff"
        response.headers["X-Frame-Options"]                   = "DENY"
        response.headers["X-XSS-Protection"]                  = "1; mode=block"
        response.headers["Referrer-Policy"]                    = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]                 = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]            = "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'; form-action \'self\'; frame-ancestors \'none\'; base-uri \'self\'; object-src \'none\'"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"]                      = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)

GLPI_URL = "http://${TICKETING_IP}/apirest.php"
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN")
OLLAMA_URL = "http://${AI_HOST_IP}:11434"
LOCALAI_URL = "http://${AI_HOST_IP}:8080"
CHROMADB_API = "http://${VECTORDB_IP}:9000"
WAZUH_URL = "https://${SIEM_IP}:55000"
WAZUH_INDEXER_URL = "https://${SIEM_IP}:9200"
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER")
WAZUH_INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASS = os.getenv("WAZUH_PASS")
BASE_DIR = "/home/chatbot/chatbot"
DB_PATH = "/home/chatbot/chatbot/endpoints.db"

# ── AUTH CONFIG ──────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY")
SESSION_EXPIRE_HOURS = 8

ROLES = {
    "superadmin": {"label": "Super Admin", "permissions": ["chat", "admin", "users", "commands", "remote", "software", "config"]},
    "admin":      {"label": "IT Admin",    "permissions": ["chat", "admin", "commands", "remote", "software"]},
    "user":       {"label": "Employee",    "permissions": ["chat"]}
}

# ── DATABASE SETUP ────────────────────────────────────────────
def sanitize(val, max_len=200):
    """Sanitize string input"""
    if val is None: return None
    val = str(val).strip()
    # Remove SQL injection chars
    val = val.replace("'","").replace('"','').replace(';','').replace('--','')
    return val[:max_len]

def validate_hostname(h):
    """Validate hostname format"""
    import re
    if not h: return False
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]{0,62}$', h))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE,
        username TEXT,
        ip TEXT,
        mac TEXT,
        os_name TEXT,
        os_version TEXT,
        cpu_percent REAL,
        cpu_cores INTEGER,
        cpu_model TEXT,
        ram_total REAL,
        ram_used REAL,
        ram_percent REAL,
        disk_total REAL,
        disk_used REAL,
        disk_percent REAL,
        last_boot TEXT,
        antivirus INTEGER,
        pending_updates INTEGER,
        rustdesk_id TEXT,
        status TEXT DEFAULT "online",
        agent_version TEXT,
        last_seen TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS software_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        software_name TEXT,
        software_version TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS command_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        command_id TEXT,
        stdout TEXT,
        stderr TEXT,
        returncode INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS pending_commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        command_type TEXT,
        payload TEXT,
        status TEXT DEFAULT "pending",
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        full_name TEXT,
        email TEXT,
        role TEXT DEFAULT "user",
        department TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        username TEXT,
        role TEXT,
        expires_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    conn.commit()

    # Create default superadmin if no users exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # Initial admin password comes from the environment; a random one is generated if unset
        initial_pw = os.environ.get("ADMIN_INITIAL_PASSWORD") or secrets.token_urlsafe(16)
        pw_hash = hashlib.sha256(initial_pw.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password_hash, full_name, email, role, department) VALUES (?,?,?,?,?,?)",
                 ("itadmin", pw_hash, "IT Administrator", "itteam@example.com", "superadmin", "IT"))
        conn.commit()
        print("Default superadmin created: itadmin (set ADMIN_INITIAL_PASSWORD, or check this log for the generated password):", initial_pw if not os.environ.get("ADMIN_INITIAL_PASSWORD") else "<from env>")

    conn.close()

init_db()

# ── AUTH FUNCTIONS ────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_session(username: str, role: str) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=SESSION_EXPIRE_HOURS)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO sessions (token, username, role, expires_at) VALUES (?,?,?,?)",
             (token, username, role, expires))
    c.execute("UPDATE users SET last_login=? WHERE username=?", (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()
    return token

def verify_session(token: str) -> dict:
    if not token:
        return None
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, role, expires_at FROM sessions WHERE token=?", (token,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    if datetime.fromisoformat(row[2]) < datetime.now():
        return None
    return {"username": row[0], "role": row[1]}

def has_permission(token: str, permission: str) -> bool:
    session = verify_session(token)
    if not session:
        return False
    role = session.get("role", "user")
    return permission in ROLES.get(role, {}).get("permissions", [])

# ── MODELS ────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    model: str = "Qwen2.5-7B-Instruct-Q4_K_M.gguf"
    messages: list
    stream: bool = False
    options: dict = {"num_predict": 1500}

class TicketRequest(BaseModel):
    name: str
    content: str
    priority: int = 3
    urgency: int = 3
    status: int = 1

class CommandRequest(BaseModel):
    hostname: str
    command_type: str
    payload: str = ""

# ── AUTH ENDPOINTS ───────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def login(req: LoginRequest):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, password_hash, full_name, role, is_active FROM users WHERE username=?",
             (req.username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)
    if not row[4]:
        return JSONResponse({"error": "Account is disabled"}, status_code=401)
    if row[1] != hash_password(req.password):
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)

    token = create_session(row[0], row[3])
    return {
        "token": token,
        "username": row[0],
        "full_name": row[2],
        "role": row[3],
        "permissions": ROLES.get(row[3], {}).get("permissions", [])
    }

@app.post("/api/auth/logout")
async def logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return {"status": "ok"}

@app.get("/api/auth/me")
async def get_me(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = verify_session(token)
    if not session:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return {
        "username": session["username"],
        "role": session["role"],
        "permissions": ROLES.get(session["role"], {}).get("permissions", [])
    }

# ── USER MANAGEMENT (superadmin only) ────────────────────────
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: str = ""
    role: str = "user"
    department: str = ""

class UserUpdate(BaseModel):
    full_name: str = None
    email: str = None
    role: str = None
    department: str = None
    is_active: int = None
    password: str = None

@app.get("/api/users")
async def get_users(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not has_permission(token, "users"):
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, full_name, email, role, department, is_active, last_login, created_at FROM users ORDER BY role, username")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return {"users": rows}

@app.post("/api/users")
async def create_user(user: UserCreate, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not has_permission(token, "users"):
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, full_name, email, role, department) VALUES (?,?,?,?,?,?)",
                 (user.username, hash_password(user.password), user.full_name, user.email, user.role, user.department))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@app.put("/api/users/{username}")
async def update_user(username: str, user: UserUpdate, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not has_permission(token, "users"):
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if user.password:
            c.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_password(user.password), username))
        if user.role:
            c.execute("UPDATE users SET role=? WHERE username=?", (user.role, username))
        if user.is_active is not None:
            c.execute("UPDATE users SET is_active=? WHERE username=?", (user.is_active, username))
        if user.full_name:
            c.execute("UPDATE users SET full_name=? WHERE username=?", (user.full_name, username))
        if user.department:
            c.execute("UPDATE users SET department=? WHERE username=?", (user.department, username))
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)

@app.delete("/api/users/{username}")
async def delete_user(username: str, request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not has_permission(token, "users"):
        return JSONResponse({"error": "Unauthorized"}, status_code=403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=? AND username != 'itadmin'", (username,))
    conn.commit()
    conn.close()
    return {"success": True}

# ── CHAT PROXY ────────────────────────────────────────────────# ── CHAT PROXY ────────────────────────────────────────────────
@app.post("/api/chat")
async def proxy_chat(req: ChatRequest):
    try:
        user_msg = ""
        for m in reversed(req.messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
                break

        # Search knowledge base first
        if user_msg:
            try:
                kb_res = requests.post(
                    f"{CHROMADB_API}/knowledge/search",
                    json={"query": user_msg, "n_results": 1},
                    timeout=5
                )
                if kb_res.status_code == 200:
                    kb_data = kb_res.json()
                    if kb_data.get("found") and kb_data.get("results"):
                        answer = kb_data["results"][0]["content"]
                        return JSONResponse({"message": {"role": "assistant", "content": answer}, "source": "knowledge_base"})
            except:
                pass

        # Call LocalAI (OpenAI-compatible API)
        localai_payload = {
            "model": req.model,
            "messages": req.messages,
            "stream": False,
        }
        if req.options and req.options.get("num_predict"):
            localai_payload["max_tokens"] = req.options["num_predict"]
        r = requests.post(f"{LOCALAI_URL}/v1/chat/completions", json=localai_payload, timeout=300)
        r.raise_for_status()
        data = r.json()
        content_text = data["choices"][0]["message"]["content"]
        return JSONResponse({"message": {"role": "assistant", "content": content_text}})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/health")
def ai_health():
    try:
        r = requests.get(f"{LOCALAI_URL}/v1/models", timeout=5)
        return {"status": "ok", "localai": r.status_code == 200}
    except:
        return {"status": "error", "localai": False}

@app.get("/api/models")
def list_models():
    try:
        r = requests.get(f"{LOCALAI_URL}/v1/models", timeout=5)
        data = r.json()
        models = [m["id"] for m in data.get("data", [])]
        return {"models": models}
    except Exception as e:
        return {"models": [], "error": str(e)}

# ── AGENT ENDPOINTS ───────────────────────────────────────────
@app.post("/api/agent/report")
async def agent_report(request: Request):
    """Receive health report from endpoint agent"""
    try:
        data = await request.json()
        hostname = data.get("hostname", "unknown")
        now = datetime.now().isoformat()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Upsert endpoint data
        c.execute('''INSERT INTO endpoints
            (hostname, username, ip, mac, os_name, os_version,
             cpu_percent, cpu_cores, cpu_model,
             ram_total, ram_used, ram_percent,
             disk_total, disk_used, disk_percent,
             last_boot, antivirus, antivirus_name, pending_updates, rustdesk_id,
             bitlocker_status, bitlocker_percent, tpm_present, wazuh_status,
             status, agent_version, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(hostname) DO UPDATE SET
            username=excluded.username, ip=excluded.ip,
            os_name=CASE WHEN excluded.os_name IS NOT NULL THEN excluded.os_name ELSE os_name END,
            os_version=CASE WHEN excluded.os_version IS NOT NULL THEN excluded.os_version ELSE os_version END,
            cpu_percent=excluded.cpu_percent, ram_percent=excluded.ram_percent,
            disk_percent=excluded.disk_percent,
            antivirus=excluded.antivirus,
            antivirus_name=CASE WHEN excluded.antivirus_name IS NOT NULL THEN excluded.antivirus_name ELSE antivirus_name END,
            pending_updates=excluded.pending_updates,
            rustdesk_id=CASE WHEN excluded.rustdesk_id IS NOT NULL THEN excluded.rustdesk_id ELSE rustdesk_id END,
            bitlocker_status=CASE WHEN excluded.bitlocker_status IS NOT NULL THEN excluded.bitlocker_status ELSE bitlocker_status END,
            bitlocker_percent=excluded.bitlocker_percent,
            tpm_present=excluded.tpm_present,
            wazuh_status=CASE WHEN excluded.wazuh_status IS NOT NULL THEN excluded.wazuh_status ELSE wazuh_status END,
            agent_version=CASE WHEN excluded.agent_version IS NOT NULL THEN excluded.agent_version ELSE agent_version END,
            status="online", last_seen=excluded.last_seen''',
            (hostname,
             data.get("username"),
             data.get("ip"),
             data.get("mac"),
             data.get("os", {}).get("name"),
             data.get("os", {}).get("version"),
             data.get("cpu", {}).get("percent"),
             data.get("cpu", {}).get("cores"),
             data.get("cpu", {}).get("model"),
             data.get("ram", {}).get("total_gb"),
             data.get("ram", {}).get("used_gb"),
             data.get("ram", {}).get("percent"),
             data.get("disk", {}).get("total_gb"),
             data.get("disk", {}).get("used_gb"),
             data.get("disk", {}).get("percent"),
             data.get("last_boot"),
             1 if data.get("antivirus") else 0,
             data.get("antivirus") if isinstance(data.get("antivirus"), str) else None,
             data.get("pending_updates", 0),
             data.get("rustdesk_id") or None,
             data.get("bitlocker",{}).get("status") if isinstance(data.get("bitlocker"),dict) else None,
             data.get("bitlocker",{}).get("percent",0) if isinstance(data.get("bitlocker"),dict) else 0,
             1 if (data.get("bitlocker",{}).get("tpm_present") if isinstance(data.get("bitlocker"),dict) else False) else 0,
             data.get("wazuh_status") or None,
             "online",
             data.get("version"),
             now))

        # Update software inventory
        if data.get("software"):
            c.execute("DELETE FROM software_inventory WHERE hostname=?", (hostname,))
            for sw in data.get("software", []):
                c.execute("INSERT INTO software_inventory (hostname, software_name, software_version) VALUES (?,?,?)",
                         (hostname, sw.get("name"), sw.get("version")))

        # Check for pending commands
        c.execute("SELECT id, command_type, payload FROM pending_commands WHERE hostname=? AND status='pending' LIMIT 1", (hostname,))
        cmd = c.fetchone()

        conn.commit()
        conn.close()

        if cmd:
            return {"status": "ok", "command": {"id": cmd[0], "type": cmd[1], "payload": cmd[2]}}
        return {"status": "ok", "command": None}

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/agent/command_result")
async def command_result(request: Request):
    """Receive command execution result from agent"""
    try:
        data = await request.json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO command_results (hostname, command_id, stdout, stderr, returncode) VALUES (?,?,?,?,?)",
                 (data.get("hostname"), data.get("command_id"), data.get("stdout"), data.get("stderr"), data.get("returncode")))
        c.execute("UPDATE pending_commands SET status='completed' WHERE id=?", (data.get("command_id"),))
        conn.commit()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ── ADMIN API ─────────────────────────────────────────────────
@app.get("/api/admin/endpoints")
def get_endpoints():
    """Get all endpoints for admin dashboard"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM endpoints ORDER BY last_seen DESC")
        rows = [dict(row) for row in c.fetchall()]
        conn.close()

        # Mark offline if not seen in 10 minutes
        now = datetime.now()
        for row in rows:
            if row.get("last_seen"):
                try:
                    last = datetime.fromisoformat(row["last_seen"])
                    if (now - last).seconds > 600:
                        row["status"] = "offline"
                except:
                    pass
        for row in rows:
            if not row.get("antivirus_name") and row.get("antivirus"):
                row["antivirus_name"] = "Trend Micro"
            row["antivirus"] = row.get("antivirus_name") or (row.get("antivirus") and "Trend Micro") or None
            row["bitlocker"] = {"status": row.get("bitlocker_status") or "Unknown","percent": row.get("bitlocker_percent") or 0,"tpm_present": bool(row.get("tpm_present"))}
            row["disk_free"] = round((row.get("disk_total") or 0) - (row.get("disk_used") or 0), 1)
        return {"endpoints": rows, "total": len(rows)}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/dashboard")
def get_dashboard():
    """Get dashboard summary stats"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        now = datetime.now()

        c.execute("SELECT COUNT(*) FROM endpoints")
        total = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM endpoints WHERE last_seen > datetime('now', '-10 minutes')")
        online = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM endpoints WHERE disk_percent > 85")
        disk_critical = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM endpoints WHERE ram_percent > 85")
        ram_critical = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM endpoints WHERE pending_updates > 0")
        needs_updates = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM endpoints WHERE (antivirus = 0 OR antivirus IS NULL) AND antivirus_name IS NULL")
        no_av = c.fetchone()[0]

        conn.close()

        return {
            "total_endpoints": total,
            "online": online,
            "offline": total - online,
            "disk_critical": disk_critical,
            "ram_critical": ram_critical,
            "needs_updates": needs_updates,
            "no_antivirus": no_av
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/software/changes")
async def get_software_changes_early(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM software_changes ORDER BY detected_at DESC LIMIT 200")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"changes": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/software/compliance")
async def get_software_compliance_early(request: Request):
    try:
        required = [
            {"name":"Wazuh Agent","required":True},
            {"name":"RustDesk","required":True},
            {"name":"Trend Micro","required":True}
        ]
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        violations = []
        c.execute("SELECT hostname FROM endpoints WHERE status='online'")
        online = [r[0] for r in c.fetchall()]
        for pc in online:
            c.execute("SELECT software_name FROM software_inventory WHERE hostname=?", (pc,))
            sw = [r[0].lower() for r in c.fetchall()]
            for req in required:
                if not any(req["name"].lower() in s for s in sw):
                    violations.append({"hostname":pc,"missing":req["name"]})
        conn.close()
        return JSONResponse({"required":required,"violations":violations})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/software/{hostname}")
def get_software(hostname: str):
    """Get software inventory for a specific PC"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT software_name, software_version FROM software_inventory WHERE hostname=? ORDER BY software_name", (hostname,))
        rows = c.fetchall()
        conn.close()
        return {"hostname": hostname, "software": [{"name": r[0], "version": r[1]} for r in rows]}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/command")
def send_command(cmd: CommandRequest):
    """Send command to endpoint agent"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO pending_commands (hostname, command_type, payload) VALUES (?,?,?)",
                 (cmd.hostname, cmd.command_type, cmd.payload))
        cmd_id = c.lastrowid
        conn.commit()
        conn.close()
        return {"status": "ok", "command_id": cmd_id}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/remote/{hostname}")
def get_remote_info(hostname: str):
    """Get RustDesk ID for remote connection"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT rustdesk_id, ip, username FROM endpoints WHERE hostname=?", (hostname,))
        row = c.fetchone()
        conn.close()
        if row:
            return {"hostname": hostname, "rustdesk_id": row[0], "ip": row[1], "username": row[2]}
        return JSONResponse({"error": "Endpoint not found"}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ── EXISTING ENDPOINTS ────────────────────────────────────────
@app.get("/version.json")
def get_version():
    path = os.path.join(BASE_DIR, "version.json")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/json")
    return {"version": "2.0.0"}

@app.get("/config.json")
def get_config():
    path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/json")
    return {"ollama_url": OLLAMA_URL, "ollama_model": "llama3.2:3b"}

@app.get("/Agent_Setup.exe")
def get_setup():
    path = os.path.join(BASE_DIR, "Agent_Setup.exe")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/octet-stream", filename="Agent_Setup.exe")
    return JSONResponse({"error": "Not found"}, status_code=404)

@app.get("/scripts/{script_name}")
def get_script(script_name: str):
    path = os.path.join(BASE_DIR, "scripts", script_name)
    if os.path.exists(path) and script_name.endswith((".ps1", ".sh")):
        return FileResponse(path, media_type="application/octet-stream", filename=script_name)
    return JSONResponse({"error": "Not found"}, status_code=404)

@app.post("/submit-ticket")
def submit_ticket(ticket: TicketRequest):
    try:
        r = requests.post(f"{GLPI_URL}/initSession",
            headers={"Authorization": f"user_token {GLPI_USER_TOKEN}", "App-Token": GLPI_APP_TOKEN})
        session = r.json().get("session_token")
        r = requests.post(f"{GLPI_URL}/Ticket",
            headers={"Authorization": f"user_token {GLPI_USER_TOKEN}", "App-Token": GLPI_APP_TOKEN,
                     "Session-Token": session, "Content-Type": "application/json"},
            json={"input": {"name": ticket.name, "content": ticket.content,
                            "priority": ticket.priority, "urgency": ticket.urgency, "status": ticket.status}})
        requests.get(f"{GLPI_URL}/killSession",
            headers={"Authorization": f"user_token {GLPI_USER_TOKEN}",
                     "App-Token": GLPI_APP_TOKEN, "Session-Token": session})
        return {"success": True, "ticket_id": r.json().get("id")}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/static/logo.png")
def get_logo():
    import os
    logo_path = os.path.join(BASE_DIR, "logo.png")
    if os.path.exists(logo_path):
        return FileResponse(logo_path, media_type="image/png")
    return JSONResponse({"error": "Not found"}, status_code=404)

@app.get("/favicon.ico")
def get_favicon():
    import os
    ico_path = os.path.join(BASE_DIR, "logo.png")
    if os.path.exists(ico_path):
        return FileResponse(ico_path, media_type="image/png")
    return JSONResponse({"error": "Not found"}, status_code=404)

@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}

@app.get("/", response_class=HTMLResponse)
def home():
    try:
        content = open(os.path.join(BASE_DIR, "index.html"), encoding="utf-8").read()
        return Response(content=content, media_type="text/html",
                        headers={"Cache-Control": "no-store, no-cache, must-revalidate",
                                 "Pragma": "no-cache", "Expires": "0"})
    except Exception as e:
        return f"<h1>AI Assistant Portal</h1><p>Error: {e}</p>"

# ── WAZUH LIVE INTEGRATION ────────────────────────────────────
WAZUH_URL = "https://${SIEM_IP}:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "Cutepage92!"

@app.get("/api/wazuh/alerts")
async def get_wazuh_alerts(request: Request):
    try:
        import urllib3
        urllib3.disable_warnings()
        min_level = int(request.query_params.get("min_level", 5))
        size = int(request.query_params.get("size", 50))

        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}}
                    ]
                }
            }
        }

        r = requests.post(
            f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS),
            json=query, verify=False, timeout=15  # nosec B501
        )
        r.raise_for_status()
        data = r.json()

        normalized = []
        for hit in data.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            rule = src.get("rule", {})
            agent = src.get("agent", {})
            normalized.append({
                "level": rule.get("level", 0),
                "agent": {"name": agent.get("name", "Unknown")},
                "rule": {
                    "description": rule.get("description", ""),
                    "id": rule.get("id", ""),
                    "groups": rule.get("groups", [])
                },
                "timestamp": src.get("timestamp", ""),
                "location": src.get("location", "")
            })

        return JSONResponse({"alerts": normalized, "total": data.get("hits",{}).get("total",{}).get("value",0)})
    except Exception as e:
        return JSONResponse({"alerts": [], "error": str(e)}, status_code=500)

PBS_URL  = "https://${BACKUP_IP}:8007"
PBS_USER = os.getenv("PBS_USER")
PBS_PASS = os.getenv("PBS_PASS")

def get_pbs_ticket():
    import urllib3; urllib3.disable_warnings()
    r = requests.post(f"{PBS_URL}/api2/json/access/ticket",
        data={"username": PBS_USER, "password": PBS_PASS},
        verify=False, timeout=10)  # nosec B501
    d = r.json().get("data", {})
    return d.get("ticket"), d.get("CSRFPreventionToken")

@app.get("/api/pbs/status")
async def pbs_status(request: Request):
    try:
        ticket, csrf = get_pbs_ticket()
        if not ticket:
            return JSONResponse({"error": "PBS auth failed"})
        headers = {"Cookie": f"PBSAuthCookie={ticket}", "CSRFPreventionToken": csrf}
        import urllib3; urllib3.disable_warnings()
        r1 = requests.get(f"{PBS_URL}/api2/json/nodes", headers=headers, verify=False, timeout=10)  # nosec B501
        r2 = requests.get(f"{PBS_URL}/api2/json/admin/datastore", headers=headers, verify=False, timeout=10)  # nosec B501
        r3 = requests.get(f"{PBS_URL}/api2/json/nodes/localhost/tasks?limit=20", headers=headers, verify=False, timeout=10)  # nosec B501
        return JSONResponse({"nodes": r1.json().get("data",[]), "datastores": r2.json().get("data",[]), "tasks": r3.json().get("data",[])})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/pbs/backups")
async def pbs_backups(request: Request):
    try:
        ticket, csrf = get_pbs_ticket()
        if not ticket:
            return JSONResponse({"error": "PBS auth failed"})
        headers = {"Cookie": f"PBSAuthCookie={ticket}", "CSRFPreventionToken": csrf}
        import urllib3; urllib3.disable_warnings()
        r1 = requests.get(f"{PBS_URL}/api2/json/admin/datastore", headers=headers, verify=False, timeout=10)  # nosec B501
        all_backups = []
        for ds in r1.json().get("data", []):
            ds_name = ds.get("store", ds.get("name",""))
            try:
                r2 = requests.get(f"{PBS_URL}/api2/json/admin/datastore/{ds_name}/snapshots", headers=headers, verify=False, timeout=10)  # nosec B501
                for s in r2.json().get("data",[])[:20]:
                    s["datastore"] = ds_name
                    all_backups.append(s)
            except: pass
        all_backups.sort(key=lambda x: x.get("backup-time",0), reverse=True)
        return JSONResponse({"backups": all_backups[:50]})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ── ZABBIX INTEGRATION ────────────────────────────────────────
ZABBIX_URL  = "http://${MONITORING_IP}/zabbix/api_jsonrpc.php"
ZABBIX_USER = os.getenv("ZABBIX_USER")
ZABBIX_PASS = os.getenv("ZABBIX_PASS")

def get_zabbix_token():
    r = requests.post(ZABBIX_URL, json={
        "jsonrpc":"2.0","method":"user.login",
        "params":{"username":ZABBIX_USER,"password":ZABBIX_PASS},"id":1
    }, timeout=10)
    return r.json().get("result")

def zabbix_post(token, method, params, rid=1):
    return requests.post(ZABBIX_URL,
        headers={"Authorization": f"Bearer {token}", "Content-Type":"application/json"},
        json={"jsonrpc":"2.0","method":method,"params":params,"id":rid},
        timeout=10).json().get("result",[])

@app.get("/api/zabbix/hosts")
async def zabbix_hosts(request: Request):
    try:
        token = get_zabbix_token()
        if not token: return JSONResponse({"error":"Zabbix auth failed"})
        hosts = zabbix_post(token,"host.get",{
            "output":["hostid","host","name","status"],
            "selectInterfaces":["ip"],"selectGroups":["name"],"limit":100})
        return JSONResponse({"hosts":hosts})
    except Exception as e:
        return JSONResponse({"error":str(e)}, status_code=500)

@app.get("/api/zabbix/problems")
async def zabbix_problems(request: Request):
    try:
        token = get_zabbix_token()
        if not token: return JSONResponse({"error":"Zabbix auth failed"})
        problems = zabbix_post(token,"problem.get",{
            "output":"extend","selectAcknowledges":"count",
            "sortfield":["eventid"],"sortorder":"DESC","limit":50})
        tids = list(set([p.get("objectid") for p in problems if p.get("objectid")]))
        if tids:
            triggers = {t["triggerid"]:t for t in zabbix_post(token,"trigger.get",{
                "output":["triggerid","description","priority","hosts"],
                "triggerids":tids[:50],"selectHosts":["host","name"]})}
            for p in problems:
                t = triggers.get(p.get("objectid"),{})
                p["trigger_name"] = t.get("description","Unknown")
                p["priority"] = t.get("priority","0")
                hosts = t.get("hosts",[])
                p["host"] = hosts[0].get("name","") if hosts else ""
        return JSONResponse({"problems":problems})
    except Exception as e:
        return JSONResponse({"error":str(e)}, status_code=500)

@app.get("/api/zabbix/overview")
async def zabbix_overview(request: Request):
    try:
        token = get_zabbix_token()
        if not token: return JSONResponse({"error":"Zabbix auth failed"})
        # Get host count
        hosts    = len(zabbix_post(token,"host.get",{"output":["hostid"]}))
        critical = len(zabbix_post(token,"problem.get",{"output":["eventid"],"severities":[4,5]}))
        warning  = len(zabbix_post(token,"problem.get",{"output":["eventid"],"severities":[2,3]}))
        total    = len(zabbix_post(token,"problem.get",{"output":["eventid"]}))
        return JSONResponse({"hosts":hosts,"critical":critical,"warning":warning,"total_problems":total})
    except Exception as e:
        return JSONResponse({"error":str(e)}, status_code=500)


# ── DLP ───────────────────────────────────────────────────────
@app.post("/api/agent/dlp_event")
async def receive_dlp_event(request: Request):
    try:
        data = await request.json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO dlp_events (hostname,event_type,severity,file_path,description,details) VALUES (?,?,?,?,?,?)",
            (data.get("hostname"),data.get("event_type"),data.get("severity"),
             data.get("file_path"),data.get("description"),json.dumps(data.get("details",{}))))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error":str(e)},status_code=500)

@app.get("/api/admin/dlp/events")
async def get_dlp_events(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM dlp_events ORDER BY timestamp DESC LIMIT 200")
        events = [dict(row) for row in c.fetchall()]
        conn.close()
        return JSONResponse({"events":events})
    except Exception as e:
        return JSONResponse({"error":str(e)},status_code=500)

@app.get("/api/admin/dlp/summary")
async def get_dlp_summary(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM dlp_events WHERE severity='critical'"); critical=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM dlp_events WHERE severity='high'"); high=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM dlp_events WHERE severity='medium'"); medium=c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM dlp_events WHERE date(timestamp)=date('now')"); today=c.fetchone()[0]
        c.execute("SELECT COUNT(DISTINCT hostname) FROM dlp_events"); affected=c.fetchone()[0]
        conn.close()
        return JSONResponse({"critical":critical,"high":high,"medium":medium,"today":today,"affected_hosts":affected})
    except Exception as e:
        return JSONResponse({"error":str(e)},status_code=500)

@app.post("/api/admin/dlp/scan")
async def trigger_dlp_scan(request: Request):
    try:
        data = await request.json()
        hostname = data.get("hostname","")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO pending_commands (hostname,command_type,payload) VALUES (?,?,?)",
            (hostname,"dlp_scan",json.dumps(data.get("policy",{}))))
        cmd_id = c.lastrowid
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok","command_id":cmd_id})
    except Exception as e:
        return JSONResponse({"error":str(e)},status_code=500)


# ── WAKE ON LAN ───────────────────────────────────────────────
@app.post("/api/admin/wol")
async def wake_on_lan(request: Request):
    try:
        data = await request.json()
        mac = data.get("mac","").strip()
        hostname = data.get("hostname","")
        broadcast = data.get("broadcast","${VULN_SCANNER_IP}5")
        if not mac:
            return JSONResponse({"error":"MAC address required"})
        # Clean MAC format
        mac = mac.replace("-",":").replace(".",":")
        import subprocess
        r = subprocess.run(
            ["/usr/bin/wakeonlan","-i",broadcast, mac],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return JSONResponse({"status":"ok","message":f"Magic packet sent to {mac} ({hostname})"})
        else:
            return JSONResponse({"error":r.stderr or "Failed to send"})
    except Exception as e:
        return JSONResponse({"error":str(e)}, status_code=500)


# ── AGENT AUTO-UPDATE ─────────────────────────────────────────
AGENT_VERSION_STATE = {
    "current_version": "2.0.0",
    "staged_version": None,
    "approved": False
}

@app.get("/api/agent/version")
async def agent_version(request: Request):
    """Agent checks this to know if update available. Only returns
    update_available=True if a staged version has been human-approved."""
    if AGENT_VERSION_STATE["approved"] and AGENT_VERSION_STATE["staged_version"]:
        return JSONResponse({
            "version": AGENT_VERSION_STATE["staged_version"],
            "update_available": True
        })
    return JSONResponse({
        "version": AGENT_VERSION_STATE["current_version"],
        "update_available": False
    })

@app.post("/api/admin/agent/stage_version")
async def stage_agent_version(request: Request):
    """Admin stages a new version number (does NOT auto-approve)."""
    try:
        data = await request.json()
        AGENT_VERSION_STATE["staged_version"] = data.get("version")
        AGENT_VERSION_STATE["approved"] = False
        return JSONResponse({"status": "ok", "staged_version": AGENT_VERSION_STATE["staged_version"], "note": "Staged but NOT yet approved for rollout"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/agent/approve_rollout")
async def approve_agent_rollout(request: Request):
    """Admin approves the staged version for fleet-wide rollout."""
    if not AGENT_VERSION_STATE["staged_version"]:
        return JSONResponse({"error": "No staged version to approve"}, status_code=400)
    AGENT_VERSION_STATE["approved"] = True
    return JSONResponse({"status": "ok", "message": f"Version {AGENT_VERSION_STATE['staged_version']} approved for rollout. Agents will update on next check-in."})

@app.post("/api/admin/agent/cancel_rollout")
async def cancel_agent_rollout(request: Request):
    """Emergency stop - halts an in-progress rollout immediately."""
    AGENT_VERSION_STATE["approved"] = False
    return JSONResponse({"status": "ok", "message": "Rollout cancelled/paused."})

@app.get("/api/admin/agent/rollout_status")
async def get_rollout_status(request: Request):
    return JSONResponse(AGENT_VERSION_STATE)

@app.get("/api/agent/download")
async def agent_download(request: Request):
    """Download latest agent binary. Serves compiled, zero-dependency
    binaries when available (preferred), falls back to raw script."""
    agent_type = request.query_params.get("type", "windows")
    base_dir = os.path.dirname(__file__)

    if agent_type == "linux":
        binary_path = os.path.join(base_dir, "dist", "endpoint-agent-linux")
        if os.path.exists(binary_path):
            return FileResponse(binary_path, filename="endpoint-agent-linux", media_type="application/octet-stream")
        script_path = os.path.join(base_dir, "endpoint_agent_linux.py")
        if os.path.exists(script_path):
            return FileResponse(script_path, filename="endpoint_agent_linux.py")

    elif agent_type == "windows":
        exe_path = os.path.join(base_dir, "dist", "endpoint-agent-windows.exe")
        if os.path.exists(exe_path):
            return FileResponse(exe_path, filename="endpoint-agent-windows.exe", media_type="application/octet-stream")
        script_path = os.path.join(base_dir, "endpoint_agent.py")
        if os.path.exists(script_path):
            return FileResponse(script_path, filename="endpoint_agent.py")

    return JSONResponse({"error": f"Agent not found for type={agent_type}"}, status_code=404)


@app.get("/robots.txt")
async def robots_txt():
    return Response("User-agent: *\nDisallow: /", media_type="text/plain")

@app.get("/sitemap.xml")
async def sitemap():
    return Response("<sitemap></sitemap>", media_type="application/xml")


# ── SECURITY SCAN APIS ────────────────────────────────────────
@app.get("/api/admin/security/bandit")
async def run_bandit(request: Request):
    try:
        import subprocess
        r = subprocess.run(
            ["/home/chatbot/.local/bin/bandit","-r",
             "/home/chatbot/chatbot/chatbot.py","-ll","--format","text"],
            capture_output=True, text=True, timeout=60
        )
        return JSONResponse({"output": r.stdout + r.stderr})
    except Exception as e:
        return JSONResponse({"error": str(e)})

@app.get("/api/admin/security/pip-audit")
async def run_pip_audit(request: Request):
    try:
        import subprocess
        r = subprocess.run(
            ["/home/chatbot/.local/bin/pip-audit",
             "--path","/home/chatbot/chatbot/chatenv/lib/python3.10/site-packages"],
            capture_output=True, text=True, timeout=120
        )
        return JSONResponse({"output": r.stdout + r.stderr})
    except Exception as e:
        return JSONResponse({"error": str(e)})

@app.get("/api/admin/security/zap")
async def run_zap(request: Request):
    try:
        import subprocess
        subprocess.Popen([
            "docker","run","--rm","--network","host",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py","-t","http://127.0.0.1:7000",
            "-r","/tmp/zap_report.html"
        ])
        return JSONResponse({"status":"ok","message":"ZAP scan started"})
    except Exception as e:
        return JSONResponse({"error": str(e)})

@app.get("/api/admin/security/zap-report")
async def zap_report():
    if os.path.exists("/tmp/zap_report.html"):
        return FileResponse("/tmp/zap_report.html")
    return JSONResponse({"error":"No report yet. Run ZAP scan first."})

@app.get("/api/admin/security/log")
async def security_log(request: Request):
    try:
        log_path = "/home/chatbot/logs/watchdog.log"
        if os.path.exists(log_path):
            with open(log_path) as f:
                return JSONResponse({"log": f.read()[-3000:]})
        return JSONResponse({"log": "No log entries yet"})
    except Exception as e:
        return JSONResponse({"error": str(e)})


# ══ INCIDENTS ═══════════════════════════════════════════════
@app.get("/api/admin/incidents")
async def get_incidents(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 200")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"incidents": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/incidents")
async def create_incident(request: Request):
    try:
        data = await request.json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO incidents (title,severity,status,host,description,source) VALUES (?,?,?,?,?,?)",
            (data.get("title"), data.get("severity","medium"), "open",
             data.get("host",""), data.get("description",""), data.get("source","manual")))
        iid = c.lastrowid
        conn.commit(); conn.close()

        # Auto-resolution check
        autoresolve = process_incident_for_autoresolve(
            iid, data.get("title",""), data.get("description",""), data.get("host",""))

        return JSONResponse({"status":"ok","id":iid,"autoresolve":autoresolve})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE incidents SET status='resolved',resolved_at=datetime('now') WHERE id=?", (incident_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/incidents/{incident_id}/progress")
async def progress_incident(incident_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE incidents SET status='in_progress',updated_at=datetime('now') WHERE id=?", (incident_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ══ CHANGES ══════════════════════════════════════════════════
@app.get("/api/admin/changes")
async def get_changes(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM changes ORDER BY created_at DESC LIMIT 200")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"changes": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/changes")
async def create_change(request: Request):
    try:
        data = await request.json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO changes (title,change_type,status,host,risk,description,source) VALUES (?,?,?,?,?,?,?)",
            (data.get("title"), data.get("change_type","other"), "pending",
             data.get("host",""), data.get("risk","low"),
             data.get("description",""), data.get("source","manual")))
        cid = c.lastrowid
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok","id":cid})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/changes/{change_id}/approve")
async def approve_change(change_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE changes SET status='approved' WHERE id=?", (change_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/changes/{change_id}/reject")
async def reject_change(change_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE changes SET status='rejected' WHERE id=?", (change_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/changes/{change_id}/execute")
async def execute_change(change_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE changes SET status='executed',executed_at=datetime('now') WHERE id=?", (change_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ══ SOFTWARE CHANGES ═════════════════════════════════════════
@app.get("/api/admin/software/changes")
async def get_software_changes(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM software_changes ORDER BY detected_at DESC LIMIT 200")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"changes": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/software/compliance")
async def get_software_compliance(request: Request):
    try:
        required = [
            {"name":"Wazuh Agent","required":True},
            {"name":"RustDesk","required":True},
            {"name":"Trend Micro","required":True}
        ]
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        violations = []
        c.execute("SELECT hostname FROM endpoints WHERE status='online'")
        online = [r[0] for r in c.fetchall()]
        for pc in online:
            c.execute("SELECT software_name FROM software_inventory WHERE hostname=?", (pc,))
            sw = [r[0].lower() for r in c.fetchall()]
            for req in required:
                if not any(req["name"].lower() in s for s in sw):
                    violations.append({"hostname":pc,"missing":req["name"]})
        conn.close()
        return JSONResponse({"required":required,"violations":violations})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ══ OPENVAS (real GMP via SSH + docker exec) ═══════════════
OPENVAS_HOST = "${VULN_SCANNER_IP}"
OPENVAS_SSH_USER = "openvas"
OPENVAS_SSH_KEY = "/home/chatbot/.ssh/id_ed25519_openvas"
OPENVAS_GMP_USER = os.getenv("OPENVAS_GMP_USER")
OPENVAS_GMP_PASS = os.getenv("OPENVAS_GMP_PASS")
OPENVAS_SOCKET_VOL = "greenbone-community-edition_gvmd_socket_vol"

def gvm_gmp_call(xml_command, timeout=60):
    """Run a GMP command against OpenVAS via SSH + docker exec, return raw XML string."""
    import subprocess
    docker_cmd = (
        f"docker run --rm -v {OPENVAS_SOCKET_VOL}:/run/gvmd "
        f"registry.community.greenbone.net/community/gvm-tools "
        f"gvm-cli --gmp-username {OPENVAS_GMP_USER} --gmp-password '{OPENVAS_GMP_PASS}' "
        f"socket --socketpath /run/gvmd/gvmd.sock --xml '{xml_command}'"
    )
    ssh_cmd = [
        "/usr/bin/ssh", "-i", OPENVAS_SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        f"{OPENVAS_SSH_USER}@{OPENVAS_HOST}",
        docker_cmd
    ]
    r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise Exception(f"SSH/GMP call failed: {r.stderr.strip()}")
    return r.stdout.strip()

def gvm_xml_to_dict(xml_str):
    import xml.etree.ElementTree as ET
    return ET.fromstring(xml_str)

@app.post("/api/admin/openvas/scan")
async def openvas_scan(request: Request):
    try:
        data = await request.json()
        target_ip = data.get("target", "10.0.0.0/24")

        create_target_xml = f'<create_target><name>AI Assistant-{target_ip}-{int(__import__("time").time())}</name><hosts>{target_ip}</hosts><port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/></create_target>'
        target_resp = gvm_gmp_call(create_target_xml)
        target_root = gvm_xml_to_dict(target_resp)
        target_id = target_root.get("id")
        if not target_id:
            return JSONResponse({"error": "Failed to create target", "raw": target_resp}, status_code=500)

        create_task_xml = (
            f'<create_task><name>AI Assistant Scan {target_ip}</name>'
            f'<target id="{target_id}"/>'
            f'<config id="daba56c8-73ec-11df-a475-002264764cea"/>'
            f'<scanner id="08b69003-5fc2-4037-a479-93b440211c73"/>'
            f'</create_task>'
        )
        task_resp = gvm_gmp_call(create_task_xml)
        task_root = gvm_xml_to_dict(task_resp)
        task_id = task_root.get("id")
        if not task_id:
            return JSONResponse({"error": "Failed to create task", "raw": task_resp}, status_code=500)

        gvm_gmp_call(f'<start_task task_id="{task_id}"/>')

        return JSONResponse({
            "status": "ok",
            "task_id": task_id,
            "target_id": target_id,
            "message": f"Real OpenVAS scan started for {target_ip}"
        })
    except Exception as e:
        return JSONResponse({"error": str(e), "message": "OpenVAS scan failed"}, status_code=500)

@app.get("/api/admin/openvas/results")
async def openvas_results(request: Request):
    try:
        tasks_resp = gvm_gmp_call('<get_tasks/>')
        root = gvm_xml_to_dict(tasks_resp)
        results = []
        for task in root.findall("task"):
            name_el = task.find("name")
            status_el = task.find("status")
            progress_el = task.find("progress")
            severity_el = task.find("last_report/report/severity")
            results.append({
                "id": task.get("id"),
                "name": name_el.text if name_el is not None else "",
                "status": status_el.text if status_el is not None else "",
                "progress": progress_el.text if progress_el is not None else "0",
                "severity": severity_el.text if severity_el is not None else None
            })
        return JSONResponse({"results": results})
    except Exception as e:
        return JSONResponse({"error": str(e), "results": []}, status_code=500)

@app.get("/api/admin/openvas/report/{task_id}")
async def openvas_report(task_id: str, request: Request):
    try:
        resp = gvm_gmp_call(f'<get_reports task_id="{task_id}"/>')
        root = gvm_xml_to_dict(resp)
        findings = []
        for result in root.findall(".//results/result"):
            name_el = result.find("name")
            host_el = result.find("host")
            severity_el = result.find("severity")
            desc_el = result.find("description")
            findings.append({
                "name": name_el.text if name_el is not None else "",
                "host": host_el.text if host_el is not None else "",
                "severity": severity_el.text if severity_el is not None else "0",
                "description": (desc_el.text or "")[:300] if desc_el is not None else ""
            })
        return JSONResponse({"findings": findings})
    except Exception as e:
        return JSONResponse({"error": str(e), "findings": []}, status_code=500)

# ══ OPENCTI ══════════════════════════════════════════════════
OPENCTI_URL = "http://${THREAT_INTEL_IP}:8080"
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN")

def opencti_query(query, variables=None):
    r = requests.post(f"{OPENCTI_URL}/graphql",
        headers={"Authorization": f"Bearer {OPENCTI_TOKEN}",
                 "Content-Type": "application/json"},
        json={"query": query, "variables": variables or {}},
        timeout=15)
    r.raise_for_status()
    return r.json()

@app.get("/api/admin/opencti/feeds")
async def opencti_feeds(request: Request):
    try:
        ap_query = """
        query { attackPatterns(first: 20) {
            edges { node { id name x_mitre_id description } } }
            malwares(first: 10) {
            edges { node { id name } } } }
        """
        counts_query = """
        query {
            indicators { pageInfo { globalCount } }
            reports { pageInfo { globalCount } }
            attackPatterns { pageInfo { globalCount } }
            malwares { pageInfo { globalCount } }
            intrusionSets { pageInfo { globalCount } }
        }
        """
        ap_data = opencti_query(ap_query)
        counts_data = opencti_query(counts_query)

        attack_patterns = []
        for e in ap_data.get("data",{}).get("attackPatterns",{}).get("edges",[]):
            n = e["node"]
            attack_patterns.append({
                "mitre_id": n.get("x_mitre_id","") or "",
                "name": n.get("name",""),
                "description": (n.get("description") or "")[:120]
            })

        counts = {k: v.get("pageInfo",{}).get("globalCount",0)
                  for k,v in counts_data.get("data",{}).items()}

        return JSONResponse({
            "attack_patterns": attack_patterns,
            "counts": counts
        })
    except Exception as e:
        return JSONResponse({"attack_patterns":[],"counts":{},"error": str(e)}, status_code=500)

@app.post("/api/admin/opencti/refresh")
async def opencti_refresh(request: Request):
    return JSONResponse({"status":"ok","message":"Feeds refreshed"})

# ══ COMMAND AUDIT ════════════════════════════════════════════
@app.get("/api/admin/command_audit")
async def command_audit(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Join pending_commands with results
        c.execute("""
            SELECT p.id, p.hostname, p.command_type, p.payload, p.status, p.created_at,
                   r.stdout, r.stderr, r.returncode
            FROM pending_commands p
            LEFT JOIN command_results r ON p.id = r.command_id
            ORDER BY p.created_at DESC LIMIT 100
        """)
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"commands": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

# ══ AUTO-DETECT SOFTWARE CHANGES ════════════════════════════
def detect_software_changes(hostname, new_software_list):
    """Compare new software list with previous, record changes"""
    BLACKLIST = ['bittorrent','utorrent','qbittorrent','teamviewer','anydesk','ccleaner']
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Get previous software list
        c.execute("SELECT software_name, software_version FROM software_inventory WHERE hostname=?", (hostname,))
        old = {r[0].lower(): r[1] for r in c.fetchall()}
        new = {s.get("name","").lower(): s.get("version","") for s in new_software_list if s.get("name")}

        # Detect installed
        for name, ver in new.items():
            if name not in old:
                change_type = "blacklisted" if any(b in name for b in BLACKLIST) else "installed"
                c.execute("INSERT INTO software_changes (hostname,software_name,new_version,change_type,os_name) VALUES (?,?,?,?,?)",
                    (hostname, name, ver, change_type, ""))
                # Auto-create incident for blacklisted
                if change_type == "blacklisted":
                    c.execute("INSERT INTO incidents (title,severity,status,host,description,source) VALUES (?,?,?,?,?,?)",
                        (f"Blacklisted software detected: {name}", "high", "open", hostname,
                         f"Software '{name}' is on the blacklist and was installed on {hostname}", "auto"))

        # Detect removed
        for name in old:
            if name not in new:
                c.execute("INSERT INTO software_changes (hostname,software_name,old_version,change_type) VALUES (?,?,?,?)",
                    (hostname, name, old[name], "removed"))

        # Detect updated
        for name in new:
            if name in old and new[name] != old[name] and old[name]:
                c.execute("INSERT INTO software_changes (hostname,software_name,old_version,new_version,change_type) VALUES (?,?,?,?,?)",
                    (hostname, name, old[name], new[name], "updated"))

        conn.commit()
        conn.close()
    except: pass


# ══ AUTO-RESOLUTION ENGINE ═══════════════════════════════════
def match_known_solution(incident_title, incident_description=""):
    """Check if an incident matches a known solution pattern.
    Returns the matched solution dict, or None if no match."""
    try:
        text = (incident_title + " " + (incident_description or "")).lower()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM solutions_library WHERE enabled=1")
        solutions = [dict(r) for r in c.fetchall()]
        conn.close()

        for sol in solutions:
            keywords = [k.strip().lower() for k in (sol.get("match_keywords") or "").split(",") if k.strip()]
            for kw in keywords:
                if kw in text:
                    return sol
        return None
    except Exception as e:
        print("match_known_solution error:", e)
        return None

def execute_known_fix(solution, hostname, incident_id):
    """Execute the matched fix via agent command queue. Logs result."""
    try:
        fix_cmd = solution.get("fix_command","")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Map fix_command to actual agent command types
        cmd_map = {
            "service_restart": ("service_restart", ""),
            "clear_temp": ("shell", "cleanup_temp"),
            "report_top_cpu": ("collect_performance", ""),
            "av_restart": ("service_restart", "antivirus"),
            "wazuh_restart": ("service_restart", "WazuhSvc"),
            "usb_notify": ("dlp_scan", "quick"),
            "block_ip": ("shell", "block_ip_placeholder"),
            "flag_manual": (None, None),  # No auto-action, just flags
        }
        cmd_type, payload = cmd_map.get(fix_cmd, (None, None))

        result_status = "resolved"
        action_note = solution.get("fix_action","Unknown fix")

        if cmd_type and hostname:
            c.execute("INSERT INTO pending_commands (hostname, command_type, payload) VALUES (?,?,?)",
                (hostname, cmd_type, payload))
        elif not hostname:
            result_status = "no_host"
            action_note += " (no hostname on incident - manual action needed)"

        # Log auto-resolution
        c.execute("""INSERT INTO auto_resolutions
            (incident_id, solution_id, hostname, action_taken, result, status)
            VALUES (?,?,?,?,?,?)""",
            (incident_id, solution.get("id"), hostname, action_note,
             f"Matched: {solution.get('pattern_name')}", result_status))

        # Update solution usage count
        c.execute("UPDATE solutions_library SET times_used = times_used + 1 WHERE id=?", (solution.get("id"),))

        # Update incident: mark resolved with note, HIGH importance flag
        c.execute("""UPDATE incidents SET
            status='resolved', resolved_at=datetime('now'),
            description = description || ' [AUTO-RESOLVED: ' || ? || ']'
            WHERE id=?""", (action_note, incident_id))

        conn.commit()
        conn.close()
        return {"status": result_status, "action": action_note}
    except Exception as e:
        print("execute_known_fix error:", e)
        return {"status": "error", "error": str(e)}


def correlate_with_openvas(hostname):
    """Check if OpenVAS has an open/recent finding for this hostname."""
    try:
        tasks_resp = gvm_gmp_call("<get_tasks/>")
        root = gvm_xml_to_dict(tasks_resp)
        for task in root.findall("task"):
            name_el = task.find("name")
            severity_el = task.find("last_report/report/severity")
            if name_el is not None and hostname.lower() in (name_el.text or "").lower():
                sev = severity_el.text if severity_el is not None else None
                if sev and sev not in ("-99.0", None):
                    return {"matched": True, "severity": sev, "task_name": name_el.text}
        return {"matched": False}
    except Exception as e:
        return {"matched": False, "error": str(e)}

def correlate_with_opencti(alert_text):
    """Check if alert text mentions a MITRE technique ID we have in OpenCTI."""
    try:
        import re
        mitre_ids = re.findall(r"T[0-9]{4}(?:\.[0-9]{3})?", alert_text or "")
        if not mitre_ids:
            return {"matched": False}
        ids_json = json.dumps(mitre_ids)
        query_parts = []
        query_parts.append("query { attackPatterns(filters: {mode: or, filters: [{key: ")
        query_parts.append(chr(34) + "x_mitre_id" + chr(34))
        query_parts.append(", values: ")
        query_parts.append(ids_json)
        query_parts.append("}], filterGroups: []}) { edges { node { name x_mitre_id description } } } }")
        query = "".join(query_parts)
        data = opencti_query(query)
        edges = data.get("data", {}).get("attackPatterns", {}).get("edges", [])
        if edges:
            node = edges[0]["node"]
            return {"matched": True, "mitre_id": node.get("x_mitre_id"), "name": node.get("name"), "description": (node.get("description") or "")[:200]}
        return {"matched": False}
    except Exception as e:
        return {"matched": False, "error": str(e)}

def build_correlated_context(title, description, hostname):
    """Gather OpenVAS + OpenCTI context for an incident, for evidence + confidence scoring."""
    context = {"openvas": {"matched": False}, "opencti": {"matched": False}, "confidence": "low"}
    if hostname:
        context["openvas"] = correlate_with_openvas(hostname)
    combined_text = title + " " + (description or "")
    context["opencti"] = correlate_with_opencti(combined_text)
    matches = 0
    if context["openvas"].get("matched", False):
        matches += 1
    if context["opencti"].get("matched", False):
        matches += 1
    if matches == 2:
        context["confidence"] = "high"
    elif matches == 1:
        context["confidence"] = "medium"
    return context



@app.post("/api/wazuh/ar_webhook")
async def wazuh_ar_webhook(request: Request):
    """Receives n8n-forwarded Wazuh alerts for brute-force + Host Blocked events.
    Tracks repeat offenders and escalates to permanent block on 3rd+ offense."""
    try:
        data = await request.json()
        rule_id = str(data.get("rule", {}).get("id", ""))
        rule_desc = data.get("rule", {}).get("description", "")
        source_ip = data.get("data", {}).get("srcip", "") or data.get("srcip", "")
        hostname = data.get("agent", {}).get("name", "")

        ESCALATION_RULES = ["125712", "125714", "120531", "120532", "122110", "122111", "123210", "123211"]

        if rule_id not in ESCALATION_RULES or not source_ip:
            return JSONResponse({"status": "ignored", "reason": "not a tracked brute-force rule"})

        # Exclude LAN ranges from tracking/escalation entirely
        if source_ip.startswith("10.0.0."):
            return JSONResponse({"status": "ignored", "reason": "internal LAN IP, not tracked"})

        result = track_and_escalate_block(source_ip, rule_id, rule_desc, hostname)

        if result.get("tier") == "permanent":
            block_result = apply_escalated_block(source_ip, hostname, "permanent")
            # Auto-create incident for permanent block - needs human review
            conn = sqlite3.connect(DB_PATH)
            c2 = conn.cursor()
            c2.execute("INSERT INTO incidents (title,severity,status,host,description,source) VALUES (?,?,?,?,?,?)",
                (f"PERMANENT BLOCK applied: {source_ip}", "critical", "open", hostname,
                 f"IP {source_ip} triggered {result.get('offense_count')} offenses (rule {rule_id}: {rule_desc}). Permanently blocked - review recommended.",
                 "auto"))
            conn.commit(); conn.close()
            return JSONResponse({"status": "escalated", "tier": "permanent", "block_result": block_result, "offense_count": result.get("offense_count")})
        elif result.get("tier") == "24hr":
            return JSONResponse({"status": "tracked", "tier": "24hr", "note": "Wazuh native AR handles 24hr block", "offense_count": result.get("offense_count")})
        else:
            return JSONResponse({"status": "tracked", "tier": "30min", "note": "Wazuh native AR handles 30min block", "offense_count": result.get("offense_count")})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/blocked_ips")
async def get_blocked_ips(request: Request):
    """List all tracked blocked IPs with offense history."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM blocked_ip_history ORDER BY last_seen DESC LIMIT 200")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"blocked_ips": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/blocked_ips/{ip}/unblock")
async def unblock_ip(ip: str, request: Request):
    """Manually unblock a permanently-blocked IP after review."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT hostname FROM blocked_ip_history WHERE source_ip=? AND permanent=1", (ip,))
        row = c.fetchone()
        if not row:
            conn.close()
            return JSONResponse({"error": "No permanent block found for this IP"}, status_code=404)
        hostname = row[0]
        cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        c.execute("INSERT INTO pending_commands (hostname, command_type, payload) VALUES (?,?,?)",
            (hostname, "shell", cmd))
        c.execute("UPDATE blocked_ip_history SET permanent=0, block_tier='manually_unblocked' WHERE source_ip=?", (ip,))
        conn.commit(); conn.close()
        return JSONResponse({"status": "ok", "message": f"Unblock command queued for {hostname}"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

def track_and_escalate_block(source_ip, rule_id, rule_description, hostname):
    """Track repeat offenders and escalate block duration. Returns escalation info."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ip_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            rule_id TEXT,
            rule_description TEXT,
            hostname TEXT,
            offense_count INTEGER DEFAULT 1,
            first_seen TEXT DEFAULT (datetime(\'now\')),
            last_seen TEXT DEFAULT (datetime(\'now\')),
            block_tier TEXT DEFAULT \'30min\',
            permanent INTEGER DEFAULT 0
        )""")
        c.execute("SELECT id, offense_count FROM blocked_ip_history WHERE source_ip=? AND last_seen > datetime(\'now\', \'-30 days\')", (source_ip,))
        row = c.fetchone()

        if row is None:
            c.execute("INSERT INTO blocked_ip_history (source_ip, rule_id, rule_description, hostname, offense_count, block_tier) VALUES (?,?,?,?,1,\'30min\')",
                (source_ip, rule_id, rule_description, hostname))
            tier = "30min"
            count = 1
        else:
            rec_id, count = row
            count += 1
            if count == 2:
                tier = "24hr"
            elif count >= 3:
                tier = "permanent"
            else:
                tier = "30min"
            c.execute("UPDATE blocked_ip_history SET offense_count=?, last_seen=datetime(\'now\'), block_tier=?, permanent=? WHERE id=?",
                (count, tier, 1 if tier == "permanent" else 0, rec_id))

        conn.commit()
        conn.close()
        return {"offense_count": count, "tier": tier, "source_ip": source_ip}
    except Exception as e:
        return {"error": str(e)}

def apply_escalated_block(source_ip, hostname, tier):
    """For 2nd+ offenses, push a longer/permanent block via agent command (bypasses Wazuh's 30-min AR timeout)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if tier == "24hr":
            cmd = f"sudo iptables -A INPUT -s {source_ip} -j DROP && (echo \'sudo iptables -D INPUT -s {source_ip} -j DROP\' | at now + 24 hours)"
        elif tier == "permanent":
            cmd = f"sudo iptables -A INPUT -s {source_ip} -j DROP"
        else:
            return {"status": "skipped", "reason": "tier 30min handled by Wazuh AR natively"}

        c.execute("INSERT INTO pending_commands (hostname, command_type, payload) VALUES (?,?,?)",
            (hostname, "shell", cmd))
        cmd_id = c.lastrowid
        conn.commit()
        conn.close()
        return {"status": "ok", "command_id": cmd_id, "tier": tier}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def process_incident_for_autoresolve(incident_id, title, description, hostname):
    """Main entry point: correlate context, then check + resolve or leave open."""
    context = build_correlated_context(title, description, hostname)
    try:
        conn = sqlite3.connect(DB_PATH)
        c2 = conn.cursor()
        note = " [CORRELATION: confidence=" + context["confidence"] + ", openvas=" + str(context["openvas"].get("matched")) + ", opencti=" + str(context["opencti"].get("matched")) + "]"
        c2.execute("UPDATE incidents SET description = description || ? WHERE id=?", (note, incident_id))
        conn.commit(); conn.close()
    except Exception:
        pass

    solution = match_known_solution(title, description)
    if solution:
        result = execute_known_fix(solution, hostname, incident_id)
        return {"matched": True, "solution": solution.get("pattern_name"), "result": result, "correlation": context}
    else:
        return {"matched": False, "correlation": context}

# ══ SOLUTIONS LIBRARY API ═════════════════════════════════════
@app.get("/api/admin/solutions")
async def get_solutions(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM solutions_library ORDER BY times_used DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"solutions": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/solutions")
async def add_solution(request: Request):
    try:
        data = await request.json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""INSERT INTO solutions_library
            (pattern_name, match_keywords, fix_action, fix_command, risk_level)
            VALUES (?,?,?,?,?)""",
            (data.get("pattern_name"), data.get("match_keywords"),
             data.get("fix_action"), data.get("fix_command","manual"),
             data.get("risk_level","low")))
        sid = c.lastrowid
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok","id":sid})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.post("/api/admin/solutions/{sol_id}/toggle")
async def toggle_solution(sol_id: int, request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE solutions_library SET enabled = 1 - enabled WHERE id=?", (sol_id,))
        conn.commit(); conn.close()
        return JSONResponse({"status":"ok"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/admin/auto_resolutions")
async def get_auto_resolutions(request: Request):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM auto_resolutions ORDER BY created_at DESC LIMIT 100")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return JSONResponse({"resolutions": rows})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7000)


# ── PBS INTEGRATION ───────────────────────────────────────────
