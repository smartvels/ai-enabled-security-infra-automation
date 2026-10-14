"""
Security regression tests for the IT operations portal.

Each test pins a fix from the security review: server-side access control,
command injection in the OpenVAS integration, input validation, password
hashing, and error-message leakage. No external services are needed.
"""
import hashlib
import importlib
import os
import shlex
import sqlite3
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ADMIN_PW = "Adm1n-test-pass!"
AGENT = "agent-token-test-123"
HOOK = "webhook-token-test-456"


@pytest.fixture(scope="module")
def portal(tmp_path_factory):
    base = tmp_path_factory.mktemp("portal")
    os.environ.update({
        "PORTAL_BASE_DIR": str(base),
        "ADMIN_INITIAL_PASSWORD": ADMIN_PW,
        "AGENT_TOKEN": AGENT,
        "WEBHOOK_TOKEN": HOOK,
    })
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    mod = importlib.import_module("chatbot")
    return mod


@pytest.fixture(scope="module")
def client(portal):
    return TestClient(portal.app)


def _login(client, user="itadmin", pw=ADMIN_PW):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


# --- Access control (default deny) ---------------------------------------

@pytest.mark.parametrize("method,path", [
    ("get", "/api/admin/endpoints"),
    ("post", "/api/admin/command"),
    ("post", "/api/admin/changes/1/execute"),
    ("post", "/api/admin/blocked_ips/203.0.113.9/unblock"),
    ("post", "/api/admin/openvas/scan"),
    ("get", "/api/wazuh/alerts"),
    ("get", "/api/pbs/status"),
    ("get", "/api/zabbix/hosts"),
    ("post", "/api/chat"),
    ("get", "/docs"),
    ("get", "/openapi.json"),
])
def test_protected_endpoints_reject_anonymous_calls(client, method, path):
    assert getattr(client, method)(path).status_code == 401


def test_admin_session_can_reach_admin_api(client):
    r = client.get("/api/admin/agent/rollout_status", headers=_login(client))
    assert r.status_code == 200


def test_employee_role_cannot_reach_admin_api(portal, client):
    conn = sqlite3.connect(portal.DB_PATH)
    conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                 ("emp1", portal.hash_password("Emp-pass-123"), "user"))
    conn.commit()
    conn.close()
    headers = _login(client, "emp1", "Emp-pass-123")
    assert client.get("/api/admin/agent/rollout_status", headers=headers).status_code == 401


def test_agent_endpoints_require_agent_token(client):
    assert client.get("/api/agent/version").status_code == 401
    assert client.get("/api/agent/version", headers={"X-Agent-Token": "wrong"}).status_code == 401
    assert client.get("/api/agent/version", headers={"X-Agent-Token": AGENT}).status_code == 200


def test_webhook_requires_webhook_token(client):
    assert client.post("/api/wazuh/ar_webhook", json={}).status_code == 401


def test_public_paths_stay_public(client):
    assert client.get("/health").status_code == 200


def test_security_headers_present_on_401(client):
    r = client.get("/api/admin/endpoints")
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_cors_is_not_wide_open(client):
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") is None


# --- OpenVAS: input validation and command injection --------------------

@pytest.mark.parametrize("good,expected", [
    ("10.0.0.5", "10.0.0.5"), ("172.20.0.0/24", "172.20.0.0/24"),
])
def test_scan_target_accepts_small_internal_ranges(portal, good, expected):
    assert portal.validate_scan_target(good) == expected


@pytest.mark.parametrize("bad", [
    "8.8.8.8",                      # public address: not ours to scan
    "10.0.0.0/8",                   # too large
    "10.0.0.1'; rm -rf / #",        # shell injection attempt
    "<hosts>x</hosts>", "", None,
])
def test_scan_target_rejects_bad_input(portal, bad):
    with pytest.raises(ValueError):
        portal.validate_scan_target(bad)


def test_scan_endpoint_rejects_injection_without_running_anything(client):
    with patch("subprocess.run") as run:
        r = client.post("/api/admin/openvas/scan", headers=_login(client),
                        json={"target": "10.0.0.1'; touch /tmp/pwned #"})
    assert r.status_code == 400
    run.assert_not_called()


def test_gmp_call_quotes_every_argument(portal):
    evil = "<x/>'; touch /tmp/pwned; echo '"
    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "<ok/>"
        portal.gvm_gmp_call(evil)
    ssh_cmd = run.call_args.args[0]
    assert "StrictHostKeyChecking=yes" in ssh_cmd
    remote = shlex.split(ssh_cmd[-1])            # what the remote shell will see
    assert remote[remote.index("--xml") + 1] == evil   # payload stays one inert argument


def test_report_rejects_non_uuid_task_id(client):
    r = client.get("/api/admin/openvas/report/abc\"/><x", headers=_login(client))
    assert r.status_code in (400, 404)


# --- Passwords ------------------------------------------------------------

def test_new_passwords_use_salted_pbkdf2(portal):
    h1, h2 = portal.hash_password("same"), portal.hash_password("same")
    assert h1.startswith("pbkdf2_sha256$") and h1 != h2
    assert portal.verify_password("same", h1)
    assert not portal.verify_password("other", h1)


def test_legacy_sha256_hash_is_upgraded_at_login(portal, client):
    legacy = hashlib.sha256(b"Legacy-pass-1").hexdigest()
    conn = sqlite3.connect(portal.DB_PATH)
    conn.execute("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                 ("old1", legacy, "user"))
    conn.commit()
    _login(client, "old1", "Legacy-pass-1")
    stored = conn.execute("SELECT password_hash FROM users WHERE username='old1'").fetchone()[0]
    conn.close()
    assert stored.startswith("pbkdf2_sha256$")


# --- Secrets and error leakage ---------------------------------------------

def test_no_hardcoded_wazuh_password(portal):
    src = open(portal.__file__, encoding="utf-8").read()
    assert 'WAZUH_PASS = os.getenv("WAZUH_PASS")' in src
    assert 'WAZUH_PASS = "' not in src


def test_errors_do_not_leak_exception_text(client):
    with patch("requests.post", side_effect=RuntimeError("secret-internal-host:8080 refused")):
        r = client.post("/submit-ticket", headers=_login(client),
                        json={"name": "t", "content": "c", "priority": 3, "urgency": 3, "status": 1})
    assert "secret-internal-host" not in r.text
