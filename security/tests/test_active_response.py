"""Offline tests for the active-response scripts (no firewall or Wazuh needed)."""
import importlib.util
import ipaddress
import json
import pathlib
import subprocess

import pytest

HERE = pathlib.Path(__file__).resolve().parent.parent / "active-response"
spec = importlib.util.spec_from_file_location("pan_block_ip", HERE / "pan-block-ip.py")
pan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pan)

ALLOW = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12")]


def _msg(command="add", srcip="203.0.113.50"):
    return {"version": 1, "command": command,
            "parameters": {"alert": {"rule": {"id": "100502"}, "data": {"srcip": srcip}}}}


def test_extracts_srcip_from_wazuh_message():
    assert pan.extract_srcip(_msg()) == "203.0.113.50"


def test_public_ip_is_accepted():
    assert str(pan.validate_ip("203.0.113.50", ALLOW)) == "203.0.113.50"


@pytest.mark.parametrize("bad", [
    "127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1",   # special addresses
    "10.1.2.3", "172.17.0.1",                              # allowlisted
    "not-an-ip", "1.2.3.4\"><x>", "",                      # junk / injection
])
def test_dangerous_or_allowlisted_ips_are_refused(bad):
    with pytest.raises(ValueError):
        pan.validate_ip(bad, ALLOW)


def test_uid_message_contains_ip_tag_and_timeout():
    msg = pan.build_uid_message(ipaddress.ip_address("203.0.113.50"), "wazuh-block", 3600)
    assert 'ip="203.0.113.50"' in msg
    assert '<member timeout="3600">wazuh-block</member>' in msg


def test_config_validation(tmp_path):
    conf = tmp_path / "pan.conf"
    conf.write_text("[panos]\nhost = fw.local\napi_key = k\ntimeout_seconds = 3600\n"
                    "[allowlist]\nnetworks = 10.0.0.0/8\n")
    cfg = pan.load_config(str(conf))
    assert cfg["tag"] == "wazuh-block" and len(cfg["allowlist"]) == 1
    conf.write_text("[panos]\nhost = https://evil/x\napi_key = k\n")
    with pytest.raises(ValueError):
        pan.load_config(str(conf))


def test_delete_messages_are_ignored(monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(_msg("delete")) + "\n"))
    assert pan.main() == 0


def test_safe_mode_script_creates_flag_on_add(tmp_path):
    flag, log = tmp_path / "SAFE_MODE", tmp_path / "ar.log"
    env = {"TRIAGE_SAFE_MODE_FLAG": str(flag), "AR_LOG": str(log), "PATH": "/usr/bin:/bin"}
    script = str(HERE / "triage-safe-mode.sh")
    subprocess.run(["bash", script], input=json.dumps(_msg("delete")) + "\n",
                   env=env, text=True, check=True)
    assert not flag.exists()
    subprocess.run(["bash", script], input=json.dumps(_msg("add")) + "\n",
                   env=env, text=True, check=True)
    assert flag.exists()
    assert "ENABLED" in log.read_text()
