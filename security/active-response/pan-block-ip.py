#!/usr/bin/env python3
"""
Wazuh active response: block an attacker IP on a Palo Alto firewall.

How it works
  The IP is registered with a tag (default "wazuh-block") through the PAN-OS
  User-ID XML API, with a timeout so the block expires on its own. A Dynamic
  Address Group matching that tag is referenced by a deny rule at the top of
  the security policy, so the block applies within seconds and needs no
  commit.

Safety
  * Only acts on "add" messages; expiry is handled by PAN-OS.
  * Refuses invalid, loopback, link-local, multicast, unspecified, and
    allowlisted addresses, so a bad rule can never lock out the office.
  * HTTPS with certificate verification only (use ca_file for a private CA).
  * API key read from a root-only config file, never from the command line.

Install (on the Wazuh manager):
  sudo cp pan-block-ip.py /var/ossec/active-response/bin/
  sudo chown root:wazuh /var/ossec/active-response/bin/pan-block-ip.py
  sudo chmod 750 /var/ossec/active-response/bin/pan-block-ip.py
  sudo cp pan-block.conf.example /var/ossec/etc/pan-block.conf   # then edit
  sudo chown root:wazuh /var/ossec/etc/pan-block.conf
  sudo chmod 640 /var/ossec/etc/pan-block.conf
"""
import configparser
import datetime
import ipaddress
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request

CONF_PATH = "/var/ossec/etc/pan-block.conf"
LOG_PATH = "/var/ossec/logs/active-responses.log"
NAME = "pan-block-ip"
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")
_TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")


def log(message: str) -> None:
    stamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp} {NAME}: {message}\n")
    except OSError:
        sys.stderr.write(f"{stamp} {NAME}: {message}\n")


def load_config(path: str = CONF_PATH) -> dict:
    parser = configparser.ConfigParser()
    if not parser.read(path):
        raise ValueError(f"config file not found: {path}")
    panos = parser["panos"]
    cfg = {
        "host": panos.get("host", "").strip(),
        "api_key": panos.get("api_key", "").strip(),
        "tag": panos.get("tag", "wazuh-block").strip(),
        "timeout": panos.getint("timeout_seconds", 3600),
        "ca_file": panos.get("ca_file", "").strip() or None,
        "allowlist": [
            ipaddress.ip_network(n.strip(), strict=False)
            for n in parser.get("allowlist", "networks", fallback="").split(",")
            if n.strip()
        ],
    }
    if not _HOST_RE.match(cfg["host"]):
        raise ValueError("invalid firewall host")
    if not cfg["api_key"]:
        raise ValueError("api_key is empty")
    if not _TAG_RE.match(cfg["tag"]):
        raise ValueError("invalid tag")
    if not 60 <= cfg["timeout"] <= 86400:
        raise ValueError("timeout_seconds must be between 60 and 86400")
    return cfg


def extract_srcip(message: dict) -> str:
    alert = (message.get("parameters") or {}).get("alert") or {}
    return str((alert.get("data") or {}).get("srcip", "")).strip()


def validate_ip(raw: str, allowlist) -> ipaddress._BaseAddress:
    ip = ipaddress.ip_address(raw)  # raises ValueError if not an IP
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"refusing to block special address {ip}")
    for net in allowlist:
        if ip.version == net.version and ip in net:
            raise ValueError(f"{ip} is allowlisted ({net})")
    return ip


def build_uid_message(ip, tag: str, timeout: int) -> str:
    # ip and tag are validated, so no user-controlled text reaches the XML
    return (
        "<uid-message><version>2.0</version><type>update</type><payload>"
        f'<register><entry ip="{ip}" persistent="0"><tag>'
        f'<member timeout="{int(timeout)}">{tag}</member>'
        "</tag></entry></register></payload></uid-message>"
    )


def send_to_firewall(cfg: dict, uid_message: str) -> None:
    url = f"https://{cfg['host']}/api/"
    body = urllib.parse.urlencode({"type": "user-id", "cmd": uid_message}).encode()
    req = urllib.request.Request(url, data=body, headers={"X-PAN-KEY": cfg["api_key"]})
    ctx = ssl.create_default_context(cafile=cfg["ca_file"])
    # Fixed https:// scheme built above; no user-controlled URL
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # nosec B310
        text = resp.read().decode("utf-8", "replace")
    if 'status="success"' not in text:
        raise RuntimeError(f"firewall rejected request: {text[:200]}")


def main() -> int:
    try:
        message = json.loads(sys.stdin.readline())
    except (ValueError, TypeError):
        log("could not parse input from wazuh-execd")
        return 1
    if message.get("command") != "add":
        return 0
    raw_ip = extract_srcip(message)
    try:
        cfg = load_config()
        ip = validate_ip(raw_ip, cfg["allowlist"])
        send_to_firewall(cfg, build_uid_message(ip, cfg["tag"], cfg["timeout"]))
    except Exception as exc:  # noqa: BLE001 - log and exit; never crash execd
        log(f"NOT blocked {raw_ip!r}: {exc}")
        return 1
    rule = ((message.get("parameters") or {}).get("alert") or {}).get("rule", {}).get("id", "?")
    log(f"blocked {ip} on firewall for {cfg['timeout']}s (tag {cfg['tag']}, rule {rule})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
