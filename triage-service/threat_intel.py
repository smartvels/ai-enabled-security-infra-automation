"""
Threat intelligence enrichment for alert source IPs (AbuseIPDB, VirusTotal).

Security design:
  * Privacy: only public IPs are looked up. Private, internal, loopback, and
    reserved addresses are never sent to a third party.
  * Untrusted input: provider responses are reduced to numbers, booleans, and
    fixed-format codes. Free text (ISP names, domains, WHOIS data) is dropped,
    because an attacker who controls an IP can also control that text and use
    it for prompt injection.
  * Fail-safe: timeouts and provider errors never block triage; the provider
    is reported as "unavailable" and triage continues.
  * Secrets: API keys come from the environment and are never logged or
    returned to callers.
  * Rate limits: a bounded in-memory TTL cache avoids repeat lookups; failed
    lookups are not cached.

Environment variables:
    ABUSEIPDB_API_KEY            - AbuseIPDB key (provider skipped if unset)
    VT_API_KEY                   - VirusTotal key (provider skipped if unset)
    TI_TIMEOUT_SECONDS           - per-request timeout (default 5)
    TI_CACHE_TTL_SECONDS         - cache lifetime (default 3600)
    TI_ABUSE_SCORE_THRESHOLD     - AbuseIPDB confidence that marks an IP malicious (default 75)
    TI_VT_MALICIOUS_THRESHOLD    - VirusTotal engines flagging malicious (default 3)
"""
import ipaddress
import os
import re
import threading
import time

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VT_KEY = os.environ.get("VT_API_KEY", "")
TIMEOUT = float(os.environ.get("TI_TIMEOUT_SECONDS", "5"))
CACHE_TTL = int(os.environ.get("TI_CACHE_TTL_SECONDS", "3600"))
CACHE_MAX = 5000
ABUSE_THRESHOLD = int(os.environ.get("TI_ABUSE_SCORE_THRESHOLD", "75"))
VT_THRESHOLD = int(os.environ.get("TI_VT_MALICIOUS_THRESHOLD", "3"))

_cache: dict = {}
_lock = threading.Lock()
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_USAGE_RE = re.compile(r"[^A-Za-z /()-]")


def _int(value, low=0, high=None) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    n = max(low, n)
    return min(n, high) if high is not None else n


def public_ip(raw) -> str:
    """Return the normalized IP if it is publicly routable, else an empty string."""
    try:
        ip = ipaddress.ip_address(str(raw or "").strip())
    except ValueError:
        return ""
    return str(ip) if ip.is_global else ""


def _abuseipdb(ip: str) -> dict:
    resp = requests.get(
        ABUSEIPDB_URL,
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json().get("data") or {}
    country = str(data.get("countryCode") or "")
    return {
        "abuse_confidence": _int(data.get("abuseConfidenceScore"), 0, 100),
        "total_reports": _int(data.get("totalReports")),
        "country": country if _COUNTRY_RE.match(country) else "",
        "usage_type": _USAGE_RE.sub("", str(data.get("usageType") or ""))[:40],
        "is_tor": bool(data.get("isTor", False)),
    }


def _virustotal(ip: str) -> dict:
    resp = requests.get(VT_URL.format(ip=ip), headers={"x-apikey": VT_KEY}, timeout=TIMEOUT)
    resp.raise_for_status()
    stats = ((resp.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    return {
        "malicious": _int(stats.get("malicious")),
        "suspicious": _int(stats.get("suspicious")),
        "harmless": _int(stats.get("harmless")),
    }


PROVIDERS = (
    ("abuseipdb", _abuseipdb, lambda: ABUSEIPDB_KEY),
    ("virustotal", _virustotal, lambda: VT_KEY),
)


def _cache_get(ip: str):
    with _lock:
        hit = _cache.get(ip)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        _cache.pop(ip, None)
    return None


def _cache_put(ip: str, value: dict) -> None:
    with _lock:
        if len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[ip] = (time.monotonic() + CACHE_TTL, value)


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def enrich_ip(raw_ip) -> dict:
    """Look up a source IP with every configured provider. Never raises."""
    ip = public_ip(raw_ip)
    if not ip:
        return {"status": "skipped", "reason": "not a public IP", "malicious": False}

    cached = _cache_get(ip)
    if cached is not None:
        return {**cached, "cached": True}

    sources = {}
    for name, lookup, key in PROVIDERS:
        if not key():
            sources[name] = {"status": "not_configured"}
            continue
        try:
            sources[name] = {"status": "ok", **lookup(ip)}
        except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
            sources[name] = {"status": "unavailable"}

    reasons = []
    abuse = sources.get("abuseipdb", {})
    if abuse.get("status") == "ok" and abuse["abuse_confidence"] >= ABUSE_THRESHOLD:
        reasons.append(f"AbuseIPDB confidence {abuse['abuse_confidence']}%")
    vt = sources.get("virustotal", {})
    if vt.get("status") == "ok" and vt["malicious"] >= VT_THRESHOLD:
        reasons.append(f"VirusTotal: {vt['malicious']} engines flag it malicious")

    result = {
        "status": "ok",
        "ip": ip,
        "malicious": bool(reasons),
        "reasons": reasons,
        "sources": sources,
    }
    if any(s.get("status") == "ok" for s in sources.values()):
        _cache_put(ip, result)
    return result
