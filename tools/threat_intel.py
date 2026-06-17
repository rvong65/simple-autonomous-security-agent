"""Threat intelligence lookup with AbuseIPDB (optional) and local heuristics fallback."""

from __future__ import annotations

import re

import requests

from tools.ip_lookup import ip_lookup

# Demo blocklist for reliable high-risk demos without API keys
DEMO_BLOCKLIST: dict[str, dict] = {
    "185.220.101.1": {
        "risk_hint": "High",
        "reason": "Known Tor exit node (demo blocklist)",
        "tags": ["tor", "anonymizer"],
    },
    "45.155.205.233": {
        "risk_hint": "High",
        "reason": "Known scanner/probe source (demo blocklist)",
        "tags": ["scanner", "brute_force"],
    },
    "89.248.165.45": {
        "risk_hint": "Medium",
        "reason": "Historical scanning activity (demo blocklist)",
        "tags": ["scanner"],
    },
}

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

DEFAULT_TIMEOUT = 5


def _check_abuseipdb(ip: str, api_key: str, timeout: int) -> dict | None:
    """Query AbuseIPDB if API key is configured."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "source": "abuseipdb",
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except requests.RequestException:
        return None


def _local_heuristics(indicator: str, indicator_type: str) -> dict:
    """Free fallback using blocklist and basic IP geo hints."""
    result: dict = {
        "source": "local_heuristics",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "risk_hint": "unknown",
        "tags": [],
    }

    if indicator_type == "ip" or IPV4_PATTERN.match(indicator):
        blocklist_hit = DEMO_BLOCKLIST.get(indicator)
        if blocklist_hit:
            result.update(blocklist_hit)
            result["blocklist_match"] = True
            return result

        geo = ip_lookup(indicator)
        if "error" not in geo:
            result["geo"] = {
                "country": geo.get("country"),
                "org": geo.get("org"),
                "asn": geo.get("asn"),
                "hosting": geo.get("hosting"),
                "proxy": geo.get("proxy"),
            }
            if geo.get("hosting") or geo.get("proxy"):
                result["risk_hint"] = "Medium"
                result["tags"].append("hosting_or_proxy")
            else:
                result["risk_hint"] = "Low"
        else:
            result["risk_hint"] = "unknown"
            result["geo_error"] = geo.get("error")

    elif indicator_type == "domain":
        suspicious_tlds = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top")
        if indicator.endswith(suspicious_tlds):
            result["risk_hint"] = "Medium"
            result["tags"].append("suspicious_tld")
        else:
            result["risk_hint"] = "Low"

    return result


def threat_intel(
    indicator: str,
    indicator_type: str = "auto",
    abuseipdb_api_key: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Check an indicator against threat intelligence sources.

    Args:
        indicator: IP address or domain to check.
        indicator_type: "ip", "domain", or "auto" (detect from indicator).
        abuseipdb_api_key: Optional AbuseIPDB API key for live reputation.
        timeout: HTTP request timeout in seconds.

    Returns:
        JSON-serializable threat intel result.
    """
    indicator = indicator.strip()
    if not indicator:
        return {"error": "Empty indicator", "indicator": indicator}

    if indicator_type == "auto":
        indicator_type = "ip" if IPV4_PATTERN.match(indicator) else "domain"

    result: dict = {
        "indicator": indicator,
        "indicator_type": indicator_type,
    }

    if indicator_type == "ip" and abuseipdb_api_key:
        abuse_data = _check_abuseipdb(indicator, abuseipdb_api_key, timeout)
        if abuse_data:
            result.update(abuse_data)
            score = abuse_data.get("abuse_score", 0) or 0
            if score >= 75:
                result["risk_hint"] = "High"
            elif score >= 25:
                result["risk_hint"] = "Medium"
            else:
                result["risk_hint"] = "Low"
            return result

    heuristics = _local_heuristics(indicator, indicator_type)
    result.update(heuristics)

    if not abuseipdb_api_key and indicator_type == "ip":
        result["note"] = "Set ABUSEIPDB_API_KEY for live reputation checks"

    return result
