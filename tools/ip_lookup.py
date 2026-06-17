"""IP geolocation and ASN lookup via ipapi.co (free tier, no API key)."""

from __future__ import annotations

import ipaddress
import re

import requests

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
)

DEFAULT_TIMEOUT = 5


def _is_valid_public_ip(ip: str) -> tuple[bool, str | None]:
    """Return (is_valid, error_message)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False, f"Invalid IP address: {ip}"

    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
        return False, f"Private or reserved IP cannot be looked up externally: {ip}"

    return True, None


def ip_lookup(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Look up geolocation, ASN, and proxy/hosting hints for an IP address.

    Args:
        ip: IPv4 or IPv6 address string.
        timeout: HTTP request timeout in seconds.

    Returns:
        JSON-serializable dict with geo/ASN data or error details.
    """
    ip = ip.strip()
    valid, err = _is_valid_public_ip(ip)
    if not valid:
        return {"error": err, "ip": ip}

    url = f"https://ipapi.co/{ip}/json/"
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "SASA/1.0"})
        response.raise_for_status()
        data = response.json()
    except requests.Timeout:
        return {"error": "IP lookup timed out", "ip": ip}
    except requests.RequestException as exc:
        return {"error": f"IP lookup failed: {exc}", "ip": ip}

    if data.get("error"):
        return {"error": data.get("reason", data.get("error")), "ip": ip}

    return {
        "ip": ip,
        "country": data.get("country_name") or data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "org": data.get("org"),
        "asn": data.get("asn"),
        "hostname": data.get("hostname"),
        "timezone": data.get("timezone"),
        "proxy": data.get("proxy"),
        "hosting": data.get("hosting"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
    }
