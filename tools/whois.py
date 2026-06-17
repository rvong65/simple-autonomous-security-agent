"""WHOIS lookup for domains and IP addresses."""

from __future__ import annotations

import re
from datetime import date, datetime

import whois

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _serialize_date(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _serialize_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def whois_lookup(target: str) -> dict:
    """
    Look up WHOIS registration details for a domain or IP.

    Args:
        target: Domain name (e.g. example.com) or IP address.

    Returns:
        JSON-serializable dict with registration details or error.
    """
    target = target.strip().lower()
    if not target:
        return {"error": "Empty WHOIS target", "target": target}

    # Strip protocol/path if accidentally included
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0].split(":")[0]

    try:
        record = whois.whois(target)
    except Exception as exc:
        return {"error": f"WHOIS lookup failed: {exc}", "target": target}

    if record is None:
        return {"error": "No WHOIS record found", "target": target}

    return {
        "target": target,
        "domain_name": _serialize_list(getattr(record, "domain_name", None)),
        "registrar": getattr(record, "registrar", None),
        "creation_date": _serialize_date(getattr(record, "creation_date", None)),
        "expiration_date": _serialize_date(getattr(record, "expiration_date", None)),
        "updated_date": _serialize_date(getattr(record, "updated_date", None)),
        "name_servers": _serialize_list(getattr(record, "name_servers", None)),
        "status": _serialize_list(getattr(record, "status", None)),
        "org": getattr(record, "org", None),
        "country": getattr(record, "country", None),
    }
