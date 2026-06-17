"""Safety guardrails: input refusal, tool validation, and rate limiting."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Any

from tools import TOOL_REGISTRY

# --- Input guard patterns ---

HARMFUL_PATTERN = re.compile(
    r"\b(hack\s+into|attack\s+this|exploit\s+this|ddos|deface|destroy|"
    r"bypass\s+security|run\s+malware|deploy\s+ransomware|steal\s+credentials|"
    r"brute\s*force\s+this|penetrate\s+this\s+system)\b",
    re.IGNORECASE,
)

OFF_TOPIC_PATTERN = re.compile(
    r"\b(weather|recipe|cook|sports|movie|music|joke|poem|stock\s+price|"
    r"bitcoin\s+price|write\s+a\s+story|homework)\b",
    re.IGNORECASE,
)

SECURITY_INTENT_PATTERN = re.compile(
    r"\b(investigate|analyze|analyse|check|review|assess|examine|lookup|"
    r"look\s+up|is\s+this\s+suspicious|security\s+event|failed\s+login|"
    r"log\s+line|threat|malicious|suspicious|ip\s+address|domain|whois|"
    r"brute\s*force|sqli|injection|scanner|alert)\b",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

SHELL_METACHAR_PATTERN = re.compile(r"[;|`$&><]")

REFUSAL_MESSAGE = (
    "I can only help with **security event investigation** — analyzing logs, "
    "IPs, domains, and suspicious activity. I cannot assist with offensive "
    "actions, attacks, or non-security topics."
)

OUT_OF_SCOPE_MESSAGE = (
    "This query doesn't appear to be a security investigation request. "
    "Please paste a log line, IP address, domain, or describe a suspicious "
    "security event to investigate."
)

# Allowed parameter keys per tool
TOOL_ALLOWED_KEYS: dict[str, set[str]] = {
    "ip_lookup": {"ip"},
    "whois_lookup": {"target"},
    "log_pattern_match": {"log_line"},
    "threat_intel": {"indicator", "indicator_type"},
}

MAX_INVESTIGATIONS_PER_MINUTE = 3
INVESTIGATION_WINDOW_SECONDS = 60


def is_security_investigation(text: str) -> bool:
    """Return True if the input looks like a legitimate investigation request."""
    text = text.strip()
    if not text:
        return False

    if HARMFUL_PATTERN.search(text):
        return False

    if OFF_TOPIC_PATTERN.search(text) and not SECURITY_INTENT_PATTERN.search(text):
        return False

    if SECURITY_INTENT_PATTERN.search(text):
        return True

    if IP_PATTERN.search(text) or DOMAIN_PATTERN.search(text):
        return True

    # Log-like content (timestamps, HTTP methods, status codes)
    if re.search(r"\b(GET|POST|PUT|DELETE|SSH|HTTP)\b", text, re.IGNORECASE):
        return True
    if re.search(r"\d{4}-\d{2}-\d{2}", text):
        return True

    # Longer free-text security descriptions
    word_count = len(re.findall(r"\w+", text))
    return word_count >= 4


def check_input(text: str) -> tuple[bool, str]:
    """
    Validate user input before starting an investigation.

    Returns:
        (allowed, message) — message is empty if allowed, else refusal text.
    """
    text = text.strip()
    if not text:
        return False, "Please provide a security event to investigate."

    if HARMFUL_PATTERN.search(text):
        return False, REFUSAL_MESSAGE

    if not is_security_investigation(text):
        return False, OUT_OF_SCOPE_MESSAGE

    return True, ""


def _sanitize_string(value: str) -> str:
    """Strip shell metacharacters from tool argument strings."""
    return SHELL_METACHAR_PATTERN.sub("", value).strip()


def _parse_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError:
        return None


def _is_private_ip(ip: str) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast


def _is_public_ip(ip: str) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_multicast
    )


def validate_tool_call(
    tool_name: str,
    args: dict[str, Any],
) -> tuple[bool, dict[str, Any] | str]:
    """
    Validate and sanitize a tool call before dispatch.

    Returns:
        (ok, sanitized_args_or_error_message)
    """
    if tool_name not in TOOL_REGISTRY:
        return False, f"Tool '{tool_name}' is not in the allowed registry."

    allowed_keys = TOOL_ALLOWED_KEYS.get(tool_name, set())
    if not args:
        return False, f"ACTION_INPUT is required for tool '{tool_name}'."

    extra_keys = set(args.keys()) - allowed_keys
    if extra_keys:
        return False, f"Unexpected parameters for {tool_name}: {extra_keys}"

    sanitized: dict[str, Any] = {}
    for key, value in args.items():
        if not isinstance(value, str):
            sanitized[key] = value
            continue
        sanitized[key] = _sanitize_string(value)

    if tool_name == "ip_lookup":
        ip = sanitized.get("ip", "")
        if not ip:
            return False, "ip_lookup requires 'ip' parameter."
        if _parse_ip(ip) is None:
            return False, f"ip_lookup requires a valid IP address, not: {ip}"
        if not _is_public_ip(ip):
            return False, f"Cannot perform external lookup on private or reserved IP: {ip}"

    if tool_name == "threat_intel":
        indicator = sanitized.get("indicator", "")
        if not indicator:
            return False, "threat_intel requires 'indicator' parameter."
        if _parse_ip(indicator) is not None and not _is_public_ip(indicator):
            return False, (
                f"Cannot run external threat intel on private/reserved IP: {indicator}. "
                "Use log_pattern_match for internal host context."
            )

    if tool_name == "whois_lookup" and not sanitized.get("target"):
        return False, "whois_lookup requires 'target' parameter."

    if tool_name == "log_pattern_match" and not sanitized.get("log_line"):
        return False, "log_pattern_match requires 'log_line' parameter."

    return True, sanitized


def check_rate_limit(
    investigation_timestamps: list[float],
    tool_call_count: int,
    max_tool_calls: int,
) -> tuple[bool, str]:
    """
    Check investigation and tool-call rate limits.

    Args:
        investigation_timestamps: List of recent investigation start times (epoch).
        tool_call_count: Tool calls in current investigation.
        max_tool_calls: Max allowed tool calls per investigation.

    Returns:
        (allowed, error_message)
    """
    now = time.time()
    recent = [t for t in investigation_timestamps if now - t < INVESTIGATION_WINDOW_SECONDS]
    if len(recent) >= MAX_INVESTIGATIONS_PER_MINUTE:
        return False, (
            f"Rate limit: max {MAX_INVESTIGATIONS_PER_MINUTE} investigations "
            f"per minute. Please wait before starting another."
        )

    if tool_call_count >= max_tool_calls:
        return False, (
            f"Tool call limit reached ({max_tool_calls} per investigation)."
        )

    return True, ""


def parse_action_input(raw: str) -> tuple[bool, dict[str, Any] | str]:
    """Parse ACTION_INPUT JSON string from LLM output."""
    raw = raw.strip()
    if not raw:
        return False, "Empty ACTION_INPUT"

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, f"Invalid ACTION_INPUT JSON: {exc}"

    if not isinstance(parsed, dict):
        return False, "ACTION_INPUT must be a JSON object"

    return True, parsed
