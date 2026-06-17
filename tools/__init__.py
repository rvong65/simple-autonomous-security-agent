"""Investigation tool registry and dispatch."""

from __future__ import annotations

from typing import Any, Callable

from tools.ip_lookup import ip_lookup
from tools.log_matcher import log_pattern_match
from tools.threat_intel import threat_intel
from tools.whois import whois_lookup

ToolFunc = Callable[..., dict]

TOOL_REGISTRY: dict[str, ToolFunc] = {
    "ip_lookup": ip_lookup,
    "whois_lookup": whois_lookup,
    "log_pattern_match": log_pattern_match,
    "threat_intel": threat_intel,
}

TOOL_SCHEMAS: dict[str, dict] = {
    "ip_lookup": {
        "description": "Geolocation, ASN, and proxy/hosting hints for a public IP address.",
        "parameters": {"ip": "IPv4 or IPv6 address string"},
    },
    "whois_lookup": {
        "description": "WHOIS registration details for a domain or IP.",
        "parameters": {"target": "Domain name or IP address"},
    },
    "log_pattern_match": {
        "description": "Regex detection of brute-force, SQLi, command injection, and scanner patterns.",
        "parameters": {"log_line": "Raw log line or event text"},
    },
    "threat_intel": {
        "description": "IP/domain reputation check (AbuseIPDB if configured, else local heuristics).",
        "parameters": {
            "indicator": "IP address or domain",
            "indicator_type": "ip, domain, or auto (optional, default auto)",
        },
    },
}


def dispatch(
    name: str,
    args: dict[str, Any],
    *,
    abuseipdb_api_key: str = "",
    tool_timeout: int = 5,
) -> dict:
    """
    Execute a registered tool by name with validated arguments.

    Args:
        name: Tool name from TOOL_REGISTRY.
        args: Tool-specific keyword arguments.
        abuseipdb_api_key: Passed to threat_intel when applicable.
        tool_timeout: HTTP timeout for network tools.

    Returns:
        Tool result dict.
    """
    if name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool: {name}"}

    func = TOOL_REGISTRY[name]

    if name == "ip_lookup":
        return func(args.get("ip", ""), timeout=tool_timeout)
    if name == "whois_lookup":
        return func(args.get("target", ""))
    if name == "log_pattern_match":
        return func(args.get("log_line", ""))
    if name == "threat_intel":
        return func(
            args.get("indicator", ""),
            indicator_type=args.get("indicator_type", "auto"),
            abuseipdb_api_key=abuseipdb_api_key,
            timeout=tool_timeout,
        )

    return {"error": f"Tool dispatch not implemented: {name}"}
