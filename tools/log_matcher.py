"""Regex-based log pattern matching for common attack signatures."""

from __future__ import annotations

import re
from typing import Literal

Severity = Literal["Low", "Medium", "High"]

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}

RULES: list[tuple[str, str, Severity]] = [
    # Brute force
    (r"failed\s+login", "failed login", "Medium"),
    (r"failed\s+password", "failed password", "Medium"),
    (r"authentication\s+failure", "authentication failure", "Medium"),
    (r"invalid\s+password", "invalid password", "Medium"),
    (r"bad\s+password", "bad password", "Medium"),
    (r"login\s+attempt\s+failed", "login attempt failed", "Medium"),
    # SQLi
    (r"union\s+select", "union select", "High"),
    (r"'\s*or\s+1\s*=\s*1", "' OR 1=1", "High"),
    (r";\s*drop\s+table", "; DROP TABLE", "High"),
    (r"'\s*;\s*--", "SQL comment injection", "High"),
    (r"information_schema", "information_schema", "High"),
    # Command injection
    (r";\s*wget\s+", "; wget", "High"),
    (r"\|\s*bash", "| bash", "High"),
    (r"`id`", "backtick id command", "High"),
    (r"\$\(whoami\)", "$(whoami)", "High"),
    (r";\s*curl\s+", "; curl", "High"),
    (r";\s*nc\s+", "; nc netcat", "High"),
    # Path traversal
    (r"\.\./", "path traversal ../", "High"),
    (r"\.\.%2f", "encoded path traversal", "High"),
    (r"%2e%2e%2f", "double-encoded traversal", "High"),
    # Suspicious user agents
    (r"sqlmap", "sqlmap scanner UA", "Medium"),
    (r"nikto", "nikto scanner UA", "Medium"),
    (r"\bnmap\b", "nmap scanner UA", "Medium"),
    (r"masscan", "masscan scanner UA", "Medium"),
    (r"dirbuster", "dirbuster scanner UA", "Medium"),
    # Scanner probes
    (r"/wp-admin", "wordpress admin probe", "Low"),
    (r"/\.env", ".env file probe", "Medium"),
    (r"/phpmyadmin", "phpMyAdmin probe", "Low"),
    (r"/admin/config", "admin config probe", "Medium"),
    (r"/\.git/", ".git directory probe", "Medium"),
]

_COMPILED_RULES = [
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, label, severity in RULES
]


def log_pattern_match(log_line: str) -> dict:
    """
    Match a log line against known attack patterns.

    Args:
        log_line: Raw log line or event text to analyze.

    Returns:
        Dict with matches, highest_severity, and match_count.
    """
    if not log_line or not log_line.strip():
        return {
            "matches": [],
            "highest_severity": None,
            "match_count": 0,
            "error": "Empty log line",
        }

    matches: list[dict] = []
    highest: Severity | None = None

    for compiled, label, severity in _COMPILED_RULES:
        match = compiled.search(log_line)
        if match:
            snippet_start = max(0, match.start() - 20)
            snippet_end = min(len(log_line), match.end() + 20)
            snippet = log_line[snippet_start:snippet_end].strip()

            matches.append(
                {
                    "category": label,
                    "pattern": compiled.pattern,
                    "severity": severity,
                    "snippet": snippet,
                }
            )
            if highest is None or SEVERITY_RANK[severity] > SEVERITY_RANK[highest]:
                highest = severity

    return {
        "matches": matches,
        "highest_severity": highest,
        "match_count": len(matches),
    }
