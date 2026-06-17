"""
Offline smoke tests for all 6 demo events.

Validates deterministic tool-layer behavior only — no LLM, no network,
no outbound calls to demo IPs/domains. Blocklist and regex checks are local.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from tools.ip_lookup import ip_lookup
from tools.log_matcher import log_pattern_match
from tools.threat_intel import threat_intel
from utils.guardrails import check_input

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_PATH = PROJECT_ROOT / "demo" / "example_events.json"

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)


def _load_demo_events() -> list[dict]:
    return json.loads(DEMO_PATH.read_text(encoding="utf-8"))


def _ips_in(text: str) -> list[str]:
    return list(set(IP_PATTERN.findall(text)))


def _domains_in(text: str) -> list[str]:
    return list(set(DOMAIN_PATTERN.findall(text)))


class TestDemoEventsInputGuard(unittest.TestCase):
    """Every demo event must pass the input guard (no agent run needed)."""

    def test_all_demo_events_allowed(self) -> None:
        for event in _load_demo_events():
            allowed, msg = check_input(event["text"])
            self.assertTrue(allowed, f"{event['label']}: {msg}")


class TestDemoEventSSHBruteForce(unittest.TestCase):
    TEXT = (
        "2024-01-15 03:22:11 sshd[1234]: Failed password for root "
        "from 185.220.101.1 port 54321 ssh2"
    )

    def test_log_pattern_detects_brute_force(self) -> None:
        result = log_pattern_match(self.TEXT)
        self.assertGreater(result["match_count"], 0)
        self.assertEqual(result["highest_severity"], "Medium")

    def test_threat_intel_blocklist_high(self) -> None:
        result = threat_intel("185.220.101.1", abuseipdb_api_key="")
        self.assertEqual(result["risk_hint"], "High")
        self.assertTrue(result.get("blocklist_match"))


class TestDemoEventSQLi(unittest.TestCase):
    TEXT = (
        '192.168.1.50 - - [15/Jan/2024:10:05:33 +0000] '
        '"GET /search?q=1\' OR 1=1-- HTTP/1.1" 404 512 "-" "sqlmap/1.7"'
    )

    def test_log_pattern_detects_sqli_and_scanner(self) -> None:
        result = log_pattern_match(self.TEXT)
        self.assertGreaterEqual(result["match_count"], 2)
        self.assertEqual(result["highest_severity"], "High")

    def test_private_ip_lookup_blocked(self) -> None:
        result = ip_lookup("192.168.1.50")
        self.assertIn("error", result)


class TestDemoEventSuspiciousDomain(unittest.TestCase):
    TEXT = (
        "DNS query for suspicious-domain-abc123.xyz from workstation "
        "WS-4421 — flagged by DNS filtering"
    )

    def test_threat_intel_suspicious_tld(self) -> None:
        result = threat_intel(
            "suspicious-domain-abc123.xyz",
            indicator_type="domain",
            abuseipdb_api_key="",
        )
        self.assertEqual(result["risk_hint"], "Medium")
        self.assertIn("suspicious_tld", result["tags"])

    def test_domain_extracted_from_event(self) -> None:
        domains = _domains_in(self.TEXT)
        self.assertIn("suspicious-domain-abc123.xyz", domains)


class TestDemoEventHighRiskIP(unittest.TestCase):
    TEXT = (
        "Firewall alert: outbound connection attempt to "
        "45.155.205.233:4444 from host APP-SERVER-03"
    )

    def test_threat_intel_blocklist_high(self) -> None:
        result = threat_intel("45.155.205.233", abuseipdb_api_key="")
        self.assertEqual(result["risk_hint"], "High")
        self.assertIn("scanner", result.get("tags", []))


class TestDemoEventPathTraversal(unittest.TestCase):
    TEXT = (
        '10.0.0.5 - admin [15/Jan/2024:14:30:00] '
        '"GET /../../../etc/passwd HTTP/1.1" 403 0 "-" "nikto/2.5.0"'
    )

    def test_log_pattern_detects_traversal_and_scanner(self) -> None:
        result = log_pattern_match(self.TEXT)
        self.assertGreaterEqual(result["match_count"], 2)
        self.assertEqual(result["highest_severity"], "High")

    def test_private_ip_lookup_blocked(self) -> None:
        result = ip_lookup("10.0.0.5")
        self.assertIn("error", result)


class TestDemoEventBenignInternal(unittest.TestCase):
    TEXT = (
        "User jsmith successfully logged in from 10.0.1.50 via VPN "
        "at 2024-01-15 09:00:00"
    )

    def test_log_pattern_no_attack_signatures(self) -> None:
        result = log_pattern_match(self.TEXT)
        self.assertEqual(result["match_count"], 0)

    def test_private_ip_lookup_blocked(self) -> None:
        result = ip_lookup("10.0.1.50")
        self.assertIn("error", result)


class TestDemoEventsToolExpectations(unittest.TestCase):
    """Summary expectations table encoded as one test per label."""

    EXPECTATIONS = {
        "SSH brute-force (external IP)": {
            "min_log_matches": 1,
            "min_log_severity": "Medium",
            "blocklist_ip": "185.220.101.1",
        },
        "SQL injection attempt (web log)": {
            "min_log_matches": 2,
            "min_log_severity": "High",
            "private_ips": ["192.168.1.50"],
        },
        "Suspicious domain lookup": {
            "domain": "suspicious-domain-abc123.xyz",
            "domain_risk": "Medium",
        },
        "High-risk IP (demo blocklist)": {
            "blocklist_ip": "45.155.205.233",
        },
        "Path traversal probe": {
            "min_log_matches": 2,
            "min_log_severity": "High",
            "private_ips": ["10.0.0.5"],
        },
        "Benign internal event": {
            "max_log_matches": 0,
            "private_ips": ["10.0.1.50"],
        },
    }

    def test_all_demo_tool_expectations(self) -> None:
        events = {e["label"]: e["text"] for e in _load_demo_events()}
        severity_rank = {"Low": 1, "Medium": 2, "High": 3}

        for label, spec in self.EXPECTATIONS.items():
            text = events[label]

            if "min_log_matches" in spec:
                log_result = log_pattern_match(text)
                self.assertGreaterEqual(
                    log_result["match_count"],
                    spec["min_log_matches"],
                    label,
                )
                if spec.get("max_log_matches") is not None:
                    self.assertLessEqual(
                        log_result["match_count"],
                        spec["max_log_matches"],
                        label,
                    )
                if "min_log_severity" in spec:
                    self.assertIsNotNone(log_result["highest_severity"], label)
                    self.assertGreaterEqual(
                        severity_rank[log_result["highest_severity"]],
                        severity_rank[spec["min_log_severity"]],
                        label,
                    )

            if "blocklist_ip" in spec:
                ti = threat_intel(spec["blocklist_ip"], abuseipdb_api_key="")
                self.assertEqual(ti["risk_hint"], "High", label)

            if "domain" in spec:
                ti = threat_intel(
                    spec["domain"],
                    indicator_type="domain",
                    abuseipdb_api_key="",
                )
                self.assertEqual(ti["risk_hint"], spec["domain_risk"], label)

            for ip in spec.get("private_ips", []):
                self.assertIn("error", ip_lookup(ip), f"{label}: {ip}")


if __name__ == "__main__":
    unittest.main()
