"""Smoke tests for investigation tools (no network calls)."""

from __future__ import annotations

import unittest

from tools.ip_lookup import ip_lookup
from tools.log_matcher import log_pattern_match
from tools.threat_intel import threat_intel


class TestLogMatcher(unittest.TestCase):
    def test_detects_sqli(self) -> None:
        result = log_pattern_match("GET /search?q=1' OR 1=1-- HTTP/1.1")
        self.assertGreater(result["match_count"], 0)
        self.assertEqual(result["highest_severity"], "High")

    def test_detects_brute_force(self) -> None:
        result = log_pattern_match("sshd: Failed password for root")
        self.assertGreater(result["match_count"], 0)
        self.assertEqual(result["highest_severity"], "Medium")

    def test_detects_ssh_demo_log_line(self) -> None:
        line = (
            "2024-01-15 03:22:11 sshd[1234]: Failed password for root "
            "from 185.220.101.1 port 54321 ssh2"
        )
        result = log_pattern_match(line)
        self.assertGreater(result["match_count"], 0)

    def test_benign_line_no_matches(self) -> None:
        result = log_pattern_match("User jsmith logged in successfully")
        self.assertEqual(result["match_count"], 0)
        self.assertIsNone(result["highest_severity"])

    def test_empty_input(self) -> None:
        result = log_pattern_match("")
        self.assertEqual(result["match_count"], 0)
        self.assertIn("error", result)


class TestIpLookup(unittest.TestCase):
    def test_rejects_private_ip_without_network(self) -> None:
        result = ip_lookup("10.0.1.50")
        self.assertIn("error", result)
        self.assertIn("Private", result["error"])

    def test_rejects_invalid_ip(self) -> None:
        result = ip_lookup("not-an-ip")
        self.assertIn("error", result)


class TestThreatIntel(unittest.TestCase):
    def test_demo_blocklist_high_risk(self) -> None:
        result = threat_intel("185.220.101.1")
        self.assertEqual(result["risk_hint"], "High")
        self.assertTrue(result.get("blocklist_match"))
        self.assertEqual(result["source"], "local_heuristics")

    def test_demo_blocklist_scanner_ip(self) -> None:
        result = threat_intel("45.155.205.233")
        self.assertEqual(result["risk_hint"], "High")

    def test_suspicious_tld_domain(self) -> None:
        result = threat_intel("evil-site.xyz", indicator_type="domain")
        self.assertEqual(result["risk_hint"], "Medium")
        self.assertIn("suspicious_tld", result["tags"])

    def test_empty_indicator(self) -> None:
        result = threat_intel("")
        self.assertIn("error", result)

    def test_note_when_no_abuseipdb_key(self) -> None:
        # Use a non-blocklist IP; patch ip_lookup so this test stays offline.
        from unittest.mock import patch

        fake_geo = {"ip": "8.8.8.8", "country": "United States", "org": "Google", "hosting": False, "proxy": False}
        with patch("tools.threat_intel.ip_lookup", return_value=fake_geo):
            result = threat_intel("8.8.8.8", indicator_type="ip", abuseipdb_api_key="")
        self.assertIn("note", result)


if __name__ == "__main__":
    unittest.main()
