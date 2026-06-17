"""Smoke tests for safety guardrails (no network, no subprocess)."""

from __future__ import annotations

import unittest

from utils.guardrails import (
    check_input,
    parse_action_input,
    validate_tool_call,
)


class TestInputGuard(unittest.TestCase):
    def test_allows_log_line_with_ip(self) -> None:
        allowed, msg = check_input(
            "2024-01-15 sshd: Failed password for root from 185.220.101.1"
        )
        self.assertTrue(allowed)
        self.assertEqual(msg, "")

    def test_allows_domain_event(self) -> None:
        allowed, _ = check_input("DNS query for suspicious-domain.xyz flagged")
        self.assertTrue(allowed)

    def test_refuses_attack_request(self) -> None:
        allowed, msg = check_input("hack into this server and steal credentials")
        self.assertFalse(allowed)
        self.assertIn("security event investigation", msg)

    def test_refuses_empty_input(self) -> None:
        allowed, msg = check_input("   ")
        self.assertFalse(allowed)

    def test_refuses_off_topic(self) -> None:
        allowed, msg = check_input("what's the weather today")
        self.assertFalse(allowed)


class TestToolGuard(unittest.TestCase):
    def test_rejects_unknown_tool(self) -> None:
        ok, err = validate_tool_call("run_shell", {"cmd": "ls"})
        self.assertFalse(ok)
        self.assertIn("not in the allowed registry", str(err))

    def test_rejects_private_ip_lookup(self) -> None:
        ok, err = validate_tool_call("ip_lookup", {"ip": "192.168.1.1"})
        self.assertFalse(ok)
        self.assertIn("private", str(err).lower())

    def test_rejects_domain_for_ip_lookup(self) -> None:
        ok, err = validate_tool_call("ip_lookup", {"ip": "evil.example.com"})
        self.assertFalse(ok)
        self.assertIn("valid IP", str(err))

    def test_rejects_private_ip_threat_intel(self) -> None:
        ok, err = validate_tool_call("threat_intel", {"indicator": "10.0.1.50"})
        self.assertFalse(ok)
        self.assertIn("private", str(err).lower())

    def test_accepts_public_ip_lookup(self) -> None:
        ok, args = validate_tool_call("ip_lookup", {"ip": "8.8.8.8"})
        self.assertTrue(ok)
        self.assertEqual(args, {"ip": "8.8.8.8"})

    def test_strips_shell_metacharacters(self) -> None:
        ok, args = validate_tool_call(
            "log_pattern_match",
            {"log_line": "test; rm -rf /"},
        )
        self.assertTrue(ok)
        self.assertNotIn(";", args["log_line"])

    def test_rejects_extra_parameters(self) -> None:
        ok, err = validate_tool_call("ip_lookup", {"ip": "8.8.8.8", "evil": "payload"})
        self.assertFalse(ok)


class TestActionInputParse(unittest.TestCase):
    def test_valid_json(self) -> None:
        ok, parsed = parse_action_input('{"ip": "8.8.8.8"}')
        self.assertTrue(ok)
        self.assertEqual(parsed, {"ip": "8.8.8.8"})

    def test_invalid_json(self) -> None:
        ok, err = parse_action_input("{not json}")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
