"""Smoke tests for agent parsing logic (no LLM, no network)."""

from __future__ import annotations

import unittest

from agent import (
    _extract_indicators,
    _normalize_risk_level,
    _parse_llm_response,
    _synthesize_fallback_report,
)
from agent import AgentStep, InvestigationState


class TestIndicatorExtraction(unittest.TestCase):
    def test_extracts_ip_and_domain(self) -> None:
        text = "Failed login from 8.8.8.8 to evil.example.com"
        indicators = _extract_indicators(text)
        self.assertIn("8.8.8.8", indicators["ips"])
        self.assertIn("evil.example.com", indicators["domains"])


class TestResponseParsing(unittest.TestCase):
    def test_parses_action(self) -> None:
        text = (
            "THOUGHT: I should check the IP.\n"
            "ACTION: ip_lookup\n"
            'ACTION_INPUT: {"ip": "8.8.8.8"}'
        )
        parsed = _parse_llm_response(text)
        self.assertEqual(parsed["type"], "action")
        self.assertEqual(parsed["action"], "ip_lookup")
        self.assertEqual(parsed["action_input"], {"ip": "8.8.8.8"})

    def test_parses_final_answer(self) -> None:
        text = (
            "THOUGHT: Enough data gathered.\n"
            'FINAL_ANSWER: {"risk_level": "High", "summary": "Bad IP", '
            '"findings": ["Tor exit"], "recommendations": ["Block IP"]}'
        )
        parsed = _parse_llm_response(text)
        self.assertEqual(parsed["type"], "final")
        self.assertEqual(parsed["report"]["risk_level"], "High")

    def test_parse_error_on_garbage(self) -> None:
        parsed = _parse_llm_response("Just some random text without format.")
        self.assertEqual(parsed["type"], "parse_error")


class TestRiskNormalization(unittest.TestCase):
    def test_normalizes_med(self) -> None:
        self.assertEqual(_normalize_risk_level("med"), "Medium")

    def test_defaults_unknown_to_medium(self) -> None:
        self.assertEqual(_normalize_risk_level("critical"), "High")


class TestFallbackReport(unittest.TestCase):
    def test_synthesizes_from_log_match(self) -> None:
        state = InvestigationState(
            event_input="test event",
            steps=[
                AgentStep(
                    step=1,
                    thought="check log",
                    action="log_pattern_match",
                    action_input={"log_line": "union select"},
                    observation='{"match_count": 1, "highest_severity": "High"}',
                )
            ],
        )
        report = _synthesize_fallback_report(state)
        self.assertEqual(report.risk_level, "High")
        self.assertGreater(len(report.findings), 0)


if __name__ == "__main__":
    unittest.main()
