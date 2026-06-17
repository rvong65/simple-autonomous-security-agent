"""Unit tests for deterministic risk scoring."""

from __future__ import annotations

import unittest

from agent import AgentStep
from utils.risk_scorer import (
    compute_tool_risk_floor,
    max_risk_level,
    merge_report_risk,
)


class TestRiskScorer(unittest.TestCase):
    def test_max_risk_level(self) -> None:
        self.assertEqual(max_risk_level("Low", "High"), "High")
        self.assertEqual(max_risk_level("Medium", "Low"), "Medium")

    def test_merge_report_risk_raises_floor(self) -> None:
        self.assertEqual(merge_report_risk("High", "Low"), "High")
        self.assertEqual(merge_report_risk("Medium", "High"), "High")

    def test_blocklist_high_floor(self) -> None:
        steps = [
            AgentStep(
                step=1,
                thought="ti",
                action="threat_intel",
                observation=(
                    '{"risk_hint": "High", "blocklist_match": true, '
                    '"indicator": "45.155.205.233"}'
                ),
            )
        ]
        self.assertEqual(compute_tool_risk_floor(steps), "High")

    def test_log_high_floor(self) -> None:
        steps = [
            AgentStep(
                step=1,
                thought="log",
                action="log_pattern_match",
                observation='{"match_count": 2, "highest_severity": "High"}',
            )
        ]
        self.assertEqual(compute_tool_risk_floor(steps), "High")

    def test_domain_medium_tld(self) -> None:
        steps = [
            AgentStep(
                step=1,
                thought="ti",
                action="threat_intel",
                observation='{"risk_hint": "Medium", "indicator": "evil.xyz"}',
            )
        ]
        self.assertEqual(compute_tool_risk_floor(steps), "Medium")

    def test_empty_steps_low(self) -> None:
        self.assertEqual(compute_tool_risk_floor([]), "Low")


if __name__ == "__main__":
    unittest.main()
