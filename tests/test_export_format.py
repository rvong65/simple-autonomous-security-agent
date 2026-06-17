"""Tests for investigation export formatting."""

from __future__ import annotations

import json
import unittest

from agent import AgentStep, InvestigationReport, InvestigationState
from config.settings import LLMProvider, Settings
from utils.export_format import build_export_payload, build_summary_text


class TestExportFormat(unittest.TestCase):
    def _sample_state_and_report(self) -> tuple[InvestigationState, InvestigationReport]:
        obs = json.dumps({"match_count": 1, "highest_severity": "Medium"})
        state = InvestigationState(
            event_input="Failed password from 185.220.101.1",
            steps=[
                AgentStep(
                    step=0,
                    thought="Auto scan",
                    action="log_pattern_match",
                    observation=obs,
                ),
            ],
        )
        report = InvestigationReport(
            risk_level="High",
            summary="Tor exit node brute-force attempt.",
            findings=["Failed password"],
            recommendations=["Monitor auth logs"],
            tool_risk_floor="High",
            raw_steps=state.steps,
        )
        return state, report

    def test_json_no_duplicate_steps(self) -> None:
        state, report = self._sample_state_and_report()
        payload = build_export_payload(state, report)
        self.assertNotIn("raw_steps", payload.get("investigation", {}))
        self.assertNotIn("report", payload)
        self.assertEqual(len(payload["steps"]), 1)
        self.assertIsInstance(payload["steps"][0]["observation"], dict)

    def test_json_includes_metadata(self) -> None:
        state, report = self._sample_state_and_report()
        settings = Settings(llm_provider=LLMProvider.GROQ, llm_model="llama-3.1-8b-instant")
        payload = build_export_payload(state, report, settings=settings)
        self.assertEqual(payload["metadata"]["llm_provider"], "groq")

    def test_summary_includes_event_and_disclaimer(self) -> None:
        state, report = self._sample_state_and_report()
        text = build_summary_text(state, report)
        self.assertIn("Event:", text)
        self.assertIn(state.event_input, text)
        self.assertIn("correlate with internal telemetry", text)


if __name__ == "__main__":
    unittest.main()
