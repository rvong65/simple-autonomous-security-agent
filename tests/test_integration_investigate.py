"""
Full investigation integration tests — same code path as Streamlit Investigate.

Requires Ollama running with the configured model (or Groq when LLM_PROVIDER=groq).

Run (venv activated):
    python -m unittest tests.test_integration_investigate -v
    python scripts/run_demo_investigations.py
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from config.settings import LLMProvider, get_settings
from tests.integration_helpers import (
    investigate_like_app,
    ollama_available,
    save_investigation_results,
)
from utils.llm import groq_api_key_configured

DEMO_PATH = Path(__file__).resolve().parent.parent / "demo" / "example_events.json"


def _load_demo_events() -> list[dict]:
    return json.loads(DEMO_PATH.read_text(encoding="utf-8"))


def _llm_ready() -> bool:
    settings = get_settings()
    if settings.llm_provider == LLMProvider.GROQ:
        return groq_api_key_configured()
    return ollama_available(settings)


@unittest.skipUnless(
    _llm_ready(),
    "LLM not ready — start Ollama or set GROQ_API_KEY with LLM_PROVIDER=groq",
)
class TestIntegrationInvestigate(unittest.TestCase):
    """End-to-end investigations via run_investigation (mirrors app.py)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = get_settings()

    def _run_demo(self, label_contains: str) -> dict:
        events = _load_demo_events()
        match = [e for e in events if label_contains.lower() in e["label"].lower()]
        self.assertEqual(len(match), 1, f"Demo not found: {label_contains}")
        result = investigate_like_app(
            match[0]["text"],
            settings=self.settings,
            demo_label=match[0]["label"],
        )
        self.assertTrue(result["input_allowed"], result.get("input_refusal"))
        self.assertIsNone(result["error"], result.get("error"))
        self.assertIsNotNone(result["report"], "No report produced")
        self.assertEqual(
            result["analysis"].get("quality_gate_failures", []),
            [],
            result["analysis"].get("quality_gate_failures"),
        )
        return result

    def test_ssh_brute_force_investigation(self) -> None:
        result = self._run_demo("SSH brute-force")
        self.assertIn("log_pattern_match", result["analysis"]["tools_called"])

    def test_high_risk_ip_investigation(self) -> None:
        result = self._run_demo("High-risk IP")
        self.assertEqual(result["report"]["risk_level"], "High")

    def test_all_demos_produce_report(self) -> None:
        """Run every demo; save JSON to tests/output/latest.json for review."""
        results = []
        for event in _load_demo_events():
            result = investigate_like_app(
                event["text"],
                settings=self.settings,
                demo_label=event["label"],
            )
            results.append(result)
            self.assertTrue(result["input_allowed"], event["label"])
            self.assertIsNone(result["error"], f"{event['label']}: {result.get('error')}")
            self.assertIsNotNone(result["report"], event["label"])
            self.assertEqual(
                result["analysis"].get("quality_gate_failures", []),
                [],
                f"{event['label']}: {result['analysis'].get('quality_gate_failures')}",
            )

        path = save_investigation_results(results, label="integration_test")
        self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
