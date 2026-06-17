"""
Run all demo events through the same investigation path as Streamlit's Investigate button.

Usage (with venv activated):
    python scripts/run_demo_investigations.py
    python scripts/run_demo_investigations.py --event "SSH brute-force (external IP)"
    python scripts/run_demo_investigations.py --list

Groq users: each demo triggers multiple LLM calls. Use --delay to avoid HTTP 429
rate limits when running all demos back-to-back (not needed for single UI investigations):
    python scripts/run_demo_investigations.py --delay 15

Output (gitignored):
    tests/output/latest.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import LLMProvider, get_settings
from tests.integration_helpers import (
    investigate_like_app,
    ollama_available,
    print_investigation_summary,
    save_investigation_results,
)
from utils.llm import groq_api_key_configured

DEMO_PATH = PROJECT_ROOT / "demo" / "example_events.json"


def _load_events() -> list[dict]:
    return json.loads(DEMO_PATH.read_text(encoding="utf-8"))


def _llm_ready(settings) -> bool:
    if settings.llm_provider == LLMProvider.GROQ:
        return groq_api_key_configured()
    return ollama_available(settings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SASA demo investigations like Streamlit.")
    parser.add_argument("--event", help="Run a single demo by label (partial match OK)")
    parser.add_argument("--list", action="store_true", help="List demo event labels")
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Pause between demos (use ~12–20s for Groq to avoid 429 rate limits)",
    )
    args = parser.parse_args()

    events = _load_events()

    if args.list:
        for e in events:
            print(f"  - {e['label']}")
        return 0

    settings = get_settings()
    if not _llm_ready(settings):
        if settings.llm_provider == LLMProvider.GROQ:
            print("LLM_PROVIDER=groq but GROQ_API_KEY is not set in the environment.")
        else:
            print(
                "Ollama is not reachable at",
                settings.ollama_base_url,
                f"\nEnsure Ollama is running and {settings.llm_model} is pulled.",
            )
        return 1

    print(f"LLM: {settings.llm_provider.value} / {settings.llm_model}")
    if settings.llm_provider == LLMProvider.GROQ and args.delay <= 0 and len(events) > 1:
        print("Tip: Groq may rate-limit rapid runs — try --delay 15")

    if args.event:
        needle = args.event.lower()
        events = [e for e in events if needle in e["label"].lower()]
        if not events:
            print(f"No demo matching: {args.event}")
            return 1

    results: list[dict] = []
    any_gate_failures = False
    for i, event in enumerate(events):
        if i > 0 and args.delay > 0:
            print(f"  (waiting {args.delay:.0f}s before next demo…)")
            time.sleep(args.delay)
        print(f"\nRunning: {event['label']} ...")
        result = investigate_like_app(
            event["text"],
            settings=settings,
            demo_label=event["label"],
        )
        result["demo_label"] = event["label"]
        if result["analysis"].get("quality_gate_failures"):
            any_gate_failures = True
        results.append(result)
        print_investigation_summary(result, event["label"])

    out_path = save_investigation_results(results)
    print(f"\nFull results written to: {out_path}")
    print(f"Also updated: {out_path.parent / 'latest.json'}")

    if any_gate_failures:
        print("\nQuality gate failures detected — see summaries above.")
        return 1
    print("\nAll quality gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
