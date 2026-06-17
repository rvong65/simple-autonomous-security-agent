"""Helpers for full investigation integration tests (mirrors Streamlit Investigate)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from agent import InvestigationReport, InvestigationState, looks_like_log_line, run_investigation
from config.settings import Settings, get_settings
from utils.guardrails import check_input
from utils.risk_scorer import SEVERITY_RANK, compute_tool_risk_floor

OUTPUT_DIR = Path(__file__).resolve().parent / "output"

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def ollama_available(settings: Settings | None = None) -> bool:
    """Return True if Ollama responds at the configured base URL."""
    settings = settings or get_settings()
    url = f"{settings.ollama_base_url.rstrip('/')}/api/tags"
    try:
        response = requests.get(url, timeout=3)
        response.raise_for_status()
        return True
    except requests.RequestException:
        return False


def investigate_like_app(
    event_text: str,
    settings: Settings | None = None,
    *,
    demo_label: str = "",
) -> dict[str, Any]:
    """
    Run the same path as app.py Investigate button (minus Streamlit session state).

    Returns:
        Structured dict with input guard result, state, report, error, and analysis flags.
    """
    settings = settings or get_settings()
    allowed, refusal = check_input(event_text)

    result: dict[str, Any] = {
        "event_input": event_text,
        "input_allowed": allowed,
        "input_refusal": refusal,
        "error": None,
        "state": None,
        "report": None,
        "analysis": {},
    }

    if not allowed:
        result["error"] = refusal
        return result

    state, report, error = run_investigation(
        event_text,
        settings=settings,
        investigation_timestamps=[],
    )
    result["state"] = state.model_dump()
    result["report"] = report.model_dump() if report else None
    result["error"] = error
    result["analysis"] = analyze_investigation(state, report, demo_label=demo_label)
    return result


def check_quality_gates(
    state: InvestigationState,
    report: InvestigationReport | None,
    *,
    demo_label: str = "",
) -> list[str]:
    """Release-quality checks for end-to-end investigations."""
    failures: list[str] = []
    if report is None:
        return ["no_report_produced"]

    floor = compute_tool_risk_floor(state.steps)
    if SEVERITY_RANK[report.risk_level] < SEVERITY_RANK[floor]:
        failures.append(
            f"risk_floor_violation: report={report.risk_level} tool_floor={floor}"
        )

    for step in state.steps:
        if not step.observation:
            continue
        try:
            obs = json.loads(step.observation)
        except json.JSONDecodeError:
            continue
        if obs.get("blocklist_match") and obs.get("risk_hint") == "High":
            if report.risk_level != "High":
                failures.append(
                    f"blocklist_high_but_report_{report.risk_level.lower()}"
                )

    label_lower = demo_label.lower()
    if "ssh" in label_lower or "brute" in label_lower:
        log_steps = [s for s in state.steps if s.action == "log_pattern_match"]
        if not log_steps:
            failures.append("ssh_demo_missing_log_pattern_match")
        else:
            matched = False
            for step in log_steps:
                if not step.observation:
                    continue
                try:
                    obs = json.loads(step.observation)
                except json.JSONDecodeError:
                    continue
                if obs.get("match_count", 0) > 0:
                    matched = True
            if not matched:
                failures.append("ssh_demo_log_pattern_zero_matches")

    if "high-risk ip" in label_lower or "blocklist" in label_lower:
        if report.risk_level != "High":
            failures.append(f"high_risk_ip_demo_report_{report.risk_level.lower()}")

    if "sql injection" in label_lower:
        if report.risk_level == "Low":
            failures.append("sqli_demo_report_low")

    return failures


def analyze_investigation(
    state: InvestigationState,
    report: InvestigationReport | None,
    *,
    demo_label: str = "",
) -> dict[str, Any]:
    """Produce machine-readable flags for common agent/tool issues."""
    tools_called: list[str] = []
    observations: list[dict[str, Any]] = []
    step_errors: list[str] = []

    for step in state.steps:
        if step.action:
            tools_called.append(step.action)
        if step.error:
            step_errors.append(step.error)
        if step.observation:
            try:
                observations.append(json.loads(step.observation))
            except json.JSONDecodeError:
                observations.append({"raw": step.observation})

    flags: list[str] = []

    if "log_pattern_match" not in tools_called and looks_like_log_line(state.event_input):
        flags.append("log_pattern_match_never_called_for_log_line")

    quality_gate_failures = check_quality_gates(state, report, demo_label=demo_label)

    if report and report.risk_level == "High":
        ti_medium = any(
            obs.get("risk_hint") == "Medium" and obs.get("source") == "local_heuristics"
            for obs in observations
        )
        log_only_medium = any(
            obs.get("highest_severity") == "Medium" for obs in observations
        ) and not any(obs.get("highest_severity") == "High" for obs in observations)
        blocklist_high = any(obs.get("blocklist_match") for obs in observations)
        if (ti_medium or log_only_medium) and not blocklist_high:
            flags.append("risk_high_but_tool_evidence_moderate")

    for err in step_errors:
        if "invalid_ip_lookup" in err or "valid IP address" in err:
            flags.append("agent_tried_ip_lookup_with_domain")
        if "private_ip" in err or "private or reserved" in err.lower():
            flags.append("agent_tried_external_lookup_on_private_ip")

    return {
        "tools_called": tools_called,
        "tool_call_count": state.tool_call_count,
        "step_count": len(state.steps),
        "step_errors": step_errors,
        "flags": flags,
        "quality_gate_failures": quality_gate_failures,
        "tool_risk_floor": compute_tool_risk_floor(state.steps),
        "observation_summary": _summarize_observations(observations),
    }


def _summarize_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for obs in observations:
        entry: dict[str, Any] = {}
        if "match_count" in obs:
            entry["type"] = "log_pattern_match"
            entry["match_count"] = obs.get("match_count")
            entry["highest_severity"] = obs.get("highest_severity")
        elif "risk_hint" in obs:
            entry["type"] = "threat_intel"
            entry["indicator"] = obs.get("indicator")
            entry["risk_hint"] = obs.get("risk_hint")
            entry["source"] = obs.get("source")
            entry["blocklist_match"] = obs.get("blocklist_match")
        elif "ip" in obs and "country" in obs:
            entry["type"] = "ip_lookup"
            entry["ip"] = obs.get("ip")
            entry["country"] = obs.get("country")
        elif "error" in obs:
            entry["type"] = "error"
            entry["error"] = obs.get("error")
        elif "target" in obs or "registrar" in obs:
            entry["type"] = "whois_lookup"
            entry["target"] = obs.get("target")
            entry["registrar"] = obs.get("registrar")
        else:
            entry["type"] = "other"
            entry["keys"] = list(obs.keys())[:8]
        summary.append(entry)
    return summary


def save_investigation_results(
    results: list[dict[str, Any]],
    *,
    label: str = "investigations",
) -> Path:
    """Write investigation JSON to tests/output/ for offline review."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = OUTPUT_DIR / f"{label}_{timestamp}.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    latest = OUTPUT_DIR / "latest.json"
    latest.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def print_investigation_summary(result: dict[str, Any], demo_label: str = "") -> None:
    """Print a compact terminal summary (replaces manual copy-paste to chat)."""
    header = demo_label or "Investigation"
    print(f"\n{'=' * 60}")
    print(f"  {header}")
    print(f"{'=' * 60}")

    if not result.get("input_allowed"):
        print(f"  BLOCKED: {result.get('input_refusal')}")
        return

    if result.get("error"):
        print(f"  ERROR: {result['error']}")
        return

    report = result.get("report") or {}
    analysis = result.get("analysis") or {}
    print(f"  Risk: {report.get('risk_level', 'N/A')}")
    print(f"  Summary: {report.get('summary', 'N/A')}")
    print(f"  Tools: {', '.join(analysis.get('tools_called', []))}")
    print(f"  Steps: {analysis.get('step_count', 0)} | Tool calls: {analysis.get('tool_call_count', 0)}")

    for item in analysis.get("observation_summary", []):
        print(f"  Observation: {item}")

    flags = analysis.get("flags", [])
    if flags:
        print(f"  FLAGS: {', '.join(flags)}")
    quality_failures = analysis.get("quality_gate_failures", [])
    if quality_failures:
        print(f"  QUALITY GATE FAILURES: {', '.join(quality_failures)}")
    floor = analysis.get("tool_risk_floor")
    if floor:
        print(f"  Tool risk floor: {floor}")
    if analysis.get("step_errors"):
        print(f"  Step errors: {analysis['step_errors']}")
