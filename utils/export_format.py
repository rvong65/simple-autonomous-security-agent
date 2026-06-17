"""Investigation report export formatting for JSON and plain-text downloads."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from agent import AgentStep, InvestigationReport, InvestigationState
from config.settings import Settings


EXPORT_SCHEMA_VERSION = "1.0"


def _normalize_step(step: AgentStep) -> dict[str, Any]:
    """Serialize a step with parsed observation JSON when possible."""
    data = step.model_dump()
    observation = data.get("observation")
    if isinstance(observation, str) and observation.strip():
        try:
            data["observation"] = json.loads(observation)
        except json.JSONDecodeError:
            pass
    return data


def build_export_payload(
    state: InvestigationState,
    report: InvestigationReport,
    *,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Structured JSON export for analyst records (single steps list, parsed observations)."""
    steps = [_normalize_step(s) for s in state.steps]
    payload: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "event_input": state.event_input,
        "investigation": {
            "risk_level": report.risk_level,
            "tool_risk_floor": report.tool_risk_floor,
            "summary": report.summary,
            "findings": report.findings,
            "recommendations": report.recommendations,
        },
        "steps": steps,
    }
    if settings is not None:
        payload["metadata"] = {
            "llm_provider": settings.llm_provider.value,
            "llm_model": settings.llm_model,
            "deployment_profile": settings.deployment_profile.value,
        }
    return payload


def build_summary_text(
    state: InvestigationState,
    report: InvestigationReport,
) -> str:
    """Plain-text export suitable for tickets, email, or SIEM notes."""
    exported = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "SASA — Investigation Summary",
        f"Exported: {exported}",
        "=" * 40,
        "",
        "Event:",
        state.event_input,
        "",
        f"Risk: {report.risk_level}",
        f"Tool evidence floor: {report.tool_risk_floor}",
        "",
        "Summary:",
        report.summary,
    ]
    if report.findings:
        lines.extend(["", "Findings:"])
        lines.extend(f"  - {finding}" for finding in report.findings)
    if report.recommendations:
        lines.extend(["", "Recommended actions:"])
        lines.extend(f"  - {rec}" for rec in report.recommendations)
    lines.extend([
        "",
        "-" * 40,
        "Read-only investigation — correlate with internal telemetry before action.",
    ])
    return "\n".join(lines)
