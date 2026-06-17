"""Deterministic risk scoring from tool observations (independent of LLM)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from agent import AgentStep

RiskLevel = Literal["Low", "Medium", "High"]

SEVERITY_RANK: dict[str, int] = {"Low": 1, "Medium": 2, "High": 3}


def _rank(level: str | None) -> int:
    if level is None:
        return 0
    return SEVERITY_RANK.get(level, 0)


def max_risk_level(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    """Return the higher of two risk levels."""
    return a if _rank(a) >= _rank(b) else b


def normalize_risk_hint(hint: str | None) -> RiskLevel | None:
    if not hint or hint.lower() == "unknown":
        return None
    normalized = hint.strip().capitalize()
    if normalized in SEVERITY_RANK:
        return normalized  # type: ignore[return-value]
    return None


def observation_risk(obs: dict, action: str | None) -> RiskLevel | None:
    """Derive risk contribution from a single tool observation."""
    if action == "log_pattern_match":
        sev = obs.get("highest_severity")
        if obs.get("match_count", 0) > 0 and sev in SEVERITY_RANK:
            return sev  # type: ignore[return-value]
        return None

    if action == "threat_intel":
        if obs.get("blocklist_match"):
            hint = normalize_risk_hint(obs.get("risk_hint"))
            if hint:
                return hint
            return "Medium"
        return normalize_risk_hint(obs.get("risk_hint"))

    return None


def compute_tool_risk_floor(steps: list[AgentStep]) -> RiskLevel:
    """
    Compute the minimum risk level justified by tool observations.

    Walks all steps with JSON observations and returns the highest severity found.
    """
    floor: RiskLevel = "Low"

    for step in steps:
        if not step.observation:
            continue
        try:
            obs = json.loads(step.observation)
        except json.JSONDecodeError:
            continue

        level = observation_risk(obs, step.action)
        if level:
            floor = max_risk_level(floor, level)

    return floor


def merge_report_risk(tool_floor: RiskLevel, llm_risk: RiskLevel) -> RiskLevel:
    """Final risk is the higher of tool evidence and LLM assessment."""
    return max_risk_level(tool_floor, llm_risk)
