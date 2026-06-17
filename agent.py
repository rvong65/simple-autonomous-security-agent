"""Core ReAct investigation agent for SASA."""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field

from config.settings import Settings, get_settings
from tools import TOOL_SCHEMAS, dispatch
from utils.guardrails import check_rate_limit, parse_action_input, validate_tool_call
from utils.llm import complete
from utils.llm_errors import LLMError
from utils.risk_scorer import RiskLevel, compute_tool_risk_floor, merge_report_risk

THOUGHT_RE = re.compile(r"THOUGHT:\s*(.+?)(?=\n(?:ACTION:|FINAL_ANSWER:)|\Z)", re.DOTALL)
ACTION_RE = re.compile(r"ACTION:\s*(\w+)")
ACTION_INPUT_RE = re.compile(r"ACTION_INPUT:\s*(\{.*?\})", re.DOTALL)
FINAL_ANSWER_RE = re.compile(r"FINAL_ANSWER:\s*(\{.*\})", re.DOTALL)

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


class AgentStep(BaseModel):
    step: int
    thought: str
    action: str | None = None
    action_input: dict | None = None
    observation: str | None = None
    error: str | None = None


class InvestigationState(BaseModel):
    event_input: str
    steps: list[AgentStep] = Field(default_factory=list)
    indicators: dict = Field(default_factory=dict)
    tool_call_count: int = 0
    error_detail: dict | None = None


class InvestigationReport(BaseModel):
    risk_level: RiskLevel
    summary: str
    findings: list[str]
    recommendations: list[str]
    raw_steps: list[AgentStep] = Field(default_factory=list)
    tool_risk_floor: RiskLevel = "Low"


def _build_system_prompt() -> str:
    schemas_text = "\n".join(
        f"- {name}: {info['description']}\n  Parameters: {info['parameters']}"
        for name, info in TOOL_SCHEMAS.items()
    )
    return f"""You are SASA, a Simple Autonomous Security Agent for SOC analysts.
Your job is to investigate suspicious security events using available tools and produce a clear risk assessment.

AVAILABLE TOOLS:
{schemas_text}

INVESTIGATION STRATEGY:
1. If the input looks like a log line, ALWAYS start with log_pattern_match on the full text.
2. Extract IPs and domains from the event; use threat_intel on suspicious external IPs only.
3. Use ip_lookup for public IPs and whois_lookup for domains only when extra context is needed.
4. Synthesize findings into a FINAL_ANSWER when you have enough context (typically 3-5 tool calls).

INTERPRETATION RULES:
- Base risk primarily on log_pattern_match and threat_intel results.
- Demo blocklist hits (blocklist_match: true) indicate suspicious sources — NEVER downgrade to Low.
- WHOIS status codes (e.g. clientTransferProhibited) are normal registrar locks, NOT evidence of malice.
- Internal/private IPs in logs are normal; guardrail blocks mean "no external TI" not "malicious host".
- Clearly distinguish demo blocklist (source: local_heuristics) from live AbuseIPDB scores.

RESPONSE FORMAT — respond with EXACTLY ONE of these per turn:

Option A (use a tool):
THOUGHT: <your reasoning about what to investigate next>
ACTION: <tool_name>
ACTION_INPUT: {{"param": "value"}}

Option B (finish investigation):
THOUGHT: <your final reasoning synthesizing all observations>
FINAL_ANSWER: {{"risk_level": "Low|Medium|High", "summary": "...", "findings": ["..."], "recommendations": ["..."]}}

RULES:
- risk_level must be exactly "Low", "Medium", or "High".
- findings and recommendations must be arrays of strings.
- Only use tools from the AVAILABLE TOOLS list.
- Never suggest destructive actions (blocking, deleting, attacking).
- Be concise but thorough in THOUGHT sections.
"""


def _extract_indicators(event: str) -> dict:
    ips = list(set(IP_PATTERN.findall(event)))
    domains = list(set(re.findall(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        event,
    )))
    return {"ips": ips, "domains": domains}


def looks_like_log_line(text: str) -> bool:
    """Return True if the event text resembles a log line."""
    if re.search(r"\d{4}-\d{2}-\d{2}", text):
        return True
    if re.search(r"\b(GET|POST|PUT|DELETE|SSH|HTTP|sshd)\b", text, re.IGNORECASE):
        return True
    return bool(IP_PATTERN.search(text))


def _parse_llm_response(text: str) -> dict:
    """Parse THOUGHT + ACTION or THOUGHT + FINAL_ANSWER from LLM output."""
    thought_match = THOUGHT_RE.search(text)
    thought = thought_match.group(1).strip() if thought_match else text.strip()

    final_match = FINAL_ANSWER_RE.search(text)
    if final_match:
        try:
            report_data = json.loads(final_match.group(1))
            return {"type": "final", "thought": thought, "report": report_data}
        except json.JSONDecodeError:
            return {"type": "parse_error", "thought": thought, "raw": text}

    action_match = ACTION_RE.search(text)
    if action_match:
        action = action_match.group(1).strip()
        input_match = ACTION_INPUT_RE.search(text)
        action_input: dict = {}
        if input_match:
            ok, parsed = parse_action_input(input_match.group(1))
            if ok:
                action_input = parsed
            else:
                return {"type": "parse_error", "thought": thought, "error": parsed}
        return {
            "type": "action",
            "thought": thought,
            "action": action,
            "action_input": action_input,
        }

    return {"type": "parse_error", "thought": thought, "raw": text}


def _normalize_risk_level(value: str) -> RiskLevel:
    normalized = value.strip().capitalize()
    if normalized in ("Low", "Medium", "High"):
        return normalized  # type: ignore[return-value]
    mapping = {"Med": "Medium", "Critical": "High", "Info": "Low"}
    return mapping.get(normalized, "Medium")  # type: ignore[return-value]


def _apply_risk_floor(report: InvestigationReport, steps: list[AgentStep]) -> InvestigationReport:
    floor = compute_tool_risk_floor(steps)
    report.tool_risk_floor = floor
    report.risk_level = merge_report_risk(floor, report.risk_level)
    return report


def _build_report_from_data(
    data: dict,
    steps: list[AgentStep],
) -> InvestigationReport:
    report = InvestigationReport(
        risk_level=_normalize_risk_level(str(data.get("risk_level", "Medium"))),
        summary=str(data.get("summary", "Investigation completed.")),
        findings=[str(f) for f in data.get("findings", [])],
        recommendations=[str(r) for r in data.get("recommendations", [])],
        raw_steps=steps,
    )
    return _apply_risk_floor(report, steps)


def _collect_findings_from_steps(steps: list[AgentStep]) -> list[str]:
    findings: list[str] = []
    for step in steps:
        if not step.observation:
            continue
        try:
            obs = json.loads(step.observation)
        except json.JSONDecodeError:
            continue

        if step.action == "log_pattern_match" and obs.get("match_count", 0) > 0:
            findings.append(
                f"Log patterns detected: {obs.get('match_count')} matches, "
                f"highest severity {obs.get('highest_severity')}"
            )
        elif step.action == "threat_intel":
            hint = obs.get("risk_hint", "unknown")
            source = obs.get("source", "unknown")
            findings.append(
                f"Threat intel for {obs.get('indicator')}: risk_hint={hint} (source={source})"
            )
        elif step.action == "ip_lookup" and "error" not in obs:
            findings.append(
                f"IP {obs.get('ip')}: {obs.get('country')}, org={obs.get('org')}"
            )
    return findings


def _synthesize_fallback_report(state: InvestigationState) -> InvestigationReport:
    """Build a minimal report when the agent loop ends without FINAL_ANSWER."""
    findings = _collect_findings_from_steps(state.steps)
    if not findings:
        findings.append("No significant threats identified from available tool results.")

    floor = compute_tool_risk_floor(state.steps)
    report = InvestigationReport(
        risk_level=floor,
        tool_risk_floor=floor,
        summary="Investigation completed with synthesized assessment (agent did not emit FINAL_ANSWER).",
        findings=findings,
        recommendations=[
            "Review raw tool observations in the chain-of-thought panel.",
            "Correlate with internal logs and authentication records.",
            "Escalate if risk level is Medium or High.",
        ],
        raw_steps=state.steps,
    )
    return report


def _guardrail_observation(action: str, action_input: dict, error: str) -> str:
    """Structured guardrail feedback (not a successful tool result)."""
    payload: dict = {"error": error, "guardrail": True}
    err_lower = error.lower()
    if action == "threat_intel" and "private" in err_lower:
        payload.update({
            "guardrail_code": "private_ip_threat_intel",
            "indicator": action_input.get("indicator"),
            "internal_ip": True,
            "note": "Internal IP — rely on log_pattern_match, not external threat intel.",
        })
    elif action == "ip_lookup" and "private" in err_lower:
        payload.update({
            "guardrail_code": "private_ip_lookup",
            "ip": action_input.get("ip"),
            "internal_ip": True,
        })
    elif action == "ip_lookup" and "valid ip" in err_lower:
        payload.update({
            "guardrail_code": "invalid_ip_lookup",
            "ip": action_input.get("ip"),
            "note": "ip_lookup requires a public IP address, not a domain name.",
        })
    return json.dumps(payload)


def _step_feedback_message(step: AgentStep) -> str:
    if step.observation:
        return f"OBSERVATION:\n{step.observation}"
    if step.error:
        return f"OBSERVATION ERROR: {step.error}"
    return ""


def _build_messages(state: InvestigationState, system_prompt: str) -> list[dict]:
    messages: list[dict] = [{"role": "system", "content": system_prompt}]

    user_content = (
        f"Investigate this security event:\n\n{state.event_input}\n\n"
        f"Extracted indicators: {json.dumps(state.indicators)}"
    )
    messages.append({"role": "user", "content": user_content})

    for step in state.steps:
        assistant_parts = [f"THOUGHT: {step.thought}"]
        if step.action:
            assistant_parts.append(f"ACTION: {step.action}")
            if step.action_input:
                assistant_parts.append(f"ACTION_INPUT: {json.dumps(step.action_input)}")
        messages.append({"role": "assistant", "content": "\n".join(assistant_parts)})

        feedback = _step_feedback_message(step)
        if feedback:
            messages.append({"role": "user", "content": feedback})

    return messages


def _bootstrap_log_pattern_match(state: InvestigationState, settings: Settings) -> None:
    """Auto-run log_pattern_match before the ReAct loop for log-like events."""
    if not looks_like_log_line(state.event_input):
        return
    if any(s.action == "log_pattern_match" for s in state.steps):
        return

    result = dispatch(
        "log_pattern_match",
        {"log_line": state.event_input},
        abuseipdb_api_key=settings.abuseipdb_key_value(),
        tool_timeout=settings.tool_timeout_seconds,
    )
    state.steps.append(AgentStep(
        step=0,
        thought="Auto: baseline log pattern scan on full event text.",
        action="log_pattern_match",
        action_input={"log_line": state.event_input},
        observation=json.dumps(result, default=str),
    ))
    state.tool_call_count += 1


def _execute_action_step(
    state: InvestigationState,
    settings: Settings,
    timestamps: list[float],
    step_num: int,
    thought: str,
    action: str,
    action_input: dict,
) -> Literal["continue", "break"]:
    """Validate, dispatch tool, append step. Returns whether to break the loop."""
    allowed_tools, tool_err = check_rate_limit(
        timestamps,
        tool_call_count=state.tool_call_count,
        max_tool_calls=settings.max_tool_calls_per_investigation,
    )
    if not allowed_tools:
        state.steps.append(AgentStep(
            step=step_num,
            thought=thought,
            action=action,
            action_input=action_input,
            error=tool_err,
        ))
        return "break"

    valid, validated = validate_tool_call(action, action_input)
    if not valid:
        state.steps.append(AgentStep(
            step=step_num,
            thought=thought,
            action=action,
            action_input=action_input,
            error=_guardrail_observation(action, action_input, str(validated)),
        ))
        return "continue"

    result = dispatch(
        action,
        validated,  # type: ignore[arg-type]
        abuseipdb_api_key=settings.abuseipdb_key_value(),
        tool_timeout=settings.tool_timeout_seconds,
    )
    state.steps.append(AgentStep(
        step=step_num,
        thought=thought,
        action=action,
        action_input=validated,  # type: ignore[arg-type]
        observation=json.dumps(result, default=str),
    ))
    state.tool_call_count += 1
    return "continue"


def run_investigation(
    event_input: str,
    settings: Settings | None = None,
    investigation_timestamps: list[float] | None = None,
) -> tuple[InvestigationState, InvestigationReport | None, str | None]:
    """
    Run the full ReAct investigation loop.

    Returns:
        (state, report, error_message) — error_message is set on guardrail/LLM failures.
    """
    settings = settings or get_settings()
    timestamps = investigation_timestamps or []

    allowed, rate_err = check_rate_limit(
        timestamps,
        tool_call_count=0,
        max_tool_calls=settings.max_tool_calls_per_investigation,
    )
    if not allowed:
        return InvestigationState(event_input=event_input), None, rate_err

    state = InvestigationState(
        event_input=event_input,
        indicators=_extract_indicators(event_input),
    )
    _bootstrap_log_pattern_match(state, settings)
    system_prompt = _build_system_prompt()

    for step_num in range(1, settings.max_agent_steps + 1):
        messages = _build_messages(state, system_prompt)

        try:
            llm_text = complete(messages, settings)
        except LLMError as exc:
            state.error_detail = exc.to_dict()
            return state, None, exc.user_message
        except Exception as exc:
            state.error_detail = {
                "code": "unknown",
                "message": str(exc),
                "detail": repr(exc),
            }
            return state, None, f"LLM error: {exc}"

        parsed = _parse_llm_response(llm_text)

        if parsed["type"] == "final":
            report = _build_report_from_data(parsed["report"], state.steps)
            state.steps.append(AgentStep(step=step_num, thought=parsed["thought"]))
            report.raw_steps = state.steps
            return state, report, None

        if parsed["type"] == "parse_error":
            state.steps.append(AgentStep(
                step=step_num,
                thought=parsed.get("thought", ""),
                error=parsed.get("error") or "Failed to parse LLM response format",
            ))
            if step_num < settings.max_agent_steps:
                messages = _build_messages(state, system_prompt)
                messages.append({
                    "role": "user",
                    "content": (
                        "Your response was not in the required format. "
                        "Respond with THOUGHT + ACTION + ACTION_INPUT, or THOUGHT + FINAL_ANSWER."
                    ),
                })
                try:
                    llm_text = complete(messages, settings)
                    parsed = _parse_llm_response(llm_text)
                    if parsed["type"] == "final":
                        report = _build_report_from_data(parsed["report"], state.steps)
                        state.steps.append(AgentStep(step=step_num, thought=parsed["thought"]))
                        report.raw_steps = state.steps
                        return state, report, None
                    if parsed["type"] == "action":
                        outcome = _execute_action_step(
                            state,
                            settings,
                            timestamps,
                            step_num,
                            parsed["thought"],
                            parsed["action"],
                            parsed.get("action_input", {}),
                        )
                        if outcome == "break":
                            break
                        continue
                except LLMError as exc:
                    state.error_detail = exc.to_dict()
                    return state, None, exc.user_message
                except Exception:
                    pass
            break

        outcome = _execute_action_step(
            state,
            settings,
            timestamps,
            step_num,
            parsed["thought"],
            parsed.get("action", ""),
            parsed.get("action_input", {}),
        )
        if outcome == "break":
            break

    report = _synthesize_fallback_report(state)
    return state, report, None
