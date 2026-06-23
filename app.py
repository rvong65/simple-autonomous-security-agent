"""
Simple Autonomous Security Agent (SASA) — Streamlit investigation UI.

Entry point for the analyst-facing web app. Orchestrates session state, sidebar
configuration, investigation triggers (via agent.run_investigation), and report
rendering. All LLM and tool execution stays server-side.

Run locally:
    streamlit run app.py
"""

from __future__ import annotations

import importlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

import streamlit as st

# Ensure project root is importable when Streamlit sets cwd elsewhere.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config.settings as settings_module
from agent import InvestigationReport, InvestigationState, run_investigation
from config.settings import LLMProvider, get_settings
from utils.export_format import build_export_payload, build_summary_text
from utils.guardrails import check_input
from utils.secrets import groq_api_key_configured, together_api_key_configured

# ---------------------------------------------------------------------------
# Theme tokens — keep in sync with .streamlit/config.toml and docs/assets SVGs
# ---------------------------------------------------------------------------
THEME = {
    "navy": "#0B1426",
    "charcoal": "#141C2B",
    "card": "#1A2332",
    "card_border": "#2A3A52",
    "cyan": "#00D4FF",
    "teal": "#14B8A6",
    "text": "#E2E8F0",
    "muted": "#94A3B8",
    "risk_low": "#14B8A6",
    "risk_medium": "#F59E0B",
    "risk_high": "#EF4444",
}

RISK_COLORS = {
    "Low": THEME["risk_low"],
    "Medium": THEME["risk_medium"],
    "High": THEME["risk_high"],
}

ERROR_LABELS = {
    "rate_limit": "RATE LIMIT",
    "auth": "AUTH",
    "timeout": "TIMEOUT",
    "connection": "CONNECTION",
    "service_unavailable": "API UNAVAILABLE",
    "missing_key": "CONFIG",
    "model_not_found": "MODEL",
    "provider_error": "PROVIDER",
    "http_error": "HTTP",
    "unknown": "ERROR",
}


# Brand assets: shield + magnifying glass = security investigation agent
_ASSETS_DIR = PROJECT_ROOT / "docs" / "assets"
_BRAND_ICON_SVG = _ASSETS_DIR / "icon.svg"
_PAGE_ICON_SVG = _ASSETS_DIR / "favicon.svg"


def _svg_data_uri(svg_path: Path) -> str:
    """Inline an SVG as a data URI for use in st.markdown HTML (Streamlit-safe)."""
    svg = svg_path.read_text(encoding="utf-8").strip()
    return f"data:image/svg+xml,{quote(svg)}"


def _brand_icon_img(height_px: int = 40) -> str:
    """HTML img tag for the SASA brand icon (sidebar / header)."""
    uri = _svg_data_uri(_BRAND_ICON_SVG)
    return (
        f'<img class="sasa-brand-icon" src="{uri}" '
        f'height="{height_px}" width="{height_px}" alt="SASA logo" />'
    )


def _theme_css() -> str:
    """Return injected CSS for the cybersecurity theme and component styling."""
    t = THEME
    return f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;500&display=swap');

    .stApp,
    [data-testid="stMain"],
    [data-testid="stSidebar"],
    [data-testid="stMain"] p,
    [data-testid="stMain"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label,
    .stMarkdown,
    .stButton button {{
        font-family: 'IBM Plex Sans', 'Segoe UI', system-ui, sans-serif !important;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }}

    .stApp {{
        background: linear-gradient(160deg, {t['navy']} 0%, {t['charcoal']} 55%, #0D1B2A 100%);
        color: {t['text']};
    }}

    /* Streamlit chrome: remove contrasting top stripe and match navy header */
    [data-testid="stDecoration"] {{
        display: none;
    }}
    header[data-testid="stHeader"] {{
        background: {t['navy']};
        background-color: {t['navy']};
    }}
    [data-testid="stToolbar"] {{
        background: {t['navy']};
        background-color: {t['navy']};
    }}
    [data-testid="stAppViewContainer"] {{
        background: transparent;
    }}
    [data-testid="stMain"] {{
        background: transparent;
    }}
    [data-testid="stHeaderActionElements"] {{
        background: transparent;
    }}
    [data-testid="stStatusWidget"] {{
        background: transparent;
    }}
    header[data-testid="stHeader"] button {{
        color: {t['muted']};
    }}
    header[data-testid="stHeader"] button:hover {{
        color: {t['cyan']};
    }}

    [data-testid="stSidebar"] {{
        background: linear-gradient(180deg, {t['charcoal']} 0%, {t['navy']} 100%);
        border-right: 1px solid {t['card_border']};
        min-width: 22.5rem !important;
        width: 22.5rem !important;
    }}
    [data-testid="stSidebar"] > div:first-child {{
        width: 22.5rem !important;
        min-width: 22.5rem !important;
    }}
    [data-testid="stSidebar"] table {{
        width: 100%;
        font-size: 0.78rem;
        border-collapse: collapse;
        margin: 0.5rem 0;
    }}
    [data-testid="stSidebar"] th,
    [data-testid="stSidebar"] td {{
        border: 1px solid {t['card_border']};
        padding: 0.35rem 0.5rem;
        vertical-align: top;
    }}
    [data-testid="stSidebar"] th {{
        background: rgba(0, 212, 255, 0.08);
        color: {t['cyan']};
    }}

    .sasa-brand {{
        display: flex;
        align-items: center;
        gap: 0.2rem;
        margin-bottom: 0.1rem;
    }}
    .sasa-brand-icon {{
        flex-shrink: 0;
        display: block;
        margin: 0;
        padding: 0;
        vertical-align: middle;
        filter: drop-shadow(0 0 8px rgba(0, 212, 255, 0.2));
    }}
    .sasa-brand-text {{
        display: flex;
        flex-direction: column;
        justify-content: center;
        gap: 0;
        line-height: 1.1;
        margin-left: 0.1rem;
    }}
    .sasa-brand-title {{
        color: {t['cyan']};
        font-weight: 700;
        font-size: 1.15rem;
        letter-spacing: 0.06em;
        line-height: 1.2;
    }}
    .sasa-brand-sub {{
        color: {t['muted']};
        font-size: 0.75rem;
        line-height: 1.3;
    }}

    .sasa-config-card {{
        background: rgba(26, 35, 50, 0.85);
        border: 1px solid {t['card_border']};
        border-radius: 8px;
        padding: 0.65rem 0.85rem;
        margin: 0.5rem 0 0.75rem;
    }}
    .sasa-config-row {{
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 0.75rem;
        padding: 0.35rem 0;
        border-bottom: 1px solid rgba(42, 58, 82, 0.5);
        font-size: 0.82rem;
    }}
    .sasa-config-row:last-child {{
        border-bottom: none;
    }}
    .sasa-config-label {{
        color: {t['muted']};
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.68rem;
        letter-spacing: 0.05em;
        flex-shrink: 0;
    }}
    .sasa-config-value {{
        color: {t['text']};
        text-align: right;
        line-height: 1.35;
    }}
    .sasa-status-dot {{
        display: inline-block;
        width: 0.5rem;
        height: 0.5rem;
        border-radius: 50%;
        margin-right: 0.35rem;
        vertical-align: middle;
    }}
    .sasa-status-ok {{ background: {t['teal']}; box-shadow: 0 0 6px {t['teal']}; }}
    .sasa-status-warn {{ background: {t['risk_medium']}; }}
    .sasa-status-err {{ background: {t['risk_high']}; }}

    .sasa-error-tag {{
        display: inline-block;
        background: rgba(239, 68, 68, 0.15);
        color: {t['risk_high']};
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-radius: 4px;
        padding: 0.1rem 0.45rem;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        margin-right: 0.5rem;
    }}

    [data-testid="stSidebar"] .stMarkdown,
    [data-testid="stSidebar"] label {{
        color: {t['text']} !important;
    }}

    h1, h2, h3, .sasa-title, .sasa-brand-title {{
        color: {t['cyan']} !important;
        font-family: 'IBM Plex Sans', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.01em;
    }}
    .sasa-subtitle {{
        color: {t['muted']};
        font-size: 1.05rem;
        font-weight: 400;
        line-height: 1.55;
        margin-top: -0.5rem;
        margin-bottom: 1.5rem;
    }}

    .sasa-header-bar {{
        background: linear-gradient(90deg, {t['card']} 0%, rgba(26,35,50,0.6) 100%);
        border: 1px solid {t['card_border']};
        border-left: 4px solid {t['cyan']};
        border-radius: 10px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.25), inset 0 1px 0 rgba(0, 212, 255, 0.06);
    }}
    .sasa-header-bar h1 {{
        margin: 0 !important;
        font-size: 1.75rem !important;
    }}
    .sasa-badge {{
        display: inline-block;
        background: rgba(0, 212, 255, 0.12);
        color: {t['cyan']};
        border: 1px solid rgba(0, 212, 255, 0.35);
        border-radius: 999px;
        padding: 0.2rem 0.75rem;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin-top: 0.5rem;
    }}

    .sasa-card {{
        background: {t['card']};
        border: 1px solid {t['card_border']};
        border-radius: 10px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 1rem;
    }}

    .sasa-risk-badge {{
        display: inline-block;
        padding: 14px 28px;
        border-radius: 10px;
        font-size: 1.35rem;
        font-weight: 700;
        color: white;
        letter-spacing: 0.02em;
        box-shadow: 0 4px 20px rgba(0,0,0,0.35);
    }}
    .sasa-floor-badge {{
        display: inline-block;
        margin-left: 12px;
        padding: 8px 16px;
        border-radius: 8px;
        font-size: 0.85rem;
        font-weight: 600;
        color: {t['muted']};
        background: rgba(20, 184, 166, 0.1);
        border: 1px solid rgba(20, 184, 166, 0.3);
        vertical-align: middle;
    }}

    .sasa-error-box {{
        background: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.35);
        border-left: 4px solid {t['risk_high']};
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin: 1rem 0;
        color: {t['text']};
    }}
    .sasa-error-title {{
        color: {t['risk_high']};
        font-weight: 600;
        font-size: 1rem;
        margin-bottom: 0.35rem;
    }}

    div[data-testid="stExpander"] {{
        background: {t['card']};
        border: 1px solid {t['card_border']};
        border-radius: 8px;
    }}
    div[data-testid="stExpander"] summary {{
        color: {t['cyan']} !important;
        font-weight: 600;
    }}

    .stTextArea textarea {{
        background-color: {t['charcoal']} !important;
        color: {t['text']} !important;
        border: 1px solid {t['card_border']} !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.9rem !important;
    }}
    .stTextArea label {{
        color: {t['cyan']} !important;
        font-weight: 600 !important;
    }}

    .stButton > button[kind="primary"] {{
        background: linear-gradient(135deg, {t['cyan']} 0%, {t['teal']} 100%) !important;
        color: {t['navy']} !important;
        border: none !important;
        font-weight: 700 !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 12px rgba(0, 212, 255, 0.25);
    }}
    .stButton > button[kind="primary"]:hover {{
        box-shadow: 0 4px 20px rgba(0, 212, 255, 0.4);
    }}
    .stButton > button[kind="secondary"] {{
        background: transparent !important;
        color: {t['muted']} !important;
        border: 1px solid {t['card_border']} !important;
        border-radius: 8px !important;
    }}

    [data-testid="stMetricValue"] {{
        color: {t['cyan']} !important;
    }}

    hr {{
        border-color: {t['card_border']} !important;
        opacity: 0.5;
    }}

    .stCode, code, pre, [data-testid="stCode"], [data-testid="stCodeBlock"] {{
        font-family: 'JetBrains Mono', 'Consolas', monospace !important;
        font-size: 0.85rem !important;
    }}
</style>
"""


st.set_page_config(
    page_title="SASA — Security Agent",
    page_icon=str(_PAGE_ICON_SVG),
    layout="wide",
    initial_sidebar_state="expanded",
)


def _inject_theme() -> None:
    """Inject global CSS (fonts, colors, Streamlit chrome overrides)."""
    st.markdown(_theme_css(), unsafe_allow_html=True)


def _get_settings():
    """Reload settings so .env / Streamlit secrets changes apply without full restart."""
    importlib.reload(settings_module)
    settings_module.get_settings.cache_clear()
    return settings_module.get_settings()


def _load_demo_events() -> list[dict]:
    """Load sidebar demo scenarios from demo/example_events.json."""
    demo_path = PROJECT_ROOT / "demo" / "example_events.json"
    if not demo_path.exists():
        return []
    return json.loads(demo_path.read_text(encoding="utf-8"))


def _init_session_state() -> None:
    """Initialize Streamlit session keys for investigation lifecycle."""
    defaults = {
        "messages": [],
        "investigation": None,
        "report": None,
        "investigation_timestamps": [],
        "last_event_input": "",
        "last_error_detail": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _render_how_it_works() -> None:
    """Sidebar expander: ReAct loop and tool overview for new users."""
    with st.sidebar.expander("How It Works", expanded=False):
        st.markdown(
            """
**SASA** investigates security events using a **ReAct loop**:

1. **Thought** — reasons about the event
2. **Action** — calls a read-only tool
3. **Observation** — reviews tool output
4. Repeat until a **Final Answer** risk report is produced
            """
        )
        st.markdown(
            """
<table>
<thead><tr><th>Tool</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td><code>log_pattern_match</code></td><td>Brute-force, SQLi, scanners</td></tr>
<tr><td><code>threat_intel</code></td><td>IP/domain reputation</td></tr>
<tr><td><code>ip_lookup</code></td><td>Geolocation &amp; ASN</td></tr>
<tr><td><code>whois_lookup</code></td><td>Domain registration</td></tr>
</tbody>
</table>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
**Risk:** Low · Medium · High — tool evidence sets a **risk floor**.

**Safety:** read-only tools, input guardrails, private IP blocks, max 8 steps.

**LLM:** Groq (default) or local Ollama. Rate limits auto-retry; check status if unavailable.

> Correlate findings with internal telemetry before taking action.
            """
        )


def _status_dot(ok: bool, warn: bool = False) -> str:
    """HTML span for configuration status indicator (green / amber / red)."""
    if ok:
        css = "sasa-status-ok"
    elif warn:
        css = "sasa-status-warn"
    else:
        css = "sasa-status-err"
    return f'<span class="sasa-status-dot {css}"></span>'


def _render_config_card(settings) -> None:
    """Render non-secret configuration status (presence checks only — never key values)."""
    groq_ok = groq_api_key_configured()
    if settings.llm_provider == LLMProvider.GROQ:
        key_html = f'{_status_dot(groq_ok)}<span>{"Ready" if groq_ok else "Missing key"}</span>'
    elif settings.llm_provider == LLMProvider.TOGETHER:
        together_ok = together_api_key_configured()
        key_html = f'{_status_dot(together_ok)}<span>{"Ready" if together_ok else "Missing key"}</span>'
    else:
        key_html = f'<span>{settings.ollama_base_url}</span>'

    if settings.abuseipdb_configured():
        intel_html = f'{_status_dot(True)}<span>AbuseIPDB live</span>'
    else:
        intel_html = (
            f'{_status_dot(True)}<span>Built-in heuristics</span>'
        )

    st.sidebar.markdown(
        f'<div class="sasa-config-card">'
        f'<div class="sasa-config-row"><span class="sasa-config-label">LLM</span>'
        f'<span class="sasa-config-value">{settings.llm_provider.value} · {settings.llm_model}</span></div>'
        f'<div class="sasa-config-row"><span class="sasa-config-label">Profile</span>'
        f'<span class="sasa-config-value">{settings.deployment_profile.value}</span></div>'
        f'<div class="sasa-config-row"><span class="sasa-config-label">API key</span>'
        f'<span class="sasa-config-value">{key_html}</span></div>'
        f'<div class="sasa-config-row"><span class="sasa-config-label">Threat intel</span>'
        f'<span class="sasa-config-value">{intel_html}</span></div>'
        f"</div>",
        unsafe_allow_html=True,
    )

    critical = settings.validate_runtime(include_optional_hints=False)
    for warning in critical:
        st.sidebar.error(warning)

    if not settings.abuseipdb_configured():
        with st.sidebar.expander("Optional integrations", expanded=False):
            st.caption(
                "Threat intel uses a built-in demo blocklist and heuristics by default. "
                "Add **ABUSEIPDB_API_KEY** to `.env` or Streamlit Secrets for live IP reputation."
            )


def _render_sidebar(settings) -> str | None:
    """Sidebar: brand, how-it-works, config, demo events. Returns selected demo text."""
    st.sidebar.markdown(
        '<div class="sasa-brand">'
        f"{_brand_icon_img(42)}"
        '<div class="sasa-brand-text"><div class="sasa-brand-title">SASA</div>'
        '<div class="sasa-brand-sub">Security Investigation Agent</div></div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.sidebar.divider()

    _render_how_it_works()

    st.sidebar.markdown("### Configuration")
    _render_config_card(settings)

    st.sidebar.divider()
    st.sidebar.markdown("### Demo Events")

    demo_events = _load_demo_events()
    selected_event: str | None = None

    if demo_events:
        labels = [e["label"] for e in demo_events]
        choice = st.sidebar.selectbox("Load example", ["— select —"] + labels, label_visibility="collapsed")
        if choice != "— select —":
            for event in demo_events:
                if event["label"] == choice:
                    selected_event = event["text"]
                    break
    else:
        st.sidebar.caption("No demo events found.")

    st.sidebar.divider()
    st.sidebar.caption(
        "Read-only investigation assistant. No blocking, exploitation, or remediation."
    )

    return selected_event


def _render_llm_error(message: str, error_detail: dict | None) -> None:
    """Friendly error panel for rate limits, auth, timeout, and provider failures."""
    code = (error_detail or {}).get("code", "unknown")
    tag = ERROR_LABELS.get(code, "ERROR")
    title_map = {
        "rate_limit": "Rate limit reached",
        "auth": "Authentication failed",
        "timeout": "Request timed out",
        "connection": "Connection failed",
        "service_unavailable": "API unavailable",
        "missing_key": "API key missing",
        "model_not_found": "Model not found",
        "provider_error": "Provider error",
    }
    title = title_map.get(code, "Investigation failed")

    st.markdown(
        f'<div class="sasa-error-box">'
        f'<div class="sasa-error-title">'
        f'<span class="sasa-error-tag">{tag}</span>{title}</div>'
        f'<div>{message}</div></div>',
        unsafe_allow_html=True,
    )

    detail = (error_detail or {}).get("detail", "")
    if detail:
        with st.expander("Technical details", expanded=False):
            st.code(detail, language=None)


def _is_synthesis_step(step) -> bool:
    """Thought-only step before FINAL_ANSWER — no tool call."""
    return bool(step.thought.strip()) and not step.action and not step.error


def _render_risk_badge(risk_level: str, tool_risk_floor: str | None = None) -> None:
    """Display final risk level and optional tool-evidence floor badge."""
    color = RISK_COLORS.get(risk_level, THEME["muted"])
    floor_html = ""
    if tool_risk_floor and tool_risk_floor != "Low":
        floor_color = RISK_COLORS.get(tool_risk_floor, THEME["teal"])
        floor_html = (
            f'<span class="sasa-floor-badge" style="border-color:{floor_color}40;'
            f'color:{floor_color};">Tool evidence floor: {tool_risk_floor}</span>'
        )
    st.markdown(
        f'<div style="margin:0.5rem 0 1rem;display:flex;flex-wrap:wrap;gap:12px;align-items:center;">'
        f'<span class="sasa-risk-badge" style="background-color:{color};">'
        f"Risk: {risk_level}</span>{floor_html}</div>",
        unsafe_allow_html=True,
    )


def _render_steps(state: InvestigationState) -> None:
    """Chain-of-thought panel: one expander per ReAct step with parsed observations."""
    st.markdown("### Chain of Thought")
    if not state.steps:
        st.info("No investigation steps yet.")
        return

    for step in state.steps:
        is_auto = step.step == 0 and step.action == "log_pattern_match"
        is_synthesis = _is_synthesis_step(step)
        if is_auto:
            label = f"Step {step.step} — `{step.action}` [auto]"
        elif is_synthesis:
            label = f"Step {step.step} — Synthesis"
        else:
            prefix = "tool" if step.action else ("error" if step.error else "think")
            label = f"Step {step.step} [{prefix}]"
            if step.action:
                label += f" — `{step.action}`"
        with st.expander(label, expanded=False):
            if is_synthesis:
                st.caption(
                    "Agent reasoning before the final report — no tool call on this step."
                )
            st.markdown("**Thought**")
            st.write(step.thought)

            if step.action:
                st.markdown("**Action**")
                st.code(step.action)
                if step.action_input:
                    st.markdown("**Action Input**")
                    st.json(step.action_input)

            if step.observation:
                st.markdown("**Observation**")
                try:
                    st.json(json.loads(step.observation))
                except json.JSONDecodeError:
                    st.code(step.observation)

            if step.error:
                st.markdown("**Error**")
                try:
                    parsed_err = json.loads(step.error)
                    st.json(parsed_err)
                except json.JSONDecodeError:
                    st.error(step.error)


def _render_report(
    report: InvestigationReport,
    state: InvestigationState | None = None,
    settings=None,
) -> None:
    """Investigation report with JSON/TXT downloads, risk badge, findings, recommendations."""
    st.markdown("### Investigation Report")
    with st.container(border=True):
        if state:
            export_payload = build_export_payload(state, report, settings=settings)
            summary_text = build_summary_text(state, report)
            col_a, col_b = st.columns(2)
            with col_a:
                st.download_button(
                    "Download JSON report",
                    data=json.dumps(export_payload, indent=2, default=str),
                    file_name="sasa_investigation.json",
                    mime="application/json",
                    use_container_width=True,
                )
            with col_b:
                st.download_button(
                    "Download summary (.txt)",
                    data=summary_text,
                    file_name="sasa_summary.txt",
                    mime="text/plain",
                    use_container_width=True,
                )

        _render_risk_badge(report.risk_level, report.tool_risk_floor)

        st.markdown("**Summary**")
        st.write(report.summary)

        if report.findings:
            st.markdown("**Findings**")
            for finding in report.findings:
                st.markdown(f"- {finding}")

        if report.recommendations:
            st.markdown("**Recommended Actions**")
            for rec in report.recommendations:
                st.markdown(f"- {rec}")


def main() -> None:
    """Application entry: header, event input, investigate flow, results rendering."""
    _inject_theme()
    _init_session_state()
    settings = _get_settings()

    st.markdown(
        '<div class="sasa-header-bar">'
        '<div class="sasa-brand" style="margin-bottom:0.5rem;">'
        f"{_brand_icon_img(46)}"
        '<div class="sasa-brand-text"><div class="sasa-brand-title" style="font-size:1.5rem; line-height:1.15;">'
        "Simple Autonomous Security Agent</div>"
        '<div class="sasa-brand-sub">Transparent ReAct investigation for SOC analysts</div></div>'
        "</div>"
        '<span class="sasa-badge">Read-Only · No Remediation</span>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<p class="sasa-subtitle">Paste a security event — log line, IP, domain, or alert — '
        "and SASA will autonomously investigate it with full chain-of-thought visibility.</p>",
        unsafe_allow_html=True,
    )

    selected_demo = _render_sidebar(settings)

    default_input = selected_demo or st.session_state.get("last_event_input", "")
    event_input = st.text_area(
        "Security Event",
        value=default_input,
        height=150,
        placeholder=(
            "Example: 2024-01-15 03:22:11 sshd[1234]: Failed password for root "
            "from 185.220.101.1 port 54321 ssh2"
        ),
    )

    col1, col2 = st.columns([1, 5])
    with col1:
        investigate_clicked = st.button("Investigate", type="primary", use_container_width=True)
    with col2:
        if st.button("Clear", use_container_width=True):
            st.session_state.investigation = None
            st.session_state.report = None
            st.session_state.messages = []
            st.session_state.last_error_detail = None
            st.rerun()

    if investigate_clicked:
        allowed, refusal = check_input(event_input)
        if not allowed:
            st.markdown(
                f'<div class="sasa-error-box">'
                f'<div class="sasa-error-title">'
                f'<span class="sasa-error-tag">BLOCKED</span>Input refused</div>'
                f"<div>{refusal}</div></div>",
                unsafe_allow_html=True,
            )
        else:
            st.session_state.last_event_input = event_input
            st.session_state.investigation_timestamps.append(time.time())
            st.session_state.last_error_detail = None

            with st.spinner(
                f"Agent investigating… up to {settings.max_agent_steps} ReAct steps "
                "(tools + risk assessment)."
            ):
                state, report, error = run_investigation(
                    event_input,
                    settings=settings,
                    investigation_timestamps=st.session_state.investigation_timestamps,
                )

            st.session_state.investigation = state
            st.session_state.report = report

            if error:
                st.session_state.last_error_detail = state.error_detail
                _render_llm_error(error, state.error_detail)
            elif report:
                st.session_state.messages.append({
                    "role": "user",
                    "content": event_input,
                })
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": report.summary,
                    "risk_level": report.risk_level,
                })
                st.session_state.messages = st.session_state.messages[-6:]

    if st.session_state.last_error_detail and not st.session_state.report:
        if not investigate_clicked:
            detail = st.session_state.last_error_detail
            _render_llm_error(detail.get("message", "Investigation failed."), detail)

    if st.session_state.investigation:
        st.divider()
        step_count = len(st.session_state.investigation.steps)
        st.caption(f"**{step_count}** step(s) recorded — expand panels for full chain-of-thought.")
        _render_steps(st.session_state.investigation)

    if st.session_state.report:
        st.divider()
        _render_report(st.session_state.report, st.session_state.investigation, settings)

    if st.session_state.messages:
        with st.expander("Conversation History", expanded=False):
            for msg in st.session_state.messages:
                role = msg["role"].capitalize()
                content = msg["content"]
                if msg["role"] == "assistant" and msg.get("risk_level"):
                    risk = msg["risk_level"]
                    color = RISK_COLORS.get(risk, THEME["muted"])
                    st.markdown(
                        f'**{role}:** '
                        f'<span style="color:{color};font-weight:600;">[{risk}]</span>',
                        unsafe_allow_html=True,
                    )
                    st.write(content)
                else:
                    st.markdown(f"**{role}:** {content}")


if __name__ == "__main__":
    main()
