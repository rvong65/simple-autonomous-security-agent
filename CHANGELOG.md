# Changelog

All notable changes to **Simple Autonomous Security Agent (SASA)** are documented in this file.

## [1.1.1] - 2026-06-23

### Added

- **Privacy & data** disclosures in README (Safety section) and Streamlit sidebar expander
- Live Demo privacy note for public Groq-based Streamlit Cloud demo

---

## [1.1.0] - 2026-06-23

### Added

- **Docker** — `Dockerfile`, `docker-compose.yml` (Groq default; optional `ollama` profile), `.dockerignore`
- **Architecture documentation** — [`docs/architecture.md`](docs/architecture.md) with end-to-end diagrams, module map, deployment topologies, and safety table
- **SVG assets** — [`docs/assets/`](docs/assets/) (`icon.svg`, `favicon.svg`, `logo-light.svg`, `logo-dark.svg` for GitHub light/dark themes)
- **CHANGELOG.md** and [`version.py`](version.py) (`1.1.0`)
- **README** — collapsible Table of Contents, Version history section, restructured Architecture summary, Docker Quick Start
- **CI** — Docker build and Streamlit health smoke test job

### Changed

- App `page_icon` points to `docs/assets/icon.svg`
- Export JSON metadata includes application `version` when settings are provided

---

## [1.0.0] - 2026-06-17

First **tagged** release. The repository and Streamlit app were **public since 2026-06-17** (initial MVP commit). README received further polish on **2026-06-17** and **2026-06-18** (including Table of Contents reorganization) before the v1.1.0 packaging release.

### Added

- Custom **ReAct investigation agent** with four read-only tools: `log_pattern_match`, `threat_intel`, `ip_lookup`, `whois_lookup`
- **Step 0 log bootstrap** — automatic `log_pattern_match` for log-like events
- **Deterministic risk floor** — tool evidence caps minimum report severity
- **Input and tool guardrails** — scope refusal, whitelist, private IP protection, rate limits
- **Streamlit UI** — dark cybersecurity theme, chain-of-thought panel, config status card, JSON/TXT exports
- **Hybrid LLM** — Groq (`llama-3.1-8b-instant`) default; Ollama local; optional Together fallback via direct HTTP
- **Six demo SOC scenarios** in `demo/example_events.json`
- **64 offline unit tests** + integration quality gates (`tests/test_integration_investigate.py`)
- **GitHub Actions CI** — offline tests on every push/PR (no API keys required)
- **Streamlit Cloud deployment** — [live demo](https://simple-autonomous-security-agent.streamlit.app/)
- Server-side **API key hygiene** (`utils/secrets.py`) — keys never in UI or exports

[1.1.1]: https://github.com/rvong65/simple-autonomous-security-agent/releases/tag/v1.1.1
[1.1.0]: https://github.com/rvong65/simple-autonomous-security-agent/releases/tag/v1.1.0
[1.0.0]: https://github.com/rvong65/simple-autonomous-security-agent/releases/tag/v1.0.0
