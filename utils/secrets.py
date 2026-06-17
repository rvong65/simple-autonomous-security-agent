"""Presence checks for API keys — never log or expose secret values."""

from __future__ import annotations

import os


def groq_api_key_configured() -> bool:
    """Return True if GROQ_API_KEY is present in the server environment."""
    return bool(os.environ.get("GROQ_API_KEY"))


def together_api_key_configured() -> bool:
    """Return True if TOGETHER_API_KEY is present in the server environment."""
    return bool(os.environ.get("TOGETHER_API_KEY"))
