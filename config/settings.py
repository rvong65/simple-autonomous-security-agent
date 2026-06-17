"""Application settings loaded from environment variables and Streamlit secrets."""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class DeploymentProfile(str, Enum):
    LOCAL = "local"
    CLOUD = "cloud"


class LLMProvider(str, Enum):
    OLLAMA = "ollama"
    GROQ = "groq"
    TOGETHER = "together"  # Optional cloud fallback if Groq is unavailable


class Settings(BaseSettings):
    """Central configuration for the investigation agent."""

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    deployment_profile: DeploymentProfile = DeploymentProfile.CLOUD

    llm_provider: LLMProvider = LLMProvider.GROQ
    llm_model: str = "llama-3.1-8b-instant"
    # GROQ/TOGETHER keys: os.environ only (see utils/secrets.py). Never on this model.
    abuseipdb_api_key: SecretStr = SecretStr("")
    ollama_base_url: str = "http://localhost:11434"

    max_agent_steps: int = Field(default=8, ge=1, le=12)
    max_tool_calls_per_investigation: int = Field(default=10, ge=1, le=20)
    tool_timeout_seconds: int = Field(default=5, ge=1, le=30)
    llm_timeout_seconds: int = Field(default=30, ge=5, le=120)

    @model_validator(mode="after")
    def apply_cloud_defaults(self) -> Settings:
        """Apply sensible cloud defaults when DEPLOYMENT_PROFILE=cloud."""
        if self.deployment_profile != DeploymentProfile.CLOUD:
            return self

        updates: dict[str, object] = {}
        if self.llm_provider == LLMProvider.OLLAMA:
            updates["llm_provider"] = LLMProvider.GROQ
            updates["llm_model"] = "llama-3.1-8b-instant"
        if updates:
            return self.model_copy(update=updates)
        return self

    def is_cloud(self) -> bool:
        return self.deployment_profile == DeploymentProfile.CLOUD

    def abuseipdb_configured(self) -> bool:
        """Presence check only — safe for UI."""
        return bool(self.abuseipdb_api_key.get_secret_value())

    def abuseipdb_key_value(self) -> str:
        """Server-side tool auth only. Never render in HTML or exports."""
        return self.abuseipdb_api_key.get_secret_value()

    def validate_runtime(self, *, include_optional_hints: bool = False) -> list[str]:
        """Return configuration warnings. Critical issues only unless optional hints requested."""
        warnings: list[str] = []

        if self.is_cloud() and self.llm_provider == LLMProvider.OLLAMA:
            warnings.append("Cloud profile with Ollama LLM — switch LLM_PROVIDER to groq.")

        if self.llm_provider == LLMProvider.GROQ and not _groq_key_configured():
            warnings.append("GROQ_API_KEY is missing for Groq LLM.")

        if self.llm_provider == LLMProvider.TOGETHER and not _together_key_configured():
            warnings.append("TOGETHER_API_KEY is missing for Together LLM.")

        if include_optional_hints and not self.abuseipdb_configured():
            warnings.append(
                "Optional: set ABUSEIPDB_API_KEY for live IP reputation (built-in heuristics are active)."
            )

        return warnings


def _together_key_configured() -> bool:
    from utils.secrets import together_api_key_configured

    return together_api_key_configured()


def _groq_key_configured() -> bool:
    from utils.secrets import groq_api_key_configured

    return groq_api_key_configured()


def _flatten_secrets(obj: object, prefix: str = "") -> dict[str, str]:
    """Flatten nested Streamlit secrets TOML into ENV-style keys."""
    flat: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}_{key}" if prefix else str(key)
            flat.update(_flatten_secrets(value, full_key))
    elif isinstance(obj, str):
        if prefix:
            flat[prefix.upper()] = obj
    return flat


def load_streamlit_secrets_into_env() -> None:
    """Overlay Streamlit secrets into os.environ when running on Streamlit Cloud."""
    try:
        import os

        import streamlit as st

        if hasattr(st, "secrets") and st.secrets:
            for key, value in _flatten_secrets(dict(st.secrets)).items():
                os.environ.setdefault(key, value)
    except Exception:
        pass


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    load_streamlit_secrets_into_env()
    # Load .env into os.environ (server-side only) without exposing keys in the UI.
    try:
        from dotenv import load_dotenv

        load_dotenv(PROJECT_ROOT / ".env", override=False)
    except Exception:
        pass
    return Settings()
