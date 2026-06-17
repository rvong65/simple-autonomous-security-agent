"""Direct HTTP chat completions for Ollama, Groq, and Together (no LiteLLM)."""

from __future__ import annotations

import logging
import os
import time

import requests

from config.settings import LLMProvider, Settings
from utils.llm_errors import (
    LLMError,
    connection_error_from_exception,
    http_error_from_response,
)

logger = logging.getLogger(__name__)

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
# Together: optional cloud fallback when Groq is rate-limited or unavailable (LLM_PROVIDER=together)
TOGETHER_API_URL = "https://api.together.xyz/v1/chat/completions"

# Retry Groq/Together on HTTP 429 (batch runs and burst UI clicks)
_LLM_RETRY_BACKOFF_SECONDS = (15, 30)
_LLM_MAX_RETRIES = 2


from utils.secrets import groq_api_key_configured, together_api_key_configured


def _groq_auth_header() -> dict[str, str]:
    """Build Groq Authorization header from environment (isolated; never logged)."""
    return {
        "Authorization": f"Bearer {os.environ['GROQ_API_KEY']}",
        "Content-Type": "application/json",
    }


def _together_auth_header() -> dict[str, str]:
    """Build Together Authorization header from environment (isolated; never logged)."""
    return {
        "Authorization": f"Bearer {os.environ['TOGETHER_API_KEY']}",
        "Content-Type": "application/json",
    }


def _post_llm(
    url: str,
    *,
    provider: str,
    settings: Settings,
    headers: dict[str, str] | None = None,
    json_payload: dict,
    retry_on_429: bool = False,
) -> requests.Response:
    try:
        for attempt in range(_LLM_MAX_RETRIES + 1):
            response = requests.post(
                url,
                headers=headers,
                json=json_payload,
                timeout=settings.llm_timeout_seconds,
            )
            if (
                retry_on_429
                and response.status_code == 429
                and attempt < _LLM_MAX_RETRIES
            ):
                wait = _LLM_RETRY_BACKOFF_SECONDS[
                    min(attempt, len(_LLM_RETRY_BACKOFF_SECONDS) - 1)
                ]
                logger.warning(
                    "LLM rate limited (429) on %s, retrying in %ss",
                    provider,
                    wait,
                )
                time.sleep(wait)
                continue
            return response
    except requests.RequestException as exc:
        base_url = settings.ollama_base_url if provider == "ollama" else url
        raise connection_error_from_exception(exc, provider, base_url) from exc
    raise RuntimeError("unreachable")


def _complete_ollama(messages: list[dict], settings: Settings) -> str:
    url = f"{settings.ollama_base_url.rstrip('/')}/api/chat"
    payload = {
        "model": settings.llm_model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.1},
    }
    response = _post_llm(url, provider="ollama", settings=settings, json_payload=payload)
    if not response.ok:
        raise http_error_from_response(response, "ollama")
    data = response.json()
    return data.get("message", {}).get("content", "") or ""


def _complete_openai_compatible(
    messages: list[dict],
    settings: Settings,
    *,
    api_url: str,
    headers: dict[str, str],
    provider: str,
) -> str:
    payload = {
        "model": settings.llm_model,
        "messages": messages,
        "temperature": 0.1,
    }
    response = _post_llm(
        api_url,
        provider=provider,
        settings=settings,
        headers=headers,
        json_payload=payload,
        retry_on_429=True,
    )
    if not response.ok:
        raise http_error_from_response(response, provider)
    data = response.json()
    return data["choices"][0]["message"]["content"] or ""


def complete(messages: list[dict], settings: Settings) -> str:
    """
    Send a chat completion request to the configured LLM provider.

    Groq requires LLM_PROVIDER=groq and GROQ_API_KEY in the environment.
    Raises LLMError on rate limits, auth failures, timeouts, and connection errors.
    """
    logger.info(
        "LLM request: provider=%s model=%s messages=%d",
        settings.llm_provider.value,
        settings.llm_model,
        len(messages),
    )

    if settings.llm_provider == LLMProvider.OLLAMA:
        return _complete_ollama(messages, settings)

    if settings.llm_provider == LLMProvider.GROQ:
        if not groq_api_key_configured():
            raise LLMError(
                code="missing_key",
                user_message=(
                    "GROQ_API_KEY is required when LLM_PROVIDER=groq. "
                    "Set it in `.env` or Streamlit Secrets."
                ),
                technical_detail="GROQ_API_KEY not present in environment.",
            )
        return _complete_openai_compatible(
            messages,
            settings,
            api_url=GROQ_API_URL,
            headers=_groq_auth_header(),
            provider="groq",
        )

    if settings.llm_provider == LLMProvider.TOGETHER:
        if not together_api_key_configured():
            raise LLMError(
                code="missing_key",
                user_message=(
                    "TOGETHER_API_KEY is required when LLM_PROVIDER=together. "
                    "Set it in `.env` or Streamlit Secrets."
                ),
                technical_detail="TOGETHER_API_KEY not present in environment.",
            )
        return _complete_openai_compatible(
            messages,
            settings,
            api_url=TOGETHER_API_URL,
            headers=_together_auth_header(),
            provider="together",
        )

    raise LLMError(
        code="unsupported_provider",
        user_message=f"Unsupported LLM provider: {settings.llm_provider.value}",
        technical_detail=f"provider={settings.llm_provider}",
    )


# Re-export for backward compatibility (presence checks only).
__all__ = ["complete", "groq_api_key_configured", "together_api_key_configured"]
