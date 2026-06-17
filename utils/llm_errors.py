"""User-friendly LLM error types for SASA (rate limits, timeouts, auth)."""

from __future__ import annotations

import json
from typing import Any

import requests


class LLMError(Exception):
    """Structured LLM failure with a safe user message and optional technical detail."""

    def __init__(
        self,
        code: str,
        user_message: str,
        technical_detail: str = "",
    ) -> None:
        self.code = code
        self.user_message = user_message
        self.technical_detail = technical_detail
        super().__init__(user_message)

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.user_message,
            "detail": self.technical_detail,
        }


def _extract_api_error_message(response: requests.Response) -> str:
    try:
        body: dict[str, Any] = response.json()
        err = body.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str):
            return err
        return json.dumps(body)[:400]
    except (json.JSONDecodeError, ValueError):
        return (response.text or "")[:400]


def http_error_from_response(response: requests.Response, provider: str) -> LLMError:
    """Map an HTTP error response to a user-facing LLMError."""
    status = response.status_code
    api_msg = _extract_api_error_message(response)
    detail = f"HTTP {status} ({provider}): {api_msg}"

    if status == 429:
        return LLMError(
            code="rate_limit",
            user_message=(
                "The LLM provider rate-limited this request (HTTP 429). "
                "Wait a minute and try again, or switch to a local Ollama model."
            ),
            technical_detail=detail,
        )

    if status in (401, 403):
        return LLMError(
            code="auth",
            user_message=(
                "LLM authentication failed. Check that your API key is set correctly "
                "in `.env` or Streamlit Secrets."
            ),
            technical_detail=detail,
        )

    if status == 404:
        return LLMError(
            code="model_not_found",
            user_message=(
                f"The configured model was not found on {provider}. "
                "Verify LLM_MODEL and that the model is available."
            ),
            technical_detail=detail,
        )

    if status in (502, 503, 504):
        return LLMError(
            code="service_unavailable",
            user_message=(
                f"The {provider} API is temporarily unavailable (HTTP {status}). "
                "The service may be down or undergoing maintenance — try again in a few minutes."
            ),
            technical_detail=detail,
        )

    if status >= 500:
        return LLMError(
            code="provider_error",
            user_message=(
                f"The {provider} LLM service returned a server error. "
                "Try again in a few moments."
            ),
            technical_detail=detail,
        )

    return LLMError(
        code="http_error",
        user_message=f"The LLM request failed (HTTP {status}).",
        technical_detail=detail,
    )


def connection_error_from_exception(exc: Exception, provider: str, base_url: str = "") -> LLMError:
    """Map connection/timeout failures to a user-facing LLMError."""
    exc_name = type(exc).__name__
    detail = f"{exc_name}: {exc}"

    if isinstance(exc, requests.Timeout):
        return LLMError(
            code="timeout",
            user_message=(
                "The LLM request timed out. The provider may be slow or unreachable — "
                "try again or increase LLM_TIMEOUT_SECONDS."
            ),
            technical_detail=detail,
        )

    if provider == "ollama":
        return LLMError(
            code="connection",
            user_message=(
                f"Cannot reach Ollama at {base_url or 'localhost'}. "
                "Ensure Ollama is running and the model is pulled."
            ),
            technical_detail=detail,
        )

    if provider == "groq":
        return LLMError(
            code="service_unavailable",
            user_message=(
                "Cannot reach the Groq API — the service may be down or your network blocked the request. "
                "Check status.groq.com and try again shortly."
            ),
            technical_detail=detail,
        )

    return LLMError(
        code="connection",
        user_message=(
            f"Cannot reach the {provider} LLM API. "
            "Verify your network connection and that the provider is operational."
        ),
        technical_detail=detail,
    )
