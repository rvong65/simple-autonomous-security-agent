"""Tests for LLM error normalization."""

from __future__ import annotations

import unittest
from unittest.mock import Mock

from utils.llm_errors import LLMError, connection_error_from_exception, http_error_from_response
import requests


class TestLLMError(unittest.TestCase):
    def test_to_dict(self) -> None:
        err = LLMError("rate_limit", "Slow down.", "HTTP 429")
        self.assertEqual(
            err.to_dict(),
            {"code": "rate_limit", "message": "Slow down.", "detail": "HTTP 429"},
        )

    def test_http_429(self) -> None:
        response = Mock()
        response.ok = False
        response.status_code = 429
        response.text = '{"error":{"message":"Rate limit reached"}}'
        response.json.return_value = {"error": {"message": "Rate limit reached"}}

        err = http_error_from_response(response, "groq")
        self.assertEqual(err.code, "rate_limit")
        self.assertIn("429", err.user_message)
        self.assertIn("Rate limit", err.technical_detail)

    def test_http_401(self) -> None:
        response = Mock()
        response.ok = False
        response.status_code = 401
        response.text = "Unauthorized"
        response.json.side_effect = ValueError()

        err = http_error_from_response(response, "groq")
        self.assertEqual(err.code, "auth")

    def test_connection_timeout(self) -> None:
        err = connection_error_from_exception(requests.Timeout("timed out"), "groq")
        self.assertEqual(err.code, "timeout")

    def test_http_503(self) -> None:
        response = Mock()
        response.ok = False
        response.status_code = 503
        response.text = "Service Unavailable"
        response.json.side_effect = ValueError()

        err = http_error_from_response(response, "groq")
        self.assertEqual(err.code, "service_unavailable")
        self.assertIn("unavailable", err.user_message.lower())

    def test_groq_connection_unavailable(self) -> None:
        err = connection_error_from_exception(
            requests.ConnectionError("Connection refused"),
            "groq",
        )
        self.assertEqual(err.code, "service_unavailable")
        self.assertIn("Groq", err.user_message)

    def test_connection_ollama(self) -> None:
        err = connection_error_from_exception(
            requests.ConnectionError("refused"),
            "ollama",
            "http://localhost:11434",
        )
        self.assertEqual(err.code, "connection")
        self.assertIn("Ollama", err.user_message)


if __name__ == "__main__":
    unittest.main()
