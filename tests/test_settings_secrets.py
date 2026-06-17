"""Settings secret-field handling tests."""

from __future__ import annotations

import unittest

from pydantic import SecretStr

from config.settings import Settings


class TestSettingsSecrets(unittest.TestCase):
    def test_abuseipdb_not_in_model_dump(self) -> None:
        settings = Settings(abuseipdb_api_key=SecretStr("test-secret-value"))
        dumped = str(settings.model_dump())
        self.assertNotIn("test-secret-value", dumped)

    def test_abuseipdb_configured_presence_only(self) -> None:
        empty = Settings(abuseipdb_api_key=SecretStr(""))
        self.assertFalse(empty.abuseipdb_configured())
        set_key = Settings(abuseipdb_api_key=SecretStr("key"))
        self.assertTrue(set_key.abuseipdb_configured())


if __name__ == "__main__":
    unittest.main()
