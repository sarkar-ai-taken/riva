"""Tests for riva.core.env_scanner."""

from unittest.mock import patch

from riva.core.env_scanner import _is_secret, scan_env_vars


class TestIsSecret:
    def test_api_key(self):
        assert _is_secret("ANTHROPIC_API_KEY") is True

    def test_token(self):
        assert _is_secret("GITHUB_TOKEN") is True

    def test_password(self):
        assert _is_secret("DB_PASSWORD") is True

    def test_non_secret(self):
        assert _is_secret("CLAUDE_CODE_ENTRYPOINT") is False

    def test_case_insensitive(self):
        assert _is_secret("my_secret_value") is True


class TestScanEnvVars:
    def test_detects_ai_vars(self):
        env = {
            "ANTHROPIC_API_KEY": "sk-ant-1234567890",
            "OPENAI_API_KEY": "sk-openai-abc",
            "CLAUDE_CODE_ENTRYPOINT": "cli",
            "HOME": "/home/user",
            "PATH": "/usr/bin",
        }
        with patch.dict("os.environ", env, clear=True):
            results = scan_env_vars()

        names = [r["name"] for r in results]
        assert "ANTHROPIC_API_KEY" in names
        assert "OPENAI_API_KEY" in names
        assert "CLAUDE_CODE_ENTRYPOINT" in names
        assert "HOME" not in names
        assert "PATH" not in names

    def test_masks_secret_values(self):
        env = {"ANTHROPIC_API_KEY": "sk-ant-1234567890"}
        with patch.dict("os.environ", env, clear=True):
            results = scan_env_vars()

        var = results[0]
        assert var["name"] == "ANTHROPIC_API_KEY"
        # Value should be masked — last 4 chars visible
        assert var["value"].endswith("7890")
        assert var["value"].startswith("*")

    def test_non_secret_not_masked(self):
        env = {"CLAUDE_CODE_ENTRYPOINT": "cli"}
        with patch.dict("os.environ", env, clear=True):
            results = scan_env_vars()

        var = results[0]
        assert var["value"] == "cli"

    def test_raw_length_is_string(self):
        env = {"GEMINI_MODEL": "gemini-pro"}
        with patch.dict("os.environ", env, clear=True):
            results = scan_env_vars()

        assert results[0]["raw_length"] == "10"

    def test_empty_env(self):
        with patch.dict("os.environ", {}, clear=True):
            results = scan_env_vars()
        assert results == []

    def test_prefix_matching(self):
        env = {"OPENCLAW_BACKEND": "ollama", "CODEX_MODEL": "gpt-5"}
        with patch.dict("os.environ", env, clear=True):
            results = scan_env_vars()
        names = {r["name"] for r in results}
        assert "OPENCLAW_BACKEND" in names
        assert "CODEX_MODEL" in names
