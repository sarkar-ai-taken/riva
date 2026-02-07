"""Tests for IDE agent detectors."""

import json
from unittest.mock import patch

from riva.agents.cline import ClineDetector
from riva.agents.continue_dev import ContinueDevDetector
from riva.agents.cursor import CursorDetector
from riva.agents.github_copilot import GitHubCopilotDetector
from riva.agents.windsurf import WindsurfDetector

# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


class TestCursorDetector:
    def test_properties(self):
        d = CursorDetector()
        assert d.agent_name == "Cursor"
        assert "Cursor" in d.binary_names
        assert d.api_domain == "api2.cursor.sh"

    def test_match_by_name(self):
        d = CursorDetector()
        assert d.match_process("Cursor", [], "") is True

    def test_match_cursor_helper(self):
        d = CursorDetector()
        assert d.match_process("Cursor Helper (Renderer)", [], "") is True

    def test_match_by_exe_macos(self):
        d = CursorDetector()
        assert d.match_process("", [], "/Applications/Cursor.app/Contents/MacOS/Cursor") is True

    def test_no_match(self):
        d = CursorDetector()
        assert d.match_process("python", ["python", "app.py"], "/usr/bin/python") is False

    def test_parse_config_with_settings(self, tmp_path):
        d = CursorDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "settings.json").write_text(json.dumps({"theme": "dark"}))
            result = d.parse_config()
            assert "theme" in result.get("settings", {})

    def test_parse_config_mcp(self, tmp_path):
        d = CursorDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            mcp_data = {"mcpServers": {"test": {"command": "node", "args": ["server.js"]}}}
            (tmp_path / "mcp.json").write_text(json.dumps(mcp_data))
            result = d.parse_config()
            assert "mcp" in result
            assert "mcpServers" in result["mcp"]

    def test_parse_config_sessions(self, tmp_path):
        d = CursorDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            projects = tmp_path / "projects"
            projects.mkdir()
            (projects / "test.jsonl").write_text('{"type": "test"}\n')
            result = d.parse_config()
            assert result["session_count"] == 1

    def test_create_detector(self):
        from riva.agents.cursor import create_detector

        d = create_detector()
        assert d.agent_name == "Cursor"


# ---------------------------------------------------------------------------
# GitHub Copilot
# ---------------------------------------------------------------------------


class TestGitHubCopilotDetector:
    def test_properties(self):
        d = GitHubCopilotDetector()
        assert d.agent_name == "GitHub Copilot"
        assert d.api_domain == "api.github.com"

    def test_match_copilot_language_server(self):
        d = GitHubCopilotDetector()
        assert d.match_process("copilot-language-server", [], "") is True

    def test_match_node_with_copilot(self):
        d = GitHubCopilotDetector()
        assert (
            d.match_process(
                "node",
                ["node", "/path/to/github.copilot/dist/language-server.js"],
                "/usr/local/bin/node",
            )
            is True
        )

    def test_no_match_plain_node(self):
        d = GitHubCopilotDetector()
        assert d.match_process("node", ["node", "server.js"], "/usr/bin/node") is False

    def test_is_installed_with_extension(self, tmp_path):
        d = GitHubCopilotDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            ext_dir = tmp_path / "extensions" / "github.copilot-1.200.0"
            ext_dir.mkdir(parents=True)
            assert d.is_installed() is True

    def test_is_not_installed(self, tmp_path):
        d = GitHubCopilotDetector()
        empty_dir = tmp_path / "nonexistent_vscode"
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: empty_dir)):
            with patch("shutil.which", return_value=None):
                assert d.is_installed() is False

    def test_parse_config_with_extension(self, tmp_path):
        d = GitHubCopilotDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            ext_dir = tmp_path / "extensions" / "github.copilot-1.200.0"
            ext_dir.mkdir(parents=True)
            (ext_dir / "package.json").write_text(
                json.dumps(
                    {
                        "version": "1.200.0",
                        "displayName": "GitHub Copilot",
                    }
                )
            )
            result = d.parse_config()
            assert result["version"] == "1.200.0"

    def test_create_detector(self):
        from riva.agents.github_copilot import create_detector

        d = create_detector()
        assert d.agent_name == "GitHub Copilot"


# ---------------------------------------------------------------------------
# Windsurf
# ---------------------------------------------------------------------------


class TestWindsurfDetector:
    def test_properties(self):
        d = WindsurfDetector()
        assert d.agent_name == "Windsurf"
        assert "windsurf" in d.binary_names
        assert d.api_domain == "api.codeium.com"

    def test_match_by_name(self):
        d = WindsurfDetector()
        assert d.match_process("windsurf", [], "") is True

    def test_match_by_exe(self):
        d = WindsurfDetector()
        assert d.match_process("", [], "/Applications/Windsurf.app/Contents/MacOS/Windsurf") is True

    def test_match_helper(self):
        d = WindsurfDetector()
        assert d.match_process("Windsurf Helper", [], "") is True

    def test_no_match(self):
        d = WindsurfDetector()
        assert d.match_process("python", ["python", "app.py"], "/usr/bin/python") is False

    def test_parse_config(self, tmp_path):
        d = WindsurfDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "config.json").write_text(json.dumps({"enabled": True}))
            result = d.parse_config()
            assert result.get("codeium_settings", {}).get("enabled") is True

    def test_create_detector(self):
        from riva.agents.windsurf import create_detector

        d = create_detector()
        assert d.agent_name == "Windsurf"


# ---------------------------------------------------------------------------
# Continue.dev
# ---------------------------------------------------------------------------


class TestContinueDevDetector:
    def test_properties(self):
        d = ContinueDevDetector()
        assert d.agent_name == "Continue"
        assert d.api_domain == "api.continue.dev"

    def test_match_by_name(self):
        d = ContinueDevDetector()
        assert d.match_process("continue", [], "") is True

    def test_match_language_server(self):
        d = ContinueDevDetector()
        assert (
            d.match_process(
                "node",
                ["node", "/path/to/continue/language-server"],
                "/usr/bin/node",
            )
            is True
        )

    def test_no_match_plain_node(self):
        d = ContinueDevDetector()
        assert d.match_process("node", ["node", "server.js"], "/usr/bin/node") is False

    def test_parse_config(self, tmp_path):
        d = ContinueDevDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            config_data = {
                "models": [{"title": "GPT-4", "provider": "openai"}],
                "tabAutocompleteModel": {"title": "Codestral", "provider": "mistral"},
            }
            (tmp_path / "config.json").write_text(json.dumps(config_data))
            result = d.parse_config()
            assert len(result["models"]) == 1
            assert result["tab_autocomplete"]["title"] == "Codestral"

    def test_create_detector(self):
        from riva.agents.continue_dev import create_detector

        d = create_detector()
        assert d.agent_name == "Continue"


# ---------------------------------------------------------------------------
# Cline
# ---------------------------------------------------------------------------


class TestClineDetector:
    def test_properties(self):
        d = ClineDetector()
        assert d.agent_name == "Cline"
        assert d.api_domain == "api.anthropic.com"

    def test_match_claude_dev_in_cmdline(self):
        d = ClineDetector()
        assert (
            d.match_process(
                "node",
                ["node", "/path/to/saoudrizwan.claude-dev/out/extension.js"],
                "/usr/bin/node",
            )
            is True
        )

    def test_no_match(self):
        d = ClineDetector()
        assert d.match_process("node", ["node", "server.js"], "/usr/bin/node") is False

    def test_is_installed_with_extension(self, tmp_path):
        d = ClineDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            ext_dir = tmp_path / "saoudrizwan.claude-dev-3.0.0"
            ext_dir.mkdir()
            assert d.is_installed() is True

    def test_is_not_installed(self, tmp_path):
        d = ClineDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            assert d.is_installed() is False

    def test_parse_config_with_extension(self, tmp_path):
        d = ClineDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            ext_dir = tmp_path / "saoudrizwan.claude-dev-3.0.0"
            ext_dir.mkdir()
            (ext_dir / "package.json").write_text(
                json.dumps(
                    {
                        "version": "3.0.0",
                        "displayName": "Cline",
                    }
                )
            )
            result = d.parse_config()
            assert result["version"] == "3.0.0"

    def test_create_detector(self):
        from riva.agents.cline import create_detector

        d = create_detector()
        assert d.agent_name == "Cline"


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


class TestRegistryWithNewDetectors:
    def test_registry_has_all_detectors(self):
        from riva.agents.registry import get_default_registry

        registry = get_default_registry()
        names = [d.agent_name for d in registry.detectors]
        assert "Cursor" in names
        assert "GitHub Copilot" in names
        assert "Windsurf" in names
        assert "Continue" in names
        assert "Cline" in names
        # Original 7 + 5 new = 12
        assert len(names) >= 12
