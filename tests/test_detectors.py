"""Tests for the builtin agent detectors."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from riva.agents.autogen import AutoGenDetector
from riva.agents.claude_code import ClaudeCodeDetector
from riva.agents.codex_cli import CodexCLIDetector
from riva.agents.crewai import CrewAIDetector
from riva.agents.gemini_cli import GeminiCLIDetector
from riva.agents.langgraph import LangGraphDetector
from riva.agents.openclaw import OpenClawDetector


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------

class TestClaudeCodeDetector:
    def test_properties(self):
        d = ClaudeCodeDetector()
        assert d.agent_name == "Claude Code"
        assert "claude" in d.binary_names
        assert d.api_domain == "api.anthropic.com"

    def test_match_by_name(self):
        d = ClaudeCodeDetector()
        assert d.match_process("claude", [], "") is True

    def test_match_by_exe(self):
        d = ClaudeCodeDetector()
        assert d.match_process("", [], "/home/user/.local/bin/claude") is True

    def test_match_by_cmdline(self):
        d = ClaudeCodeDetector()
        assert d.match_process("", ["/home/user/.local/bin/claude", "chat"], "") is True

    def test_no_match(self):
        d = ClaudeCodeDetector()
        assert d.match_process("python", ["python", "-m", "claude_api"], "/usr/bin/python") is False

    def test_parse_config_with_settings(self, tmp_path):
        d = ClaudeCodeDetector()
        settings = {"theme": "dark", "api_key": "sk-secret"}
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "settings.json").write_text(json.dumps(settings))
            result = d.parse_config()
            assert "theme" in result.get("settings", {})
            assert "api_key" not in result.get("settings", {})

    def test_parse_config_counts_projects(self, tmp_path):
        d = ClaudeCodeDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            projects = tmp_path / "projects"
            projects.mkdir()
            (projects / "proj-a").mkdir()
            (projects / "proj-b").mkdir()
            result = d.parse_config()
            assert result["projects_count"] == 2

    def test_parse_config_missing_dir(self):
        d = ClaudeCodeDetector()
        with patch.object(
            type(d), "config_dir",
            new_callable=lambda: property(lambda self: Path("/tmp/riva_nonexistent_claude")),
        ):
            result = d.parse_config()
            assert "installed" in result

    def test_create_detector(self):
        from riva.agents.claude_code import create_detector

        d = create_detector()
        assert d.agent_name == "Claude Code"


# ---------------------------------------------------------------------------
# Codex CLI
# ---------------------------------------------------------------------------

class TestCodexCLIDetector:
    def test_properties(self):
        d = CodexCLIDetector()
        assert d.agent_name == "Codex CLI"
        assert "codex" in d.binary_names
        assert d.api_domain == "api.openai.com"

    def test_match_by_name(self):
        d = CodexCLIDetector()
        assert d.match_process("codex", [], "") is True

    def test_no_match(self):
        d = CodexCLIDetector()
        assert d.match_process("node", ["node", "codex-server"], "/usr/bin/node") is False

    def test_parse_config_toml(self, tmp_path):
        d = CodexCLIDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "config.toml").write_text(
                'model = "gpt-5"\napi_key = "sk-123"\n'
            )
            result = d.parse_config()
            assert result["settings"]["model"] == "gpt-5"
            assert "api_key" not in result["settings"]

    def test_parse_config_instructions(self, tmp_path):
        d = CodexCLIDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "instructions.md").write_text("Be helpful and concise.")
            result = d.parse_config()
            assert result["instructions_length"] == 23
            assert "Be helpful" in result["instructions_preview"]

    def test_create_detector(self):
        from riva.agents.codex_cli import create_detector

        d = create_detector()
        assert d.agent_name == "Codex CLI"


# ---------------------------------------------------------------------------
# Gemini CLI
# ---------------------------------------------------------------------------

class TestGeminiCLIDetector:
    def test_properties(self):
        d = GeminiCLIDetector()
        assert d.agent_name == "Gemini CLI"
        assert "gemini" in d.binary_names
        assert "googleapis" in d.api_domain

    def test_match_by_name(self):
        d = GeminiCLIDetector()
        assert d.match_process("gemini", [], "") is True

    def test_match_node_with_gemini_cli(self):
        d = GeminiCLIDetector()
        assert d.match_process(
            "node",
            ["/usr/local/bin/node", "/path/to/@google/gemini-cli/index.js"],
            "/usr/local/bin/node",
        ) is True

    def test_no_match_plain_node(self):
        d = GeminiCLIDetector()
        assert d.match_process("node", ["node", "server.js"], "/usr/bin/node") is False

    def test_parse_config_settings_and_config(self, tmp_path):
        d = GeminiCLIDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "settings.json").write_text(json.dumps({"theme": "light"}))
            (tmp_path / "config.json").write_text(json.dumps({"project": "my-proj"}))
            result = d.parse_config()
            assert result["settings"]["theme"] == "light"
            assert result["config"]["project"] == "my-proj"

    def test_create_detector(self):
        from riva.agents.gemini_cli import create_detector

        d = create_detector()
        assert d.agent_name == "Gemini CLI"


# ---------------------------------------------------------------------------
# OpenClaw
# ---------------------------------------------------------------------------

class TestOpenClawDetector:
    def test_properties(self):
        d = OpenClawDetector()
        assert d.agent_name == "OpenClaw"
        assert "openclaw" in d.binary_names
        assert "moltbot" in d.binary_names
        assert "clawdbot" in d.binary_names

    def test_match_openclaw(self):
        d = OpenClawDetector()
        assert d.match_process("openclaw", [], "") is True

    def test_match_moltbot(self):
        d = OpenClawDetector()
        assert d.match_process("moltbot", [], "") is True

    def test_match_clawdbot_exe(self):
        d = OpenClawDetector()
        assert d.match_process("", [], "/usr/bin/clawdbot") is True

    def test_no_match(self):
        d = OpenClawDetector()
        assert d.match_process("python", [], "/usr/bin/python") is False

    def test_parse_config(self, tmp_path):
        d = OpenClawDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "config.json").write_text(
                json.dumps({"backend": "ollama", "api_key": "sk-x"})
            )
            result = d.parse_config()
            assert result["settings"]["backend"] == "ollama"
            assert "api_key" not in result["settings"]

    def test_create_detector(self):
        from riva.agents.openclaw import create_detector

        d = create_detector()
        assert d.agent_name == "OpenClaw"


# ---------------------------------------------------------------------------
# LangGraph
# ---------------------------------------------------------------------------

class TestLangGraphDetector:
    def test_properties(self):
        d = LangGraphDetector()
        assert d.agent_name == "LangGraph"
        assert "langgraph" in d.binary_names
        assert "langchain" in d.api_domain

    def test_match_by_name(self):
        d = LangGraphDetector()
        assert d.match_process("langgraph", [], "") is True

    def test_match_python_with_langgraph(self):
        d = LangGraphDetector()
        assert d.match_process(
            "python", ["python", "-m", "langgraph", "serve"], "/usr/bin/python"
        ) is True

    def test_match_python_with_langchain(self):
        d = LangGraphDetector()
        assert d.match_process(
            "python3", ["python3", "run_langchain_agent.py"], "/usr/bin/python3"
        ) is True

    def test_no_match_plain_python(self):
        d = LangGraphDetector()
        assert d.match_process("python", ["python", "server.py"], "/usr/bin/python") is False

    def test_parse_config(self, tmp_path):
        d = LangGraphDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "langgraph.json").write_text(json.dumps({"graph": "my_graph"}))
            result = d.parse_config()
            assert result["settings"]["graph"] == "my_graph"

    def test_create_detector(self):
        from riva.agents.langgraph import create_detector

        d = create_detector()
        assert d.agent_name == "LangGraph"


# ---------------------------------------------------------------------------
# CrewAI
# ---------------------------------------------------------------------------

class TestCrewAIDetector:
    def test_properties(self):
        d = CrewAIDetector()
        assert d.agent_name == "CrewAI"
        assert "crewai" in d.binary_names
        assert "crewai" in d.api_domain

    def test_match_by_name(self):
        d = CrewAIDetector()
        assert d.match_process("crewai", [], "") is True

    def test_match_python_with_crewai(self):
        d = CrewAIDetector()
        assert d.match_process(
            "python", ["python", "-m", "crewai", "run"], "/usr/bin/python"
        ) is True

    def test_no_match_plain_python(self):
        d = CrewAIDetector()
        assert d.match_process("python", ["python", "app.py"], "/usr/bin/python") is False

    def test_parse_config(self, tmp_path):
        d = CrewAIDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "config.json").write_text(json.dumps({"crew": "research"}))
            result = d.parse_config()
            assert result["settings"]["crew"] == "research"

    def test_create_detector(self):
        from riva.agents.crewai import create_detector

        d = create_detector()
        assert d.agent_name == "CrewAI"


# ---------------------------------------------------------------------------
# AutoGen
# ---------------------------------------------------------------------------

class TestAutoGenDetector:
    def test_properties(self):
        d = AutoGenDetector()
        assert d.agent_name == "AutoGen"
        assert "autogen" in d.binary_names

    def test_match_by_name(self):
        d = AutoGenDetector()
        assert d.match_process("autogen", [], "") is True

    def test_match_python_with_autogen(self):
        d = AutoGenDetector()
        assert d.match_process(
            "python", ["python", "-m", "autogen", "serve"], "/usr/bin/python"
        ) is True

    def test_match_python3_with_autogen_script(self):
        d = AutoGenDetector()
        assert d.match_process(
            "python3", ["python3", "run_autogen_chat.py"], "/usr/bin/python3"
        ) is True

    def test_no_match_plain_python(self):
        d = AutoGenDetector()
        assert d.match_process("python", ["python", "main.py"], "/usr/bin/python") is False

    def test_parse_config(self, tmp_path):
        d = AutoGenDetector()
        with patch.object(type(d), "config_dir", new_callable=lambda: property(lambda self: tmp_path)):
            (tmp_path / "OAI_CONFIG_LIST").write_text(json.dumps({"model": "gpt-4"}))
            result = d.parse_config()
            assert result["settings"]["model"] == "gpt-4"

    def test_create_detector(self):
        from riva.agents.autogen import create_detector

        d = create_detector()
        assert d.agent_name == "AutoGen"
