"""Tests for riva.agents.base."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from riva.agents.base import (
    AgentDetector,
    AgentInstance,
    AgentStatus,
    SimpleAgentDetector,
    filter_secrets,
)


# ---------------------------------------------------------------------------
# filter_secrets
# ---------------------------------------------------------------------------

class TestFilterSecrets:
    def test_removes_key_fields(self):
        data = {"api_key": "secret", "model": "gpt-4", "token": "abc"}
        result = filter_secrets(data)
        assert result == {"model": "gpt-4"}

    def test_case_insensitive(self):
        data = {"API_KEY": "x", "Secret_Value": "y", "name": "z"}
        result = filter_secrets(data)
        assert result == {"name": "z"}

    def test_empty_dict(self):
        assert filter_secrets({}) == {}

    def test_no_secrets(self):
        data = {"model": "claude", "temperature": 0.7}
        assert filter_secrets(data) == data

    def test_password_and_credential(self):
        data = {"db_password": "pw", "user_credential": "cred", "host": "localhost"}
        assert filter_secrets(data) == {"host": "localhost"}


# ---------------------------------------------------------------------------
# AgentStatus
# ---------------------------------------------------------------------------

class TestAgentStatus:
    def test_values(self):
        assert AgentStatus.RUNNING.value == "running"
        assert AgentStatus.INSTALLED.value == "installed"
        assert AgentStatus.NOT_FOUND.value == "not_found"


# ---------------------------------------------------------------------------
# AgentInstance
# ---------------------------------------------------------------------------

class TestAgentInstance:
    def test_defaults(self):
        inst = AgentInstance(name="Test", status=AgentStatus.INSTALLED)
        assert inst.pid is None
        assert inst.cpu_percent == 0.0
        assert inst.command_line == []
        assert inst.extra == {}

    def test_full_construction(self):
        inst = AgentInstance(
            name="Claude Code",
            status=AgentStatus.RUNNING,
            pid=1234,
            cpu_percent=12.5,
            memory_mb=256.0,
            api_domain="api.anthropic.com",
        )
        assert inst.pid == 1234
        assert inst.api_domain == "api.anthropic.com"


# ---------------------------------------------------------------------------
# SimpleAgentDetector
# ---------------------------------------------------------------------------

class TestSimpleAgentDetector:
    def _make(self, **kwargs):
        defaults = dict(
            name="TestAgent",
            binaries=["testagent"],
            config="/tmp/riva_test_nonexistent_dir",
            api="api.test.dev",
        )
        defaults.update(kwargs)
        return SimpleAgentDetector(**defaults)

    def test_properties(self):
        det = self._make()
        assert det.agent_name == "TestAgent"
        assert det.binary_names == ["testagent"]
        assert det.api_domain == "api.test.dev"

    def test_match_by_process_name(self):
        det = self._make()
        assert det.match_process("testagent", [], "") is True

    def test_no_match_wrong_name(self):
        det = self._make()
        assert det.match_process("other", [], "") is False

    def test_match_by_exe_path(self):
        det = self._make()
        assert det.match_process("", [], "/usr/bin/testagent") is True

    def test_match_by_cmdline(self):
        det = self._make()
        assert det.match_process("", ["/usr/local/bin/testagent", "--flag"], "") is True

    def test_cmdline_contains(self):
        det = self._make(cmdline_contains=["gemini-cli"])
        assert det.match_process("node", ["/usr/bin/node", "/path/to/gemini-cli"], "") is True

    def test_cmdline_contains_no_match(self):
        det = self._make(cmdline_contains=["gemini-cli"])
        assert det.match_process("node", ["/usr/bin/node", "server.js"], "") is False

    def test_custom_process_matcher(self):
        matcher = lambda name, cmdline, exe: name == "custom"
        det = self._make(process_matcher=matcher)
        assert det.match_process("custom", [], "") is True
        assert det.match_process("testagent", [], "") is False

    def test_is_installed_false_when_nothing_exists(self):
        det = self._make(config="/tmp/riva_test_nonexistent_dir_xyz")
        with patch("shutil.which", return_value=None):
            assert det.is_installed() is False

    def test_is_installed_true_when_config_dir_exists(self, tmp_path):
        det = self._make(config=str(tmp_path))
        assert det.is_installed() is True

    def test_build_instance_not_found(self):
        det = self._make(config="/tmp/riva_test_nonexistent_dir_xyz")
        with patch("shutil.which", return_value=None):
            inst = det.build_instance()
            assert inst.status == AgentStatus.NOT_FOUND
            assert inst.name == "TestAgent"

    def test_build_instance_running(self, tmp_path):
        det = self._make(config=str(tmp_path))
        inst = det.build_instance(pid=999, cpu_percent=5.0, memory_mb=100.0)
        assert inst.status == AgentStatus.RUNNING
        assert inst.pid == 999
        assert inst.cpu_percent == 5.0

    def test_parse_config_json(self, tmp_path):
        config_dir = tmp_path / "agent"
        config_dir.mkdir()
        (config_dir / "settings.json").write_text(
            json.dumps({"model": "gpt-4", "api_key": "sk-secret"})
        )
        det = self._make(config=str(config_dir))
        result = det.parse_config()
        assert result["settings"]["model"] == "gpt-4"
        assert "api_key" not in result["settings"]

    def test_parse_config_toml(self, tmp_path):
        config_dir = tmp_path / "agent"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text('model = "claude"\napi_key = "sk-x"\n')
        det = self._make(
            config=str(config_dir),
            config_filenames=["config.toml"],
        )
        result = det.parse_config()
        assert result["settings"]["model"] == "claude"
        assert "api_key" not in result["settings"]

    def test_custom_config_parser(self, tmp_path):
        def my_parser(config_dir: Path) -> dict:
            return {"custom": True}

        det = self._make(config=str(tmp_path), config_parser=my_parser)
        result = det.parse_config()
        assert result == {"custom": True}

    def test_custom_config_parser_exception(self, tmp_path):
        def bad_parser(config_dir: Path) -> dict:
            raise RuntimeError("boom")

        det = self._make(config=str(tmp_path), config_parser=bad_parser)
        result = det.parse_config()
        assert "_error" in result


# ---------------------------------------------------------------------------
# _match_by_name (via a minimal concrete subclass)
# ---------------------------------------------------------------------------

class _StubDetector(AgentDetector):
    @property
    def agent_name(self):
        return "Stub"

    @property
    def binary_names(self):
        return ["stub", "stub-alt"]

    @property
    def config_dir(self):
        return Path("/tmp/riva_stub_nonexistent")

    @property
    def api_domain(self):
        return "api.stub.dev"

    def match_process(self, name, cmdline, exe):
        return self._match_by_name(name, cmdline, exe)

    def parse_config(self):
        return {}


class TestMatchByName:
    def test_exact_name(self):
        det = _StubDetector()
        assert det.match_process("stub", [], "") is True

    def test_alt_name(self):
        det = _StubDetector()
        assert det.match_process("stub-alt", [], "") is True

    def test_exe_tail_match(self):
        det = _StubDetector()
        assert det.match_process("", [], "/usr/local/bin/stub") is True

    def test_cmdline_arg_match(self):
        det = _StubDetector()
        assert det.match_process("", ["/opt/bin/stub-alt", "--verbose"], "") is True

    def test_no_match(self):
        det = _StubDetector()
        assert det.match_process("python", ["python", "script.py"], "/usr/bin/python") is False

    def test_empty_inputs(self):
        det = _StubDetector()
        assert det.match_process("", [], "") is False
