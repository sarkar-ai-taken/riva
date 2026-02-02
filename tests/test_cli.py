"""Tests for riva.cli."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from riva.agents.base import AgentInstance, AgentStatus
from riva.cli import cli
from riva.core.usage_stats import TokenUsage, ToolCallStats, UsageStats


@pytest.fixture
def runner():
    return CliRunner()


def _fake_instances():
    return [
        AgentInstance(
            name="Claude Code",
            status=AgentStatus.RUNNING,
            pid=1234,
            cpu_percent=5.0,
            memory_mb=256.0,
            uptime_seconds=3600,
            api_domain="api.anthropic.com",
            working_directory="/home/user/project",
        ),
        AgentInstance(
            name="Codex CLI",
            status=AgentStatus.INSTALLED,
            api_domain="api.openai.com",
        ),
    ]


class TestScanCommand:
    def test_scan_table_output(self, runner):
        with patch("riva.cli.ResourceMonitor") as MockMonitor:
            mock = MockMonitor.return_value
            mock.scan_once.return_value = _fake_instances()
            result = runner.invoke(cli, ["scan"])

        assert result.exit_code == 0
        assert "Claude Code" in result.output

    def test_scan_json_output(self, runner):
        with patch("riva.cli.ResourceMonitor") as MockMonitor:
            mock = MockMonitor.return_value
            mock.scan_once.return_value = _fake_instances()
            result = runner.invoke(cli, ["scan", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 2
        names = {d["name"] for d in data}
        assert "Claude Code" in names
        assert "Codex CLI" in names

    def test_scan_json_fields(self, runner):
        with patch("riva.cli.ResourceMonitor") as MockMonitor:
            mock = MockMonitor.return_value
            mock.scan_once.return_value = _fake_instances()
            result = runner.invoke(cli, ["scan", "--json"])

        data = json.loads(result.output)
        claude = next(d for d in data if d["name"] == "Claude Code")
        assert claude["status"] == "running"
        assert claude["pid"] == 1234
        assert claude["api_domain"] == "api.anthropic.com"
        assert "cpu_percent" in claude
        assert "memory_mb" in claude

    def test_scan_empty(self, runner):
        with patch("riva.cli.ResourceMonitor") as MockMonitor:
            mock = MockMonitor.return_value
            mock.scan_once.return_value = []
            result = runner.invoke(cli, ["scan"])

        assert result.exit_code == 0

    def test_scan_json_empty(self, runner):
        with patch("riva.cli.ResourceMonitor") as MockMonitor:
            mock = MockMonitor.return_value
            mock.scan_once.return_value = []
            result = runner.invoke(cli, ["scan", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.output) == []


class TestListCommand:
    def test_list_shows_all_agents(self, runner):
        result = runner.invoke(cli, ["list"])
        assert result.exit_code == 0
        assert "Claude Code" in result.output
        assert "Codex CLI" in result.output
        assert "Gemini CLI" in result.output
        assert "OpenClaw" in result.output
        assert "LangGraph" in result.output
        assert "CrewAI" in result.output
        assert "AutoGen" in result.output

    def test_list_shows_binaries(self, runner):
        result = runner.invoke(cli, ["list"])
        assert "claude" in result.output
        assert "codex" in result.output
        assert "gemini" in result.output
        assert "langgraph" in result.output
        assert "crewai" in result.output
        assert "autogen" in result.output


class TestConfigCommand:
    def test_config_runs(self, runner):
        result = runner.invoke(cli, ["config"])
        assert result.exit_code == 0

    def test_config_no_agents_installed(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            reg = MagicMock()
            det = MagicMock()
            det.is_installed.return_value = False
            reg.detectors = [det]
            mock_reg.return_value = reg
            result = runner.invoke(cli, ["config"])

        assert result.exit_code == 0
        assert "No installed agents" in result.output


class TestAuditCommand:
    def test_audit_table_output(self, runner):
        from riva.core.audit import AuditResult

        fake_results = [
            AuditResult(check="API Key Exposure", status="pass", detail="No secrets found."),
            AuditResult(check="Dashboard Status", status="warn", detail="Dashboard is running."),
        ]
        with patch("riva.core.audit.run_audit", return_value=fake_results):
            result = runner.invoke(cli, ["audit"])

        assert result.exit_code == 0
        assert "API Key Exposure" in result.output
        assert "PASS" in result.output
        assert "WARN" in result.output

    def test_audit_json_output(self, runner):
        from riva.core.audit import AuditResult

        fake_results = [
            AuditResult(check="API Key Exposure", status="pass", detail="No secrets found."),
        ]
        with patch("riva.core.audit.run_audit", return_value=fake_results):
            result = runner.invoke(cli, ["audit", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["check"] == "API Key Exposure"
        assert data[0]["status"] == "pass"
        assert data[0]["detail"] == "No secrets found."

    def test_audit_empty_results(self, runner):
        with patch("riva.core.audit.run_audit", return_value=[]):
            result = runner.invoke(cli, ["audit"])
        assert result.exit_code == 0


class TestHostBindingWarning:
    def test_non_localhost_warning_foreground(self, runner):
        with patch("riva.web.server.run_server") as mock_run:
            result = runner.invoke(cli, ["web", "--host", "0.0.0.0", "start", "-f"])
        assert result.exit_code == 0
        assert "non-localhost" in result.output.lower() or "Warning" in result.output

    def test_localhost_no_warning(self, runner):
        with patch("riva.web.server.run_server") as mock_run:
            result = runner.invoke(cli, ["web", "--host", "127.0.0.1", "start", "-f"])
        assert result.exit_code == 0
        assert "non-localhost" not in result.output.lower()

    def test_non_localhost_warning_background(self, runner):
        with patch("riva.web.daemon.start_daemon", return_value=4242):
            result = runner.invoke(cli, ["web", "--host", "0.0.0.0", "start"])
        assert result.exit_code == 0
        assert "non-localhost" in result.output.lower() or "Warning" in result.output


class TestHelpAndDefault:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Riva" in result.output
        assert "watch" in result.output
        assert "scan" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output


# ---------------------------------------------------------------------------
# riva stats
# ---------------------------------------------------------------------------


def _fake_usage_stats():
    return UsageStats(
        total_tokens=15000,
        total_sessions=5,
        total_messages=100,
        total_tool_calls=42,
        tool_stats=[
            ToolCallStats(tool_name="Read", call_count=20),
            ToolCallStats(tool_name="Write", call_count=10),
        ],
        time_range_start="2025-01-01",
        time_range_end="2025-01-15",
    )


def _make_mock_registry(installed=True, usage=None):
    """Create a mock registry with one detector."""
    registry = MagicMock()
    det = MagicMock()
    det.agent_name = "Claude Code"
    det.is_installed.return_value = installed
    det.binary_names = ["claude"]
    det.config_dir = MagicMock()
    det.config_dir.exists.return_value = installed
    det.api_domain = "api.anthropic.com"
    det.parse_usage.return_value = usage
    inst = AgentInstance(
        name="Claude Code",
        status=AgentStatus.INSTALLED if installed else AgentStatus.NOT_FOUND,
        api_domain="api.anthropic.com",
    )
    det.build_instance.return_value = inst
    registry.detectors = [det]
    return registry


class TestStatsCommand:
    def test_stats_table_output(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(
                installed=True, usage=_fake_usage_stats()
            )
            result = runner.invoke(cli, ["stats"])

        assert result.exit_code == 0
        assert "Claude Code" in result.output

    def test_stats_json_output(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(
                installed=True, usage=_fake_usage_stats()
            )
            result = runner.invoke(cli, ["stats", "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        entry = data[0]
        assert entry["name"] == "Claude Code"
        assert entry["usage"] is not None
        assert entry["usage"]["total_tokens"] == 15000
        assert entry["usage"]["total_sessions"] == 5
        assert entry["usage"]["total_messages"] == 100
        assert entry["usage"]["total_tool_calls"] == 42
        assert len(entry["usage"]["top_tools"]) == 2

    def test_stats_json_no_usage(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(installed=True, usage=None)
            result = runner.invoke(cli, ["stats", "--json"])

        data = json.loads(result.output)
        assert data[0]["usage"] is None

    def test_stats_agent_filter(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(installed=True, usage=_fake_usage_stats())
            result = runner.invoke(cli, ["stats", "--agent", "Claude"])

        assert result.exit_code == 0
        assert "Claude Code" in result.output

    def test_stats_agent_filter_no_match(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(installed=True, usage=_fake_usage_stats())
            result = runner.invoke(cli, ["stats", "--agent", "NonExistent"])

        assert result.exit_code == 0

    def test_stats_no_installed_agents(self, runner):
        with patch("riva.cli.get_default_registry") as mock_reg:
            mock_reg.return_value = _make_mock_registry(installed=False)
            result = runner.invoke(cli, ["stats"])

        assert result.exit_code == 0
