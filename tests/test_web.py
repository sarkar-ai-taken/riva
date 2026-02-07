"""Tests for riva.web.server and riva.web.daemon."""

from __future__ import annotations

import signal
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from riva.agents.base import AgentInstance, AgentStatus
from riva.cli import cli as riva_cli
from riva.core.monitor import AgentHistory, ResourceSnapshot
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_instances():
    return [
        AgentInstance(
            name="Claude Code",
            status=AgentStatus.RUNNING,
            pid=1234,
            binary_path="/usr/local/bin/claude",
            config_dir="~/.claude",
            api_domain="api.anthropic.com",
            cpu_percent=5.2,
            memory_mb=256.1,
            uptime_seconds=3600,
            working_directory="/home/user/project",
        ),
        AgentInstance(
            name="Codex CLI",
            status=AgentStatus.INSTALLED,
            api_domain="api.openai.com",
        ),
    ]


def _fake_histories():
    hist = AgentHistory(agent_name="Claude Code", pid=1234)
    for i in range(5):
        hist.snapshots.append(ResourceSnapshot(timestamp=1000 + i, cpu_percent=3.0 + i, memory_mb=250.0 + i))
    return {"Claude Code:1234": hist}


def _fake_usage_stats():
    return UsageStats(
        total_tokens=15000,
        total_sessions=5,
        total_messages=100,
        total_tool_calls=42,
        tool_stats=[
            ToolCallStats(tool_name="Read", call_count=20, last_used="2025-01-15"),
            ToolCallStats(tool_name="Write", call_count=10),
        ],
        model_stats={
            "claude-3-opus": ModelStats(
                model_id="claude-3-opus",
                usage=TokenUsage(
                    input_tokens=5000,
                    output_tokens=8000,
                    cache_read_input_tokens=1500,
                    cache_creation_input_tokens=500,
                ),
            )
        },
        daily_activity=[
            DailyStats(date="2025-01-15", message_count=30, session_count=2, tool_call_count=15, total_tokens=5000),
        ],
        time_range_start="2025-01-01",
        time_range_end="2025-01-15",
    )


def _make_mock_monitor(instances=None, histories=None):
    monitor = MagicMock()
    monitor.instances = instances if instances is not None else _fake_instances()
    monitor.histories = histories if histories is not None else _fake_histories()
    return monitor


def _make_mock_registry(installed=True, usage=None, parse_config_return=None):
    registry = MagicMock()
    det = MagicMock()
    det.agent_name = "Claude Code"
    det.binary_names = ["claude"]
    det.config_dir = MagicMock()
    det.config_dir.exists.return_value = installed
    det.config_dir.__str__ = lambda self: "~/.claude"
    det.api_domain = "api.anthropic.com"
    det.is_installed.return_value = installed

    inst = AgentInstance(
        name="Claude Code",
        status=AgentStatus.INSTALLED if installed else AgentStatus.NOT_FOUND,
        api_domain="api.anthropic.com",
    )
    det.build_instance.return_value = inst
    det.parse_usage.return_value = usage
    det.parse_config.return_value = parse_config_return or {"config_dir": "~/.claude", "settings": {"theme": "dark"}}
    registry.detectors = [det]
    return registry


@pytest.fixture
def app():
    """Create a test Flask app with mocked monitor and registry."""
    import riva.web.server as srv

    # Clear caches
    srv._stats_cache.clear()

    with (
        patch.object(srv, "_get_monitor", return_value=_make_mock_monitor()),
        patch.object(srv, "_get_registry", return_value=_make_mock_registry(installed=True, usage=_fake_usage_stats())),
    ):
        application = srv.create_app()
        application.config["TESTING"] = True
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestIndexRoute:
    def test_index_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"RIVA" in resp.data
        assert b"text/html" in resp.content_type.encode()


class TestApiAgents:
    def test_returns_agents_list(self, client):
        resp = client.get("/api/agents")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "agents" in data
        assert "timestamp" in data
        assert len(data["agents"]) == 2

    def test_agent_fields(self, client):
        resp = client.get("/api/agents")
        data = resp.get_json()
        claude = next(a for a in data["agents"] if a["name"] == "Claude Code")
        assert claude["status"] == "running"
        assert claude["pid"] == 1234
        assert claude["cpu_percent"] == 5.2
        assert claude["memory_mb"] == 256.1
        assert "memory_formatted" in claude
        assert "uptime_formatted" in claude
        assert claude["api_domain"] == "api.anthropic.com"

    def test_empty_agents(self):
        import riva.web.server as srv

        srv._stats_cache.clear()

        with (
            patch.object(srv, "_get_monitor", return_value=_make_mock_monitor(instances=[])),
            patch.object(srv, "_get_registry", return_value=_make_mock_registry()),
        ):
            application = srv.create_app()
            application.config["TESTING"] = True
            with application.test_client() as c:
                resp = c.get("/api/agents")
                data = resp.get_json()
                assert data["agents"] == []


class TestApiAgentsHistory:
    def test_returns_histories(self, client):
        resp = client.get("/api/agents/history")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "histories" in data
        hist = data["histories"]["Claude Code:1234"]
        assert hist["agent_name"] == "Claude Code"
        assert hist["pid"] == 1234
        assert len(hist["cpu_history"]) == 5
        assert len(hist["memory_history"]) == 5

    def test_empty_histories(self):
        import riva.web.server as srv

        srv._stats_cache.clear()

        with (
            patch.object(srv, "_get_monitor", return_value=_make_mock_monitor(histories={})),
            patch.object(srv, "_get_registry", return_value=_make_mock_registry()),
        ):
            application = srv.create_app()
            application.config["TESTING"] = True
            with application.test_client() as c:
                resp = c.get("/api/agents/history")
                assert resp.get_json()["histories"] == {}


class TestApiStats:
    def test_returns_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data
        assert len(data["stats"]) == 1
        s = data["stats"][0]
        assert s["name"] == "Claude Code"
        assert s["total_tokens"] == 15000
        assert s["total_sessions"] == 5
        assert s["total_messages"] == 100
        assert s["total_tool_calls"] == 42
        assert len(s["top_tools"]) == 2
        assert len(s["daily_activity"]) == 1
        assert "claude-3-opus" in s["models"]

    def test_stats_none_usage(self):
        import riva.web.server as srv

        srv._stats_cache.clear()

        with (
            patch.object(srv, "_get_monitor", return_value=_make_mock_monitor()),
            patch.object(srv, "_get_registry", return_value=_make_mock_registry(installed=True, usage=None)),
        ):
            application = srv.create_app()
            application.config["TESTING"] = True
            with application.test_client() as c:
                resp = c.get("/api/stats")
                data = resp.get_json()
                assert data["stats"][0]["total_tokens"] == 0
                assert data["stats"][0]["top_tools"] == []


class TestApiEnv:
    def test_returns_env_vars(self, client):
        with patch(
            "riva.web.server.scan_env_vars",
            return_value=[{"name": "ANTHROPIC_API_KEY", "value": "****abcd", "raw_length": "51"}],
        ):
            import riva.web.server as srv

            srv._stats_cache.pop("env", None)
            resp = client.get("/api/env")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "env_vars" in data
            assert len(data["env_vars"]) == 1
            assert data["env_vars"][0]["name"] == "ANTHROPIC_API_KEY"


class TestApiRegistry:
    def test_returns_registry(self, client):
        resp = client.get("/api/registry")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "agents" in data
        assert len(data["agents"]) == 1
        a = data["agents"][0]
        assert a["name"] == "Claude Code"
        assert a["binaries"] == ["claude"]
        assert a["installed"] is True
        assert a["api_domain"] == "api.anthropic.com"


class TestApiConfig:
    def test_returns_configs(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "configs" in data
        assert len(data["configs"]) == 1
        assert data["configs"][0]["name"] == "Claude Code"
        assert "config_dir" in data["configs"][0]["config"]

    def test_no_installed_agents(self):
        import riva.web.server as srv

        srv._stats_cache.clear()

        with (
            patch.object(srv, "_get_monitor", return_value=_make_mock_monitor()),
            patch.object(srv, "_get_registry", return_value=_make_mock_registry(installed=False)),
        ):
            application = srv.create_app()
            application.config["TESTING"] = True
            with application.test_client() as c:
                resp = c.get("/api/config")
                data = resp.get_json()
                assert data["configs"] == []


# ---------------------------------------------------------------------------
# Daemon PID file management tests
# ---------------------------------------------------------------------------


class TestDaemonPidFile:
    def test_write_and_read_pid(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        with patch.object(daemon, "PID_FILE", pid_file), patch.object(daemon, "PID_DIR", tmp_path):
            daemon.write_pid(12345)
            assert daemon.read_pid() == 12345

    def test_read_pid_missing(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        with patch.object(daemon, "PID_FILE", pid_file):
            assert daemon.read_pid() is None

    def test_read_pid_invalid(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        pid_file.write_text("not-a-number")
        with patch.object(daemon, "PID_FILE", pid_file):
            assert daemon.read_pid() is None

    def test_remove_pid(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        pid_file.write_text("999")
        with patch.object(daemon, "PID_FILE", pid_file):
            daemon.remove_pid()
            assert not pid_file.exists()

    def test_remove_pid_missing(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        with patch.object(daemon, "PID_FILE", pid_file):
            daemon.remove_pid()  # should not raise

    def test_is_running_true(self):
        from riva.web import daemon

        with patch("os.kill") as mock_kill:
            mock_kill.return_value = None
            assert daemon.is_running(1234) is True
            mock_kill.assert_called_once_with(1234, 0)

    def test_is_running_false(self):
        from riva.web import daemon

        with patch("os.kill", side_effect=ProcessLookupError):
            assert daemon.is_running(1234) is False


class TestStartDaemon:
    def test_start_daemon_success(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        log_file = tmp_path / "web.log"

        mock_proc = MagicMock()
        mock_proc.pid = 9999

        with (
            patch.object(daemon, "PID_FILE", pid_file),
            patch.object(daemon, "PID_DIR", tmp_path),
            patch.object(daemon, "LOG_FILE", log_file),
            patch.object(daemon, "read_pid", return_value=None),
            patch("subprocess.Popen", return_value=mock_proc),
        ):
            pid = daemon.start_daemon("127.0.0.1", 8585)

        assert pid == 9999
        assert pid_file.read_text() == "9999"

    def test_start_daemon_already_running(self, tmp_path):
        from riva.web import daemon

        with patch.object(daemon, "read_pid", return_value=1111), patch.object(daemon, "is_running", return_value=True):
            with pytest.raises(RuntimeError, match="already running"):
                daemon.start_daemon("127.0.0.1", 8585)


class TestStopDaemon:
    def test_stop_daemon_success(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        pid_file.write_text("5555")

        # is_running returns True first (for the initial check), then False (after SIGTERM)
        with (
            patch.object(daemon, "PID_FILE", pid_file),
            patch.object(daemon, "read_pid", return_value=5555),
            patch.object(daemon, "is_running", side_effect=[True, False]),
            patch("os.kill") as mock_kill,
            patch("time.sleep"),
        ):
            result = daemon.stop_daemon()

        assert result is True
        mock_kill.assert_called_once_with(5555, signal.SIGTERM)

    def test_stop_daemon_not_running(self, tmp_path):
        from riva.web import daemon

        pid_file = tmp_path / "web.pid"
        with patch.object(daemon, "PID_FILE", pid_file), patch.object(daemon, "read_pid", return_value=None):
            result = daemon.stop_daemon()

        assert result is False


class TestDaemonStatus:
    def test_status_running(self):
        from riva.web import daemon

        with (
            patch.object(daemon, "read_pid", return_value=7777),
            patch.object(daemon, "is_running", return_value=True),
            patch.object(daemon, "LOG_FILE", MagicMock(__str__=lambda s: "/tmp/web.log")),
        ):
            info = daemon.daemon_status()

        assert info["running"] is True
        assert info["pid"] == 7777

    def test_status_not_running(self):
        from riva.web import daemon

        with (
            patch.object(daemon, "read_pid", return_value=None),
            patch.object(daemon, "LOG_FILE", MagicMock(__str__=lambda s: "/tmp/web.log")),
        ):
            info = daemon.daemon_status()

        assert info["running"] is False
        assert info["pid"] is None


# ---------------------------------------------------------------------------
# CLI subcommand tests
# ---------------------------------------------------------------------------


class TestWebStartCommand:
    def test_start_background(self):
        runner = CliRunner()
        with patch("riva.web.daemon.start_daemon", return_value=4242) as mock_start:
            result = runner.invoke(riva_cli, ["web", "start"])
        assert result.exit_code == 0
        assert "4242" in result.output
        mock_start.assert_called_once_with("127.0.0.1", 8585, auth_token=None)

    def test_start_foreground(self):
        runner = CliRunner()
        with patch("riva.web.server.run_server") as mock_run:
            result = runner.invoke(riva_cli, ["web", "start", "-f"])
        assert result.exit_code == 0
        mock_run.assert_called_once_with(host="127.0.0.1", port=8585, auth_token=None)

    def test_start_already_running(self):
        runner = CliRunner()
        with patch("riva.web.daemon.start_daemon", side_effect=RuntimeError("already running")):
            result = runner.invoke(riva_cli, ["web", "start"])
        assert result.exit_code == 1
        assert "already running" in result.output


class TestWebStopCommand:
    def test_stop_running(self):
        runner = CliRunner()
        with patch("riva.web.daemon.stop_daemon", return_value=True):
            result = runner.invoke(riva_cli, ["web", "stop"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()

    def test_stop_not_running(self):
        runner = CliRunner()
        with patch("riva.web.daemon.stop_daemon", return_value=False):
            result = runner.invoke(riva_cli, ["web", "stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()


class TestWebStatusCommand:
    def test_status_running(self):
        runner = CliRunner()
        with patch(
            "riva.web.daemon.daemon_status",
            return_value={
                "running": True,
                "pid": 1234,
                "log_file": "/tmp/web.log",
            },
        ):
            result = runner.invoke(riva_cli, ["web", "status"])
        assert result.exit_code == 0
        assert "1234" in result.output
        assert "Running" in result.output

    def test_status_not_running(self):
        runner = CliRunner()
        with patch(
            "riva.web.daemon.daemon_status",
            return_value={
                "running": False,
                "pid": None,
                "log_file": "/tmp/web.log",
            },
        ):
            result = runner.invoke(riva_cli, ["web", "status"])
        assert result.exit_code == 0
        assert "Not running" in result.output


class TestWebLogsCommand:
    def test_logs_no_file(self, tmp_path):
        runner = CliRunner()
        fake_log = tmp_path / "web.log"
        with patch("riva.web.daemon.LOG_FILE", fake_log):
            result = runner.invoke(riva_cli, ["web", "logs"])
        assert result.exit_code == 0
        assert "No log file" in result.output

    def test_logs_reads_file(self, tmp_path):
        runner = CliRunner()
        fake_log = tmp_path / "web.log"
        fake_log.write_text("line1\nline2\nline3\n")
        with patch("riva.web.daemon.LOG_FILE", fake_log):
            result = runner.invoke(riva_cli, ["web", "logs", "-n", "2"])
        assert result.exit_code == 0
        assert "line2" in result.output
        assert "line3" in result.output


class TestWebBackwardCompat:
    """``riva web`` with no subcommand should run in foreground."""

    def test_bare_web_runs_foreground(self):
        runner = CliRunner()
        with patch("riva.web.server.run_server") as mock_run:
            result = runner.invoke(riva_cli, ["web"])
        assert result.exit_code == 0
        mock_run.assert_called_once_with(host="127.0.0.1", port=8585, auth_token=None)


# ---------------------------------------------------------------------------
# Security headers tests
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        resp = client.get("/api/agents")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Content-Security-Policy"] == "default-src 'self' 'unsafe-inline'"
        assert resp.headers["X-XSS-Protection"] == "1; mode=block"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_security_headers_on_index(self, client):
        resp = client.get("/")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"


# ---------------------------------------------------------------------------
# Auth token tests
# ---------------------------------------------------------------------------


class TestAuthToken:
    def _create_authed_app(self, token):
        import riva.web.server as srv

        srv._stats_cache.clear()

        with (
            patch.object(srv, "_get_monitor", return_value=_make_mock_monitor()),
            patch.object(
                srv, "_get_registry", return_value=_make_mock_registry(installed=True, usage=_fake_usage_stats())
            ),
        ):
            application = srv.create_app(auth_token=token)
            application.config["TESTING"] = True
            return application

    def test_api_returns_401_without_token(self):
        app = self._create_authed_app("secret123")
        with app.test_client() as c:
            resp = c.get("/api/agents")
            assert resp.status_code == 401
            data = resp.get_json()
            assert data["error"] == "Unauthorized"

    def test_api_returns_200_with_valid_token(self):
        app = self._create_authed_app("secret123")
        with app.test_client() as c:
            resp = c.get("/api/agents", headers={"Authorization": "Bearer secret123"})
            assert resp.status_code == 200

    def test_api_returns_401_with_wrong_token(self):
        app = self._create_authed_app("secret123")
        with app.test_client() as c:
            resp = c.get("/api/agents", headers={"Authorization": "Bearer wrongtoken"})
            assert resp.status_code == 401

    def test_index_accessible_without_token(self):
        app = self._create_authed_app("secret123")
        with app.test_client() as c:
            resp = c.get("/")
            assert resp.status_code == 200

    def test_no_auth_token_allows_all(self, client):
        resp = client.get("/api/agents")
        assert resp.status_code == 200
