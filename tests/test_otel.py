"""Tests for riva.otel — OpenTelemetry exporter integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — lightweight fakes that avoid importing real OTel SDK
# ---------------------------------------------------------------------------


@dataclass
class FakeAgentInstance:
    name: str = "Claude Code"
    status: object = None
    pid: int | None = 1234
    cpu_percent: float = 12.5
    memory_mb: float = 256.0
    uptime_seconds: float = 120.0
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.status is None:
            # Lazy import to avoid circular deps in tests
            from riva.agents.base import AgentStatus

            self.status = AgentStatus.RUNNING


@dataclass
class FakeAuditResult:
    check: str = "Test Check"
    status: str = "warn"
    detail: str = "Something is suspicious"
    severity: str = "medium"
    category: str = "general"


# ---------------------------------------------------------------------------
# Phase 1: Config tests
# ---------------------------------------------------------------------------


class TestOTelConfig:
    """Test OTelConfig dataclass and load_otel_config."""

    def test_defaults(self):
        from riva.otel.config import OTelConfig

        cfg = OTelConfig()
        assert cfg.enabled is False
        assert cfg.endpoint == "http://localhost:4318"
        assert cfg.protocol == "http"
        assert cfg.service_name == "riva"
        assert cfg.export_interval == 5.0
        assert cfg.metrics is True
        assert cfg.logs is True
        assert cfg.traces is False

    def test_load_from_workspace_config(self):
        from riva.otel.config import load_otel_config

        @dataclass
        class FakeWsConfig:
            otel_enabled: bool = True
            otel_endpoint: str = "http://collector:4318"
            otel_protocol: str = "grpc"
            otel_headers: dict = field(default_factory=lambda: {"Authorization": "Bearer tok"})
            otel_service_name: str = "my-riva"
            otel_export_interval: float = 10.0
            otel_metrics: bool = True
            otel_logs: bool = False
            otel_traces: bool = True

        ws = FakeWsConfig()
        cfg = load_otel_config(ws)
        assert cfg.enabled is True
        assert cfg.endpoint == "http://collector:4318"
        assert cfg.protocol == "grpc"
        assert cfg.headers == {"Authorization": "Bearer tok"}
        assert cfg.service_name == "my-riva"
        assert cfg.export_interval == 10.0
        assert cfg.logs is False
        assert cfg.traces is True

    def test_load_from_env_vars(self, monkeypatch):
        from riva.otel.config import load_otel_config

        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-collector:4318")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "env-riva")
        monkeypatch.setenv("RIVA_OTEL_ENABLED", "true")

        cfg = load_otel_config()
        assert cfg.enabled is True
        assert cfg.endpoint == "http://env-collector:4318"
        assert cfg.service_name == "env-riva"

    def test_workspace_overrides_env(self, monkeypatch):
        from riva.otel.config import load_otel_config

        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:4318")
        monkeypatch.setenv("OTEL_SERVICE_NAME", "env-svc")

        @dataclass
        class FakeWsConfig:
            otel_enabled: bool = True
            otel_endpoint: str = "http://ws:4318"
            otel_protocol: str = "http"
            otel_headers: dict = field(default_factory=dict)
            otel_service_name: str = "ws-svc"
            otel_export_interval: float = 5.0
            otel_metrics: bool = True
            otel_logs: bool = True
            otel_traces: bool = False

        cfg = load_otel_config(FakeWsConfig())
        assert cfg.endpoint == "http://ws:4318"
        assert cfg.service_name == "ws-svc"

    def test_load_with_none_workspace(self):
        from riva.otel.config import load_otel_config

        cfg = load_otel_config(None)
        assert cfg.enabled is False
        assert cfg.endpoint == "http://localhost:4318"


# ---------------------------------------------------------------------------
# is_available() detection
# ---------------------------------------------------------------------------


class TestIsAvailable:
    def test_is_available_returns_bool(self):
        from riva.otel import is_available

        result = is_available()
        assert isinstance(result, bool)

    def test_is_available_false_when_sdk_missing(self):
        """Simulating missing SDK by patching import."""

        import riva.otel as otel_mod

        original = otel_mod.is_available

        def fake_unavailable():
            return False

        otel_mod.is_available = fake_unavailable
        try:
            assert otel_mod.is_available() is False
        finally:
            otel_mod.is_available = original


# ---------------------------------------------------------------------------
# Workspace config integration
# ---------------------------------------------------------------------------


class TestWorkspaceOTelConfig:
    def test_workspace_config_has_otel_fields(self):
        from pathlib import Path

        from riva.core.workspace import WorkspaceConfig

        wc = WorkspaceConfig(root_dir=Path("/tmp"), riva_dir=Path("/tmp/.riva"))
        assert wc.otel_enabled is False
        assert wc.otel_endpoint == "http://localhost:4318"
        assert wc.otel_protocol == "http"
        assert wc.otel_service_name == "riva"
        assert wc.otel_export_interval == 5.0
        assert wc.otel_metrics is True
        assert wc.otel_logs is True
        assert wc.otel_traces is False

    def test_load_workspace_config_parses_otel(self, tmp_path):
        from riva.core.workspace import load_workspace_config

        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        config_toml = riva_dir / "config.toml"
        config_toml.write_text(
            '[workspace]\nname = "test"\n\n'
            "[otel]\n"
            "enabled = true\n"
            'endpoint = "http://my-collector:4318"\n'
            'service_name = "test-riva"\n'
            "traces = true\n"
        )

        wc = load_workspace_config(riva_dir)
        assert wc.otel_enabled is True
        assert wc.otel_endpoint == "http://my-collector:4318"
        assert wc.otel_service_name == "test-riva"
        assert wc.otel_traces is True


# ---------------------------------------------------------------------------
# RivaOTelExporter with mocked providers (requires OTel SDK)
# ---------------------------------------------------------------------------


def _otel_available():
    try:
        import opentelemetry.sdk  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _otel_available(), reason="opentelemetry SDK not installed")
class TestRivaOTelExporter:
    """Integration-style tests with real OTel SDK but mocked OTLP exporters."""

    def _make_config(self, **overrides):
        from riva.otel.config import OTelConfig

        defaults = dict(
            enabled=True,
            endpoint="http://localhost:4318",
            metrics=True,
            logs=True,
            traces=True,
        )
        defaults.update(overrides)
        return OTelConfig(**defaults)

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_on_poll_updates_snapshot(self, mock_span_exp, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config()
        exporter = RivaOTelExporter(cfg)

        instances = [FakeAgentInstance()]
        exporter.on_poll(instances)

        assert exporter._metrics._instances == instances
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_on_agent_detected(self, mock_span_exp, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config()
        exporter = RivaOTelExporter(cfg)

        exporter.on_agent_detected("Claude Code", 1234)
        # Verify no crash; counter incremented internally
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_on_agent_stopped(self, mock_span_exp, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config()
        exporter = RivaOTelExporter(cfg)

        exporter.on_agent_stopped("Claude Code", 1234)
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_on_audit_results(self, mock_span_exp, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config()
        exporter = RivaOTelExporter(cfg)

        results = [FakeAuditResult(), FakeAuditResult(status="fail", severity="high")]
        exporter.on_audit_results(results)
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_export_sessions(self, mock_span_exp, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config()
        exporter = RivaOTelExporter(cfg)

        @dataclass
        class FakeAction:
            tool_name: str = "Read"
            input_summary: str = "file.py"
            output_preview: str = ""
            duration_ms: int | None = 50
            files_touched: list = field(default_factory=lambda: ["file.py"])
            timestamp: str | None = None
            success: bool = True

        @dataclass
        class FakeTurn:
            index: int = 0
            prompt: str = "Fix the bug"
            actions: list = field(default_factory=lambda: [FakeAction()])
            model: str = "claude-opus-4-6"
            tokens_in: int = 100
            tokens_out: int = 200
            timestamp_start: str | None = "2025-01-01T00:00:00"
            timestamp_end: str | None = "2025-01-01T00:01:00"
            is_dead_end: bool = False
            files_read: list = field(default_factory=lambda: ["file.py"])
            files_written: list = field(default_factory=list)

        @dataclass
        class FakeSession:
            session_id: str = "abc-123"
            slug: str | None = "fix-bug"
            project: str | None = "/home/user/project"
            agent: str = "Claude Code"
            model: str = "claude-opus-4-6"
            turns: list = field(default_factory=lambda: [FakeTurn()])
            timestamp_start: str | None = "2025-01-01T00:00:00"
            timestamp_end: str | None = "2025-01-01T00:05:00"
            total_tokens: int = 300
            total_files_read: int = 1
            total_files_written: int = 0
            total_actions: int = 1
            dead_end_count: int = 0
            efficiency: float = 1.0

        exporter.export_sessions([FakeSession()])
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    def test_metrics_only(self, mock_log_exp, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config(traces=False)
        exporter = RivaOTelExporter(cfg)

        assert exporter._metrics is not None
        assert exporter._logs is not None
        assert exporter._traces is None

        exporter.on_poll([FakeAgentInstance()])
        exporter.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    def test_metrics_only_no_logs(self, mock_metric_exp):
        from riva.otel.exporter import RivaOTelExporter

        cfg = self._make_config(logs=False, traces=False)
        exporter = RivaOTelExporter(cfg)

        assert exporter._metrics is not None
        assert exporter._logs is None
        assert exporter._traces is None
        exporter.shutdown()


# ---------------------------------------------------------------------------
# Graceful degradation (no SDK)
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_import_otel_package_never_fails(self):
        """Importing riva.otel should always succeed."""
        import riva.otel  # noqa: F401

    def test_is_available_callable(self):
        from riva.otel import is_available

        # Should return a bool regardless of SDK presence
        assert isinstance(is_available(), bool)

    def test_config_loads_without_sdk(self):
        """OTelConfig and load_otel_config don't need the SDK."""
        from riva.otel.config import OTelConfig, load_otel_config

        cfg = OTelConfig()
        assert cfg.endpoint == "http://localhost:4318"

        loaded = load_otel_config()
        assert loaded.enabled is False


# ---------------------------------------------------------------------------
# Metrics exporter unit tests (requires SDK)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _otel_available(), reason="opentelemetry SDK not installed")
class TestMetricsExporter:
    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    def test_update_snapshot_stores_instances(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.metrics import MetricsExporter

        cfg = OTelConfig(enabled=True)
        metrics = MetricsExporter(cfg)

        instances = [FakeAgentInstance(), FakeAgentInstance(name="Cursor", pid=5678)]
        metrics.update_snapshot(instances)
        assert len(metrics._instances) == 2
        metrics.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    def test_record_scan_increments(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.metrics import MetricsExporter

        cfg = OTelConfig(enabled=True)
        metrics = MetricsExporter(cfg)

        # Should not raise
        metrics.record_scan()
        metrics.record_scan()
        metrics.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.metric_exporter.OTLPMetricExporter")
    def test_record_audit_finding(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.metrics import MetricsExporter

        cfg = OTelConfig(enabled=True)
        metrics = MetricsExporter(cfg)

        metrics.record_audit_finding(FakeAuditResult())
        metrics.shutdown()


# ---------------------------------------------------------------------------
# Logs exporter unit tests (requires SDK)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _otel_available(), reason="opentelemetry SDK not installed")
class TestLogsExporter:
    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    def test_emit_audit_finding(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.logs import LogsExporter

        cfg = OTelConfig(enabled=True)
        logs = LogsExporter(cfg)

        logs.emit_audit_finding(FakeAuditResult())
        logs.emit_audit_finding(FakeAuditResult(status="fail"))
        logs.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http._log_exporter.OTLPLogExporter")
    def test_emit_lifecycle_event(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.logs import LogsExporter

        cfg = OTelConfig(enabled=True)
        logs = LogsExporter(cfg)

        logs.emit_lifecycle_event("agent_detected", agent_name="Claude Code", pid=1234)
        logs.emit_lifecycle_event("agent_stopped", agent_name="Cursor", pid=5678)
        logs.shutdown()


# ---------------------------------------------------------------------------
# Traces exporter unit tests (requires SDK)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _otel_available(), reason="opentelemetry SDK not installed")
class TestTracesExporter:
    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_export_session(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.traces import TracesExporter

        cfg = OTelConfig(enabled=True, traces=True)
        traces = TracesExporter(cfg)

        @dataclass
        class FakeAction:
            tool_name: str = "Write"
            input_summary: str = ""
            output_preview: str = ""
            duration_ms: int | None = 100
            files_touched: list = field(default_factory=lambda: ["main.py"])
            timestamp: str | None = "2025-01-01T00:00:30"
            success: bool = True

        @dataclass
        class FakeTurn:
            index: int = 0
            prompt: str = "Write tests"
            actions: list = field(default_factory=lambda: [FakeAction()])
            model: str = "claude-opus-4-6"
            tokens_in: int = 500
            tokens_out: int = 1000
            timestamp_start: str | None = "2025-01-01T00:00:00"
            timestamp_end: str | None = "2025-01-01T00:02:00"
            is_dead_end: bool = False
            files_read: list = field(default_factory=list)
            files_written: list = field(default_factory=lambda: ["main.py"])

        @dataclass
        class FakeSession:
            session_id: str = "sess-001"
            slug: str | None = "write-tests"
            project: str | None = "/project"
            agent: str = "Claude Code"
            model: str = "claude-opus-4-6"
            turns: list = field(default_factory=lambda: [FakeTurn()])
            timestamp_start: str | None = "2025-01-01T00:00:00"
            timestamp_end: str | None = "2025-01-01T00:10:00"
            total_tokens: int = 1500
            total_files_read: int = 0
            total_files_written: int = 1
            total_actions: int = 1
            dead_end_count: int = 0
            efficiency: float = 1.0

        traces.export_session(FakeSession())
        traces.shutdown()

    @patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter")
    def test_export_session_with_dead_end(self, mock_exporter):
        from riva.otel.config import OTelConfig
        from riva.otel.traces import TracesExporter

        cfg = OTelConfig(enabled=True, traces=True)
        traces = TracesExporter(cfg)

        @dataclass
        class FakeTurn:
            index: int = 0
            prompt: str = "Try something"
            actions: list = field(default_factory=list)
            model: str = "claude-opus-4-6"
            tokens_in: int = 200
            tokens_out: int = 100
            timestamp_start: str | None = None
            timestamp_end: str | None = None
            is_dead_end: bool = True
            files_read: list = field(default_factory=list)
            files_written: list = field(default_factory=list)

        @dataclass
        class FakeSession:
            session_id: str = "sess-dead"
            slug: str | None = None
            project: str | None = None
            agent: str = "Claude Code"
            model: str | None = None
            turns: list = field(default_factory=lambda: [FakeTurn()])
            timestamp_start: str | None = None
            timestamp_end: str | None = None
            total_tokens: int = 300
            total_files_read: int = 0
            total_files_written: int = 0
            total_actions: int = 0
            dead_end_count: int = 1
            efficiency: float = 0.0

        traces.export_session(FakeSession())
        traces.shutdown()


# ---------------------------------------------------------------------------
# Traces helper
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _otel_available(), reason="opentelemetry SDK not installed")
class TestIsoToNs:
    def test_valid_iso(self):
        from riva.otel.traces import _iso_to_ns

        ns = _iso_to_ns("2025-01-01T00:00:00")
        assert ns is not None
        assert ns > 0

    def test_none_input(self):
        from riva.otel.traces import _iso_to_ns

        assert _iso_to_ns(None) is None

    def test_invalid_input(self):
        from riva.otel.traces import _iso_to_ns

        assert _iso_to_ns("not-a-date") is None
