"""OTel configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class OTelConfig:
    """Parsed OpenTelemetry exporter configuration."""

    enabled: bool = False
    endpoint: str = "http://localhost:4318"
    protocol: str = "http"  # http | grpc
    headers: dict[str, str] = field(default_factory=dict)
    service_name: str = "riva"
    export_interval: float = 5.0  # seconds
    metrics: bool = True
    logs: bool = True
    traces: bool = False  # opt-in


def load_otel_config(workspace_config: object | None = None) -> OTelConfig:
    """Build an :class:`OTelConfig` from workspace config, env vars, then defaults.

    Priority: workspace config > environment variables > defaults.
    """
    cfg = OTelConfig()

    # 1. Environment variable fallbacks
    if ep := os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        cfg.endpoint = ep
    if sn := os.environ.get("OTEL_SERVICE_NAME"):
        cfg.service_name = sn
    if os.environ.get("RIVA_OTEL_ENABLED", "").lower() in ("1", "true", "yes"):
        cfg.enabled = True

    # 2. Workspace config overrides (highest priority)
    if workspace_config is not None:
        wc = workspace_config
        if hasattr(wc, "otel_enabled"):
            cfg.enabled = wc.otel_enabled
        if hasattr(wc, "otel_endpoint") and wc.otel_endpoint:
            cfg.endpoint = wc.otel_endpoint
        if hasattr(wc, "otel_protocol") and wc.otel_protocol:
            cfg.protocol = wc.otel_protocol
        if hasattr(wc, "otel_headers") and wc.otel_headers:
            cfg.headers = dict(wc.otel_headers)
        if hasattr(wc, "otel_service_name") and wc.otel_service_name:
            cfg.service_name = wc.otel_service_name
        if hasattr(wc, "otel_export_interval"):
            cfg.export_interval = wc.otel_export_interval
        if hasattr(wc, "otel_metrics"):
            cfg.metrics = wc.otel_metrics
        if hasattr(wc, "otel_logs"):
            cfg.logs = wc.otel_logs
        if hasattr(wc, "otel_traces"):
            cfg.traces = wc.otel_traces

    return cfg
