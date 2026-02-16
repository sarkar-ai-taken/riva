"""Main OTel exporter coordinator for Riva."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.agents.base import AgentInstance
    from riva.core.audit import AuditResult
    from riva.core.forensic import ForensicSession
    from riva.otel.config import OTelConfig

logger = logging.getLogger(__name__)


class RivaOTelExporter:
    """Orchestrates metrics, logs, and traces OTel exporters."""

    def __init__(self, config: OTelConfig) -> None:
        self._config = config
        self._metrics = None
        self._logs = None
        self._traces = None

        if config.metrics:
            from riva.otel.metrics import MetricsExporter

            self._metrics = MetricsExporter(config)

        if config.logs:
            from riva.otel.logs import LogsExporter

            self._logs = LogsExporter(config)

        if config.traces:
            from riva.otel.traces import TracesExporter

            self._traces = TracesExporter(config)

        logger.info(
            "OTel exporter initialized (metrics=%s, logs=%s, traces=%s) → %s",
            config.metrics,
            config.logs,
            config.traces,
            config.endpoint,
        )

    def on_poll(self, instances: list[AgentInstance]) -> None:
        """Called after each monitor poll cycle."""
        if self._metrics:
            self._metrics.update_snapshot(instances)
            self._metrics.record_scan()

    def on_agent_detected(self, agent_name: str, pid: int) -> None:
        if self._metrics:
            self._metrics.record_agent_detected(agent_name)
        if self._logs:
            self._logs.emit_lifecycle_event("agent_detected", agent_name=agent_name, pid=pid)

    def on_agent_stopped(self, agent_name: str, pid: int) -> None:
        if self._metrics:
            self._metrics.record_agent_stopped(agent_name)
        if self._logs:
            self._logs.emit_lifecycle_event("agent_stopped", agent_name=agent_name, pid=pid)

    def on_audit_results(self, results: list[AuditResult]) -> None:
        for r in results:
            if self._metrics:
                self._metrics.record_audit_finding(r)
            if self._logs:
                self._logs.emit_audit_finding(r)

    def export_sessions(self, sessions: list[ForensicSession]) -> None:
        if self._traces:
            self._traces.export_sessions(sessions)

    def shutdown(self) -> None:
        errors: list[str] = []
        if self._metrics:
            try:
                self._metrics.shutdown()
            except Exception as exc:
                errors.append(f"metrics: {exc}")
        if self._logs:
            try:
                self._logs.shutdown()
            except Exception as exc:
                errors.append(f"logs: {exc}")
        if self._traces:
            try:
                self._traces.shutdown()
            except Exception as exc:
                errors.append(f"traces: {exc}")
        if errors:
            logger.warning("OTel shutdown errors: %s", "; ".join(errors))
