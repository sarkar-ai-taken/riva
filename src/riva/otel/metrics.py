"""OTel metrics exporter — observable gauges and counters for Riva agent data."""

from __future__ import annotations

import platform
from importlib.metadata import version as pkg_version
from typing import TYPE_CHECKING

from opentelemetry.metrics import CallbackOptions, Observation
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

if TYPE_CHECKING:
    from riva.agents.base import AgentInstance
    from riva.core.audit import AuditResult
    from riva.otel.config import OTelConfig


class MetricsExporter:
    """Exports Riva agent metrics via OTLP."""

    def __init__(self, config: OTelConfig) -> None:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )

        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.version": self._get_version(),
                "host.name": platform.node(),
            }
        )

        exporter = OTLPMetricExporter(
            endpoint=f"{config.endpoint}/v1/metrics",
            headers=config.headers or {},
        )
        reader = PeriodicExportingMetricReader(exporter, export_interval_millis=int(config.export_interval * 1000))
        self._meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        meter = self._meter_provider.get_meter("riva", self._get_version())

        # Snapshot state for gauge callbacks
        self._instances: list[AgentInstance] = []

        # --- Observable gauges ---
        meter.create_observable_gauge(
            "riva.agent.cpu_percent",
            callbacks=[self._observe_cpu],
            unit="%",
            description="CPU usage percentage per agent",
        )
        meter.create_observable_gauge(
            "riva.agent.memory_mb",
            callbacks=[self._observe_memory],
            unit="MiBy",
            description="Memory usage in MB per agent",
        )
        meter.create_observable_gauge(
            "riva.agent.uptime_seconds",
            callbacks=[self._observe_uptime],
            unit="s",
            description="Agent uptime in seconds",
        )
        meter.create_observable_gauge(
            "riva.agent.connection_count",
            callbacks=[self._observe_connections],
            unit="{connection}",
            description="Number of active network connections per agent",
        )
        meter.create_observable_gauge(
            "riva.agent.child_count",
            callbacks=[self._observe_children],
            unit="{process}",
            description="Number of child processes per agent",
        )
        meter.create_observable_gauge(
            "riva.agent.tree_cpu_percent",
            callbacks=[self._observe_tree_cpu],
            unit="%",
            description="Total CPU usage for agent process tree",
        )
        meter.create_observable_gauge(
            "riva.agent.tree_memory_mb",
            callbacks=[self._observe_tree_memory],
            unit="MiBy",
            description="Total memory for agent process tree in MB",
        )
        meter.create_observable_gauge(
            "riva.agents.running_count",
            callbacks=[self._observe_running_count],
            unit="{agent}",
            description="Number of running agent instances",
        )

        # --- Counters ---
        self._detected_counter = meter.create_counter(
            "riva.agent.detected_total",
            unit="{event}",
            description="Total agent detection events",
        )
        self._stopped_counter = meter.create_counter(
            "riva.agent.stopped_total",
            unit="{event}",
            description="Total agent stop events",
        )
        self._scan_counter = meter.create_counter(
            "riva.scan.total",
            unit="{scan}",
            description="Total scan cycles",
        )
        self._audit_counter = meter.create_counter(
            "riva.audit.finding_total",
            unit="{finding}",
            description="Total audit findings",
        )

    # --- Public API ---

    def update_snapshot(self, instances: list[AgentInstance]) -> None:
        """Store latest instances so gauge callbacks can read them."""
        self._instances = list(instances)

    def record_agent_detected(self, agent_name: str) -> None:
        self._detected_counter.add(1, {"riva.agent.name": agent_name})

    def record_agent_stopped(self, agent_name: str) -> None:
        self._stopped_counter.add(1, {"riva.agent.name": agent_name})

    def record_scan(self) -> None:
        self._scan_counter.add(1)

    def record_audit_finding(self, result: AuditResult) -> None:
        self._audit_counter.add(
            1,
            {
                "riva.audit.check": result.check,
                "riva.audit.status": result.status,
                "riva.audit.severity": result.severity,
                "riva.audit.category": result.category,
            },
        )

    def shutdown(self) -> None:
        self._meter_provider.shutdown()

    # --- Gauge callbacks ---

    def _running_instances(self) -> list[AgentInstance]:
        from riva.agents.base import AgentStatus

        return [i for i in self._instances if i.status == AgentStatus.RUNNING and i.pid]

    def _attrs(self, inst: AgentInstance) -> dict:
        return {"riva.agent.name": inst.name, "process.pid": inst.pid}

    def _observe_cpu(self, options: CallbackOptions):
        for inst in self._running_instances():
            yield Observation(inst.cpu_percent, self._attrs(inst))

    def _observe_memory(self, options: CallbackOptions):
        for inst in self._running_instances():
            yield Observation(inst.memory_mb, self._attrs(inst))

    def _observe_uptime(self, options: CallbackOptions):
        for inst in self._running_instances():
            yield Observation(inst.uptime_seconds, self._attrs(inst))

    def _observe_connections(self, options: CallbackOptions):
        for inst in self._running_instances():
            count = len(inst.extra.get("network", []))
            yield Observation(count, self._attrs(inst))

    def _observe_children(self, options: CallbackOptions):
        for inst in self._running_instances():
            tree = inst.extra.get("process_tree", {})
            yield Observation(tree.get("child_count", 0), self._attrs(inst))

    def _observe_tree_cpu(self, options: CallbackOptions):
        for inst in self._running_instances():
            tree = inst.extra.get("process_tree", {})
            yield Observation(tree.get("tree_cpu_percent", 0.0), self._attrs(inst))

    def _observe_tree_memory(self, options: CallbackOptions):
        for inst in self._running_instances():
            tree = inst.extra.get("process_tree", {})
            yield Observation(tree.get("tree_memory_mb", 0.0), self._attrs(inst))

    def _observe_running_count(self, options: CallbackOptions):
        yield Observation(len(self._running_instances()))

    # --- Helpers ---

    @staticmethod
    def _get_version() -> str:
        try:
            return pkg_version("riva")
        except Exception:
            return "0.0.0"
