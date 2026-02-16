"""OTel logs exporter — audit findings and lifecycle events as log records."""

from __future__ import annotations

import platform
from importlib.metadata import version as pkg_version
from typing import TYPE_CHECKING

from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource

if TYPE_CHECKING:
    from riva.core.audit import AuditResult
    from riva.otel.config import OTelConfig

# Map audit status to OTel severity numbers (per OTel spec)
_SEVERITY_MAP = {
    "pass": 9,  # INFO
    "warn": 13,  # WARN
    "fail": 17,  # ERROR
}

_SEVERITY_TEXT_MAP = {
    "pass": "INFO",
    "warn": "WARN",
    "fail": "ERROR",
}


class LogsExporter:
    """Exports Riva audit findings and lifecycle events as OTel log records."""

    def __init__(self, config: OTelConfig) -> None:
        from opentelemetry.exporter.otlp.proto.http._log_exporter import (
            OTLPLogExporter,
        )

        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.version": self._get_version(),
                "host.name": platform.node(),
            }
        )

        exporter = OTLPLogExporter(
            endpoint=f"{config.endpoint}/v1/logs",
            headers=config.headers or {},
        )
        self._logger_provider = LoggerProvider(resource=resource)
        self._logger_provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
        self._logger = self._logger_provider.get_logger("riva", self._get_version())

    def emit_audit_finding(self, result: AuditResult) -> None:
        """Emit an audit finding as an OTel log record."""
        from opentelemetry._logs import SeverityNumber

        severity_number = _SEVERITY_MAP.get(result.status, 9)
        severity_text = _SEVERITY_TEXT_MAP.get(result.status, "INFO")

        self._logger.emit(
            severity_number=SeverityNumber(severity_number),
            severity_text=severity_text,
            body=result.detail,
            attributes={
                "riva.audit.check": result.check,
                "riva.audit.status": result.status,
                "riva.audit.severity": result.severity,
                "riva.audit.category": result.category,
            },
        )

    def emit_lifecycle_event(self, event: str, **attrs: object) -> None:
        """Emit a lifecycle event (agent_detected, agent_stopped, scan_complete)."""
        from opentelemetry._logs import SeverityNumber

        agent_name = attrs.get("agent_name", "unknown")
        body = f"Agent {event}: {agent_name}"

        log_attrs: dict = {"riva.event": event}
        if agent_name != "unknown":
            log_attrs["riva.agent.name"] = agent_name
        if "pid" in attrs:
            log_attrs["process.pid"] = attrs["pid"]

        self._logger.emit(
            severity_number=SeverityNumber.INFO,
            severity_text="INFO",
            body=body,
            attributes=log_attrs,
        )

    def shutdown(self) -> None:
        self._logger_provider.shutdown()

    @staticmethod
    def _get_version() -> str:
        try:
            return pkg_version("riva")
        except Exception:
            return "0.0.0"
