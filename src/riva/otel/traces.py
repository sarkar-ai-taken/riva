"""OTel traces exporter — forensic sessions as span trees."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from importlib.metadata import version as pkg_version
from typing import TYPE_CHECKING

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import StatusCode

if TYPE_CHECKING:
    from riva.core.forensic import ForensicSession
    from riva.otel.config import OTelConfig


def _iso_to_ns(iso_str: str | None) -> int | None:
    """Convert an ISO-8601 timestamp string to nanoseconds since epoch."""
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1e9)
    except (ValueError, TypeError):
        return None


class TracesExporter:
    """Exports forensic sessions as OTel trace span trees."""

    def __init__(self, config: OTelConfig) -> None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.version": self._get_version(),
                "host.name": platform.node(),
            }
        )

        exporter = OTLPSpanExporter(
            endpoint=f"{config.endpoint}/v1/traces",
            headers=config.headers or {},
        )
        self._tracer_provider = TracerProvider(resource=resource)
        self._tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
        self._tracer = self._tracer_provider.get_tracer("riva", self._get_version())

    def export_session(self, session: ForensicSession) -> None:
        """Export a single forensic session as a span tree."""
        session_name = f"session:{session.slug or (session.session_id[:12])}"
        session_start = _iso_to_ns(session.timestamp_start)
        session_end = _iso_to_ns(session.timestamp_end)

        with self._tracer.start_as_current_span(
            name=session_name,
            start_time=session_start,
            end_on_exit=False,
        ) as root_span:
            root_span.set_attributes(
                {
                    "riva.session.id": session.session_id,
                    "riva.session.slug": session.slug or "",
                    "riva.session.project": session.project or "",
                    "gen_ai.system": session.agent,
                    "gen_ai.request.model": session.model or "",
                    "riva.session.turns": len(session.turns),
                    "riva.session.total_tokens": session.total_tokens,
                    "riva.session.efficiency": session.efficiency,
                    "riva.session.dead_ends": session.dead_end_count,
                    "riva.session.files_read": session.total_files_read,
                    "riva.session.files_written": session.total_files_written,
                }
            )

            for turn in session.turns:
                self._export_turn(turn)

            if session_end:
                root_span.end(end_time=session_end)
            else:
                root_span.end()

    def _export_turn(self, turn) -> None:
        """Export a single turn as a child span with action grandchildren."""
        turn_start = _iso_to_ns(turn.timestamp_start)
        turn_end = _iso_to_ns(turn.timestamp_end)

        with self._tracer.start_as_current_span(
            name=f"turn:{turn.index}",
            start_time=turn_start,
            end_on_exit=False,
        ) as turn_span:
            attrs: dict = {
                "gen_ai.usage.input_tokens": turn.tokens_in,
                "gen_ai.usage.output_tokens": turn.tokens_out,
                "riva.turn.actions": len(turn.actions),
                "riva.turn.is_dead_end": turn.is_dead_end,
                "riva.turn.files_read": turn.files_read,
                "riva.turn.files_written": turn.files_written,
            }
            if turn.model:
                attrs["gen_ai.request.model"] = turn.model
            turn_span.set_attributes(attrs)

            if turn.is_dead_end:
                turn_span.set_status(StatusCode.ERROR, "dead_end")

            for action in turn.actions:
                self._export_action(action, turn_start)

            if turn_end:
                turn_span.end(end_time=turn_end)
            else:
                turn_span.end()

    def _export_action(self, action, parent_start_ns: int | None) -> None:
        """Export a single action as a grandchild span."""
        action_start = _iso_to_ns(action.timestamp) if action.timestamp else parent_start_ns

        with self._tracer.start_as_current_span(
            name=f"action:{action.tool_name}",
            start_time=action_start,
            end_on_exit=False,
        ) as action_span:
            action_span.set_attributes(
                {
                    "riva.action.tool": action.tool_name,
                    "riva.action.success": action.success,
                    "riva.action.files": action.files_touched,
                }
            )
            if not action.success:
                action_span.set_status(StatusCode.ERROR, "action_failed")

            # Calculate end time from duration if available
            if action_start and action.duration_ms:
                action_end = action_start + int(action.duration_ms * 1e6)
                action_span.end(end_time=action_end)
            else:
                action_span.end()

    def export_sessions(self, sessions: list[ForensicSession]) -> None:
        """Batch export multiple sessions."""
        for session in sessions:
            self.export_session(session)

    def shutdown(self) -> None:
        self._tracer_provider.shutdown()

    @staticmethod
    def _get_version() -> str:
        try:
            return pkg_version("riva")
        except Exception:
            return "0.0.0"
