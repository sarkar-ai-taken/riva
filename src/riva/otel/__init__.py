"""OpenTelemetry exporter for Riva — optional integration.

Install with: ``pip install riva[otel]``
"""

from __future__ import annotations


def is_available() -> bool:
    """Return True if the opentelemetry SDK is importable."""
    try:
        import opentelemetry.sdk  # noqa: F401

        return True
    except ImportError:
        return False


# Re-export the main exporter class with a safe guard so that importing
# ``riva.otel`` never fails even when the OTel SDK is absent.
try:
    from riva.otel.exporter import RivaOTelExporter  # noqa: F401
except ImportError:
    RivaOTelExporter = None  # type: ignore[assignment,misc]

__all__ = ["is_available", "RivaOTelExporter"]
