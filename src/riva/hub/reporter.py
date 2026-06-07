"""Push current Riva metrics to a connected server.

A snapshot mirrors the public CLI's ``/api/agents`` + ``/api/stats`` shapes so
the server can re-serve them per-device under
``/api/v1/devices/{id}/{agents,stats,…}`` and the same WUI bundle works.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request

from riva.hub.config import get_device_id, get_device_token, get_server_url, is_connected

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_DEFAULT_INTERVAL = 30.0  # seconds


def _build_snapshot() -> dict:
    """Collect a metrics snapshot from the local Riva monitor + registry."""
    from riva import __version__
    from riva.agents.registry import get_default_registry
    from riva.core.monitor import ResourceMonitor
    from riva.utils.formatting import format_mb, format_uptime

    registry = get_default_registry()
    monitor = ResourceMonitor(registry=registry)
    instances = monitor.scan_once()

    agents = [
        {
            "name": inst.name,
            "status": inst.status.value,
            "pid": inst.pid,
            "cpu_percent": round(inst.cpu_percent, 1),
            "memory_mb": round(inst.memory_mb, 1),
            "memory_formatted": format_mb(inst.memory_mb),
            "uptime_seconds": round(inst.uptime_seconds, 1),
            "uptime_formatted": format_uptime(inst.uptime_seconds),
            "working_directory": inst.working_directory,
            "binary_path": inst.binary_path,
            "config_dir": inst.config_dir,
            "api_domain": inst.api_domain,
            "launched_by": inst.launched_by,
        }
        for inst in instances
    ]

    return {
        "riva_version": __version__,
        "timestamp": time.time(),
        "agents": agents,
    }


def report_once() -> dict:
    """Send a single snapshot to the configured server. Raises on failure."""
    if not is_connected():
        raise RuntimeError("not connected — run `riva connect <token>` first")

    base = get_server_url()
    device_id = get_device_id()
    token = get_device_token()
    snapshot = _build_snapshot()

    req = urllib.request.Request(
        f"{base}/devices/{device_id}/report",
        data=json.dumps(snapshot).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read() or b"{}")


def _loop(interval: float, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            report_once()
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            logger.debug("riva report failed (will retry): %s", e)
        except Exception:
            logger.exception("riva report unexpected error")
        stop.wait(interval)


def start_background(interval: float = _DEFAULT_INTERVAL) -> threading.Event:
    """Start a daemon thread that pushes snapshots every *interval* seconds.

    Returns an Event that, when set, asks the loop to stop.
    """
    stop = threading.Event()
    t = threading.Thread(target=_loop, args=(interval, stop), daemon=True)
    t.start()
    return stop
