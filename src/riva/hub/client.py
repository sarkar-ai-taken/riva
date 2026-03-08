"""Hub ping client — fire-and-forget telemetry."""

from __future__ import annotations

import json
import logging
import platform
import threading
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.agents.base import AgentInstance

logger = logging.getLogger(__name__)

_GEO_URL = "http://ip-api.com/json/?fields=city,country,countryCode"
_TIMEOUT = 5  # seconds for both geo lookup and hub POST


def _get_geo() -> dict[str, str]:
    """Return city/country from ip-api.com, or empty dict on any error."""
    try:
        with urllib.request.urlopen(_GEO_URL, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
        return {
            "city": data.get("city", ""),
            "country": data.get("country", ""),
            "country_code": data.get("countryCode", ""),
        }
    except Exception:
        return {}


def _os_string() -> str:
    system = platform.system()
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    if system == "Linux":
        try:
            import distro  # type: ignore[import-untyped]
            return f"Linux {distro.name()} {distro.version()}"
        except ImportError:
            return f"Linux {platform.release()}"
    return f"{system} {platform.release()}"


def _do_ping(endpoint: str, client_id: str, agents: list[str]) -> None:
    """Run in a daemon thread — never raises."""
    try:
        from riva import __version__

        geo = _get_geo()
        payload = {
            "client_id": client_id,
            "riva_version": __version__,
            "os": _os_string(),
            "arch": platform.machine(),
            "agents": agents,
            "ts": datetime.now(timezone.utc).isoformat(),
            **geo,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT):
            pass
        logger.debug("Hub ping sent: %s agents, %s", len(agents), geo.get("city", "?"))
    except Exception as exc:
        logger.debug("Hub ping failed (non-fatal): %s", exc)


def ping_hub(instances: list[AgentInstance]) -> None:
    """Fire-and-forget ping to the Riva Hub.

    Reads consent + endpoint from hub config. No-ops if consent was not given.
    Runs in a daemon thread so it never blocks the caller.
    """
    from riva.hub.config import get_client_id, get_consent, get_endpoint

    if not get_consent():
        return

    agent_names = [inst.name for inst in instances if inst.pid]
    endpoint = get_endpoint()
    client_id = get_client_id()

    t = threading.Thread(target=_do_ping, args=(endpoint, client_id, agent_names), daemon=True)
    t.start()
