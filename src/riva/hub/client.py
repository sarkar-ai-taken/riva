"""Hub ping client — fire-and-forget telemetry."""

from __future__ import annotations

import json
import logging
import platform
import threading
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.agents.base import AgentInstance

logger = logging.getLogger(__name__)

_GEO_URL = "http://ip-api.com/json/?fields=city,country,countryCode,lat,lon"
_TIMEOUT = 5  # seconds for both geo lookup and hub POST

# Map riva agent display names → server slug
_AGENT_SLUGS: dict[str, str] = {
    "claude code": "claude-code",
    "opencode": "opencode",
    "openclaw": "openclaw",
    "codex cli": "codex-cli",
    "gemini cli": "gemini-cli",
    "cursor": "cursor",
    "cline": "cline",
    "windsurf": "windsurf",
    "continue.dev": "continue-dev",
    "github copilot": "github-copilot",
    "langgraph": "langgraph",
    "crewai": "crewai",
    "autogen": "autogen",
}


def _agent_slug(name: str) -> str:
    return _AGENT_SLUGS.get(name.lower(), name.lower().replace(" ", "-"))


def _get_geo() -> dict:
    """Return city/country/lat/lon from ip-api.com, or empty dict on any error."""
    try:
        with urllib.request.urlopen(_GEO_URL, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
        return {
            "city": data.get("city", ""),
            "country": data.get("country", ""),
            "lat": data.get("lat", 0.0),
            "lon": data.get("lon", 0.0),
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


def _post(endpoint: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT):
        pass


def _do_ping(endpoint: str, agent_slugs: list[str]) -> None:
    """Send one POST per detected agent. Runs in a daemon thread — never raises."""
    try:
        from riva import __version__

        geo = _get_geo()
        os_str = _os_string()

        for slug in agent_slugs:
            payload = {
                "os": os_str,
                "city": geo.get("city", ""),
                "country": geo.get("country", ""),
                "lat": geo.get("lat", 0.0),
                "lon": geo.get("lon", 0.0),
                "agent": slug,
                "riva_version": __version__,
            }
            _post(endpoint, payload)
            logger.debug("Hub ping sent: %s @ %s", slug, geo.get("city", "?"))

    except Exception as exc:
        logger.debug("Hub ping failed (non-fatal): %s", exc)


def ping_hub(instances: list[AgentInstance]) -> None:
    """Fire-and-forget ping to the Riva Hub for each running agent.

    Reads consent + endpoint from hub config. No-ops if consent was not given.
    Runs in a daemon thread so it never blocks the caller.
    """
    from riva.hub.config import get_consent, get_endpoint

    if not get_consent():
        return

    slugs = list(dict.fromkeys(_agent_slug(inst.name) for inst in instances if inst.pid))
    if not slugs:
        return

    endpoint = get_endpoint()
    t = threading.Thread(target=_do_ping, args=(endpoint, slugs), daemon=True)
    t.start()


def ping_hub_manual(agents: list[str] | None = None) -> list[dict]:
    """Synchronous ping used by `riva ping` CLI command. Returns sent payloads."""
    from riva import __version__
    from riva.hub.config import get_endpoint
    from riva.agents.registry import get_default_registry
    from riva.core.monitor import ResourceMonitor

    endpoint = get_endpoint()
    geo = _get_geo()
    os_str = _os_string()

    if agents is None:
        registry = get_default_registry()
        monitor = ResourceMonitor(registry=registry)
        instances = monitor.scan_once()
        agents = list(dict.fromkeys(_agent_slug(inst.name) for inst in instances if inst.pid))

    sent = []
    for slug in agents:
        payload = {
            "os": os_str,
            "city": geo.get("city", ""),
            "country": geo.get("country", ""),
            "lat": geo.get("lat", 0.0),
            "lon": geo.get("lon", 0.0),
            "agent": slug,
            "riva_version": __version__,
        }
        _post(endpoint, payload)
        sent.append(payload)

    return sent
