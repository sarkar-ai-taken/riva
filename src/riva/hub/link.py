"""Link this machine to a remote Riva Server (self-hosted / AWS-deployed).

This is a distinct flow from the older device-token registration in
``riva/hub/connect.py`` + ``riva/hub/reporter.py``. Where that flow mints a
long-lived *device* credential, this "link" flow pairs the local tool with a
multi-tenant Riva Server and stores a per-tenant API key.

The pairing handshake:

1. ``POST {server_url}/link``          → ``{pairing_token, code, approve_url, ...}``
2. user approves on the server (or the server auto-approves)
3. ``POST {server_url}/link/redeem``   → ``{tenant_id, api_key, server_url}``

Once linked we persist ``{server_url, tenant_id, api_key}`` to
``~/.riva/server-link.json`` and can:

* register agents:  ``POST {server_url}/tenants/{tenant_id}/agents``
* heartbeat status: ``POST {server_url}/tenants/{tenant_id}/status`` (every 30s)

All requests use the standard library only (``urllib``) — no new deps — and
authenticate with ``Authorization: Bearer {api_key}``.
"""

from __future__ import annotations

import json
import logging
import platform
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.core.usage_stats import ModelStats

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config storage — ~/.riva/server-link.json
# ---------------------------------------------------------------------------

CONFIG_DIR = Path.home() / ".riva"
CONFIG_FILE = CONFIG_DIR / "server-link.json"

_TIMEOUT = 10  # seconds for one-shot API calls
DEFAULT_HEARTBEAT_INTERVAL = 30.0  # seconds


class LinkError(RuntimeError):
    """Raised when a link/redeem/heartbeat request fails."""


@dataclass
class LinkConfig:
    """Persisted server-link credentials."""

    server_url: str
    tenant_id: str
    api_key: str
    linked_at: float = 0.0
    last_synced: float = 0.0
    # Roll-up cursors — how far local data has been pushed to the server.
    audit_cursor: int = 0  # audit.jsonl lines already ingested server-side
    forensics_synced_at: float = 0.0  # only sessions modified after this are re-sent
    usage_synced_at: float = 0.0  # last usage-rollup push (hourly cadence)
    security_synced_at: float = 0.0  # last security-scan push (hourly cadence)
    # Cached approximate location (geo-IP, consent-gated) for the server map.
    geo_lat: float | None = None
    geo_lon: float | None = None
    geo_at: float = 0.0

    def redacted(self) -> dict:
        """Dict view safe to show in a UI (api_key masked)."""
        key = self.api_key or ""
        masked = (key[:4] + "…" + key[-4:]) if len(key) > 8 else "••••"
        return {
            "server_url": self.server_url,
            "tenant_id": self.tenant_id,
            "api_key_masked": masked,
            "linked_at": self.linked_at,
            "last_synced": self.last_synced,
        }


def load_config() -> LinkConfig | None:
    """Return the stored link config, or None if not linked / unreadable."""
    if not CONFIG_FILE.is_file():
        return None
    # A corrupt file (bad JSON, wrong-typed values, bad encoding) counts as
    # unlinked rather than raising into every caller.
    try:
        raw = json.loads(CONFIG_FILE.read_text())
        server_url = raw.get("server_url")
        tenant_id = raw.get("tenant_id")
        api_key = raw.get("api_key")
        if not (server_url and tenant_id and api_key):
            return None
        return LinkConfig(
            server_url=server_url.rstrip("/"),
            tenant_id=tenant_id,
            api_key=api_key,
            linked_at=float(raw.get("linked_at", 0.0) or 0.0),
            last_synced=float(raw.get("last_synced", 0.0) or 0.0),
            audit_cursor=int(raw.get("audit_cursor", 0) or 0),
            forensics_synced_at=float(raw.get("forensics_synced_at", 0.0) or 0.0),
            usage_synced_at=float(raw.get("usage_synced_at", 0.0) or 0.0),
            security_synced_at=float(raw.get("security_synced_at", 0.0) or 0.0),
            geo_lat=raw.get("geo_lat"),
            geo_lon=raw.get("geo_lon"),
            geo_at=float(raw.get("geo_at", 0.0) or 0.0),
        )
    except (OSError, TypeError, ValueError, AttributeError):
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError.
        return None


def save_config(config: LinkConfig) -> None:
    """Persist link config to ~/.riva/server-link.json (0600 perms)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(asdict(config), indent=2) + "\n")
    try:
        CONFIG_FILE.chmod(0o600)  # contains an API key
    except OSError:
        pass


def clear_config() -> bool:
    """Delete the stored link config. Returns True if a file was removed."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        return True
    return False


def unlink(revoke: bool = True) -> bool:
    """Unlink from the server: revoke our API key (best-effort), drop credentials.

    Revocation invalidates the key server-side so a leaked copy of the old
    credentials can't keep pushing data. Server-side data is retained.
    """
    config = load_config()
    if revoke and config is not None:
        try:
            _request(
                "POST",
                f"{_api_base(config.server_url)}/link/revoke",
                {},
                api_key=config.api_key,
            )
        except LinkError as e:
            logger.debug("key revocation failed (clearing local credentials anyway): %s", e)
    return clear_config()


def is_linked() -> bool:
    return load_config() is not None


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _machine_name() -> str:
    name = socket.gethostname() or platform.node() or "unknown"
    return name.split(".")[0]


def _machine_id() -> str:
    """Stable machine identity — the hub's client_id UUID (survives hostname
    changes and disambiguates machines that share a hostname)."""
    try:
        from riva.hub.config import get_client_id

        return get_client_id()
    except Exception:
        return ""


def _os_string() -> str:
    system = platform.system()
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    return f"{system} {platform.release()}"


def _request(method: str, url: str, payload: dict | None = None, api_key: str | None = None) -> dict:
    """Issue a JSON HTTP request and return the parsed response dict.

    Raises ``LinkError`` on transport errors or non-2xx responses.
    """
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise LinkError(f"server returned {e.code}: {detail}") from e
    except (urllib.error.URLError, OSError) as e:
        raise LinkError(f"cannot reach {url}: {e}") from e
    except json.JSONDecodeError as e:
        raise LinkError(f"malformed response from {url}: {e}") from e


# ---------------------------------------------------------------------------
# Pairing handshake
# ---------------------------------------------------------------------------


def _api_base(server_url: str) -> str:
    """Return the API base for a server URL, appending ``/api/v1`` if absent."""
    base = server_url.rstrip("/")
    if "/api/" in base:
        return base
    return f"{base}/api/v1"


def start_link(server_url: str) -> dict:
    """Begin pairing: ``POST {api_base}/pair`` (unauthenticated device flow).

    Returns the server's response, expected to contain a ``pairing_token`` plus
    a human-facing ``code`` and ``approve_url`` for browser approval.
    """
    payload = {
        "machine_name": _machine_name(),
        "os": _os_string(),
    }
    data = _request("POST", f"{_api_base(server_url)}/pair", payload)
    if not data.get("pairing_token"):
        raise LinkError(f"server did not return a pairing_token: {data}")
    return data


def redeem_link(server_url: str, pairing_token: str) -> LinkConfig:
    """Exchange a pairing token for tenant credentials and persist them.

    ``POST {api_base}/link/redeem`` → ``{tenant_id, api_key, server_url?}``.
    While the pairing code is still unapproved the server answers 425
    (authorization pending), surfaced as a retryable ``LinkError``.
    """
    base = server_url.rstrip("/")
    data = _request(
        "POST",
        f"{_api_base(server_url)}/link/redeem",
        {"pairing_token": pairing_token, "tool_name": _machine_name()},
    )

    tenant_id = data.get("tenant_id")
    api_key = data.get("api_key")
    if not tenant_id or not api_key:
        raise LinkError(f"redeem response missing tenant_id/api_key: {data}")

    # Server may hand back a canonical URL (e.g. behind a load balancer).
    resolved_url = (data.get("server_url") or base).rstrip("/")

    config = LinkConfig(
        server_url=resolved_url,
        tenant_id=tenant_id,
        api_key=api_key,
        linked_at=time.time(),
    )
    save_config(config)
    return config


def link(server_url: str, poll: bool = True, poll_timeout: float = 120.0) -> LinkConfig:
    """Full link flow: start pairing, then redeem.

    If the server auto-approves, ``/link/redeem`` succeeds immediately. When
    *poll* is True and the token is not yet approved, keep retrying redeem until
    it succeeds or *poll_timeout* elapses.
    """
    started = start_link(server_url)
    token = started["pairing_token"]

    deadline = time.time() + poll_timeout
    last_err: LinkError | None = None
    while True:
        try:
            return redeem_link(server_url, token)
        except LinkError as e:
            last_err = e
            if not poll or time.time() >= deadline:
                raise
            time.sleep(2.0)
    # unreachable, but keeps type checkers happy
    raise last_err  # pragma: no cover


# ---------------------------------------------------------------------------
# Snapshot / agent registration / heartbeat
# ---------------------------------------------------------------------------


def _collect_agents() -> list[dict]:
    """Collect the local agent board as a list of plain dicts."""
    from riva.agents.registry import get_default_registry
    from riva.core.monitor import ResourceMonitor
    from riva.utils.formatting import format_mb, format_uptime

    registry = get_default_registry()
    monitor = ResourceMonitor(registry=registry)
    instances = monitor.scan_once()

    return [
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
            "api_domain": inst.api_domain,
        }
        for inst in instances
    ]


def _collect_leases() -> list[dict]:
    """Collect active resource leases from the local harness board, if present.

    Riva ships without the agent-harness-board daemon by default, so this is a
    best-effort hook: returns [] when no board integration is available.
    """
    try:  # pragma: no cover - optional integration
        from riva.core.board import get_active_leases  # type: ignore

        return list(get_active_leases())
    except Exception:
        return []


def build_status_payload() -> dict:
    """Build the ``{agents, leases, health}`` snapshot sent on each heartbeat."""
    from riva import __version__

    agents = _collect_agents()
    running = sum(1 for a in agents if a.get("status") == "running")
    return {
        "agents": agents,
        "leases": _collect_leases(),
        "health": {
            "riva_version": __version__,
            "machine_name": _machine_name(),
            "machine_id": _machine_id(),
            "os": _os_string(),
            "agent_count": len(agents),
            "running_count": running,
            "timestamp": time.time(),
        },
    }


def register_agent(agent: dict, config: LinkConfig | None = None) -> dict:
    """Register a single local agent with the server.

    ``POST {server_url}/tenants/{tenant_id}/agents``.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")
    url = f"{_api_base(config.server_url)}/tenants/{config.tenant_id}/agents"
    # Machine identity keeps registration on the same device row the heartbeat
    # writes to — without it the server would file the agent under no device.
    payload = {
        **agent,
        "machine_name": _machine_name(),
        "machine_id": _machine_id(),
    }
    return _request("POST", url, payload, api_key=config.api_key)


def register_agents(config: LinkConfig | None = None) -> int:
    """Register every currently-detected local agent. Returns count registered."""
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")
    agents = _collect_agents()
    count = 0
    for agent in agents:
        try:
            register_agent(agent, config=config)
            count += 1
        except LinkError as e:
            logger.debug("agent registration failed for %s: %s", agent.get("name"), e)
    return count


_GEO_TTL = 7 * 24 * 3600.0  # refresh the geo-IP lookup weekly


def _geo_location(config: LinkConfig) -> tuple[float, float] | None:
    """Approximate (lat, lon) for the server map. Consent-gated and cached.

    Uses the same geo-IP source and consent flag as the community ping; when
    the user has not consented to sharing location, returns None and nothing
    is sent.
    """
    try:
        from riva.hub.config import get_consent

        if get_consent() is not True:
            return None
    except Exception:
        return None

    now = time.time()
    if config.geo_lat is not None and config.geo_lon is not None and now - config.geo_at < _GEO_TTL:
        return (config.geo_lat, config.geo_lon)

    try:
        from riva.hub.client import _get_geo

        geo = _get_geo()
    except Exception:
        geo = {}
    lat, lon = geo.get("lat"), geo.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and (lat or lon):
        config.geo_lat, config.geo_lon, config.geo_at = float(lat), float(lon), now
        save_config(config)
        return (config.geo_lat, config.geo_lon)
    return None


def send_heartbeat(config: LinkConfig | None = None) -> dict:
    """Send one status heartbeat to the server. Raises ``LinkError`` on failure.

    ``POST {server_url}/tenants/{tenant_id}/status``.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")
    url = f"{_api_base(config.server_url)}/tenants/{config.tenant_id}/status"
    payload = build_status_payload()
    location = _geo_location(config)
    if location:
        payload["health"]["latitude"], payload["health"]["longitude"] = location
    result = _request("POST", url, payload, api_key=config.api_key)
    # Stamp the config object we were handed, not a fresh copy from disk: the
    # audit/forensics steps that follow in sync_once persist *this* object's
    # cursors, and saving it with a stale last_synced would clobber the stamp.
    config.last_synced = time.time()
    save_config(config)
    return result


# ---------------------------------------------------------------------------
# Audit + forensics roll-up
# ---------------------------------------------------------------------------

_AUDIT_BATCH_LIMIT = 500  # max audit entries per sync
_FORENSICS_BATCH_LIMIT = 100  # max session summaries per sync


def send_audit(config: LinkConfig | None = None) -> int:
    """Push new local audit-log entries since the stored cursor.

    ``POST {api_base}/tenants/{tenant_id}/audit``. Returns entries ingested.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")

    from riva.core.audit_log import AuditLog

    log_file = AuditLog().log_file
    if not log_file.is_file():
        return 0

    entries: list[dict] = []
    line_no = 0
    try:
        with open(log_file, encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                if line_no <= config.audit_cursor or not line.strip():
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(entries) >= _AUDIT_BATCH_LIMIT:
                    break
    except OSError as e:
        raise LinkError(f"cannot read audit log: {e}") from e

    if not entries:
        return 0

    url = f"{_api_base(config.server_url)}/tenants/{config.tenant_id}/audit"
    result = _request(
        "POST",
        url,
        {"machine_name": _machine_name(), "machine_id": _machine_id(), "entries": entries},
        api_key=config.api_key,
    )
    # Advance the cursor past everything we sent (server dedupes by event_id).
    config.audit_cursor = max(config.audit_cursor, line_no)
    save_config(config)
    return int(result.get("ingested", len(entries)))


def send_forensics(config: LinkConfig | None = None) -> int:
    """Push forensic session summaries modified since the last forensics sync.

    ``POST {api_base}/tenants/{tenant_id}/forensics``. Returns sessions sent.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")

    try:
        from riva.core.forensic import discover_sessions

        sessions = discover_sessions(limit=_FORENSICS_BATCH_LIMIT)
    except Exception:
        return 0

    def _mtime(s: dict) -> float:
        try:
            from datetime import datetime as _dt

            return _dt.fromisoformat(s.get("modified_time", "")).timestamp()
        except (ValueError, TypeError):
            return 0.0

    fresh = [s for s in sessions if _mtime(s) > config.forensics_synced_at]
    if not fresh:
        return 0

    # Deep-parse each fresh session so the server gets real metrics
    # (tokens, actions, files, dead ends) rather than zeroed summaries.
    from riva.core.forensic import parse_session

    payload_sessions: list[dict] = []
    for s in fresh:
        entry = dict(s)
        try:
            parsed = parse_session(s["file_path"], max_lines=20000)
            entry.update(
                {
                    "slug": parsed.slug or s.get("slug"),
                    "agent": parsed.agent,
                    "model": parsed.model,
                    "git_branch": parsed.git_branch,
                    "timestamp_start": parsed.timestamp_start or s.get("first_timestamp"),
                    "timestamp_end": parsed.timestamp_end,
                    "total_tokens": parsed.total_tokens,
                    "total_actions": parsed.total_actions,
                    "total_files_read": len(parsed.all_files_read),
                    "total_files_written": len(parsed.all_files_written),
                    "dead_end_count": parsed.dead_end_count,
                    "efficiency": round(parsed.efficiency, 4),
                }
            )
        except Exception:
            logger.debug("forensic parse failed for %s; sending light summary", s.get("session_id"))
        payload_sessions.append(entry)

    url = f"{_api_base(config.server_url)}/tenants/{config.tenant_id}/forensics"
    _request(
        "POST",
        url,
        {"machine_name": _machine_name(), "machine_id": _machine_id(), "sessions": payload_sessions},
        api_key=config.api_key,
    )
    config.forensics_synced_at = max(_mtime(s) for s in fresh)
    save_config(config)
    return len(fresh)


_SLOW_SYNC_INTERVAL = 3600.0  # usage/security push at most hourly


def send_usage_rollups(config: LinkConfig | None = None) -> int:
    """Push per-agent, per-model token rollups from local usage data.

    ``POST {api_base}/usage/rollups``. The server replaces this machine's prior
    rollups, so lifetime totals are pushed as a single "all-time" day grain.
    Returns rollup rows sent.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")

    from riva.agents.registry import get_default_registry

    rollups: list[dict] = []
    for det in get_default_registry().detectors:
        try:
            if not det.is_installed():
                continue
            usage = det.parse_usage()
        except Exception:
            continue
        if usage is None or not usage.total_tokens:
            continue
        sessions_left = usage.total_sessions
        model_items: list[tuple[str, ModelStats | None]] = list(usage.model_stats.items())
        if not model_items:
            model_items = [("unknown", None)]
        for model_id, ms in model_items:
            tokens = ms.usage if ms is not None else None
            rollups.append(
                {
                    "day": "all-time",
                    "agent": det.agent_name,
                    "model": model_id,
                    "input_tokens": tokens.input_tokens if tokens else 0,
                    "output_tokens": tokens.output_tokens if tokens else 0,
                    "total_tokens": tokens.total_tokens if tokens else usage.total_tokens,
                    "session_count": sessions_left,  # attributed to the first row only
                }
            )
            sessions_left = 0

    if not rollups:
        return 0

    url = f"{_api_base(config.server_url)}/usage/rollups"
    _request(
        "POST",
        url,
        {"machine_name": _machine_name(), "machine_id": _machine_id(), "rollups": rollups},
        api_key=config.api_key,
    )
    config.usage_synced_at = time.time()
    save_config(config)
    return len(rollups)


def send_security_findings(config: LinkConfig | None = None) -> int:
    """Run the local security audit and push the findings.

    ``POST {api_base}/security/findings``. The server keeps only the latest
    scan per machine. Returns findings sent.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")

    from riva.core.audit import run_audit

    try:
        results = run_audit(include_network=False)
    except Exception:
        return 0
    findings = [
        {
            "category": r.category,
            "check": r.check,
            "severity": r.severity,
            "status": r.status,
            "detail": r.detail,
        }
        for r in results
    ]
    if not findings:
        return 0

    url = f"{_api_base(config.server_url)}/security/findings"
    scan_id = f"scan-{int(time.time())}"
    _request(
        "POST",
        url,
        {
            "machine_name": _machine_name(),
            "machine_id": _machine_id(),
            "scan_id": scan_id,
            "findings": findings,
        },
        api_key=config.api_key,
    )
    config.security_synced_at = time.time()
    save_config(config)
    return len(findings)


def sync_once(config: LinkConfig | None = None) -> dict:
    """One full roll-up: heartbeat (agents) + audit batch + forensic sessions.

    The heartbeat failing raises; audit/forensics failures are best-effort so a
    single bad batch can't wedge the status sync.
    """
    config = config or load_config()
    if config is None:
        raise LinkError("not linked — run `riva link <server_url>` first")

    heartbeat = send_heartbeat(config)
    result = {"heartbeat": heartbeat, "audit_ingested": 0, "forensic_sessions": 0}
    try:
        result["audit_ingested"] = send_audit(config)
    except LinkError as e:
        logger.debug("audit push failed (will retry next sync): %s", e)
    try:
        result["forensic_sessions"] = send_forensics(config)
    except LinkError as e:
        logger.debug("forensics push failed (will retry next sync): %s", e)

    # Usage + security are heavier scans — push at most hourly.
    now = time.time()
    result["usage_rollups"] = 0
    result["security_findings"] = 0
    if now - config.usage_synced_at >= _SLOW_SYNC_INTERVAL:
        try:
            result["usage_rollups"] = send_usage_rollups(config)
        except LinkError as e:
            logger.debug("usage push failed (will retry next sync): %s", e)
    if now - config.security_synced_at >= _SLOW_SYNC_INTERVAL:
        try:
            result["security_findings"] = send_security_findings(config)
        except LinkError as e:
            logger.debug("security push failed (will retry next sync): %s", e)
    return result


def start_heartbeat(interval: float = DEFAULT_HEARTBEAT_INTERVAL) -> threading.Event:
    """Start a daemon thread that heartbeats every *interval* seconds.

    No-op-safe: if the tool is not linked the loop simply idles and re-checks,
    so it can be started once and survive link/unlink toggles. Returns an Event
    that stops the loop when set.
    """
    stop = threading.Event()

    def _loop() -> None:
        while not stop.is_set():
            if is_linked():
                try:
                    sync_once()
                    logger.debug("sync sent (agents + audit + forensics)")
                except LinkError as e:
                    logger.debug("sync failed (will retry): %s", e)
                except Exception:
                    logger.exception("sync unexpected error")
            stop.wait(interval)

    t = threading.Thread(target=_loop, name="riva-heartbeat", daemon=True)
    t.start()
    return stop
