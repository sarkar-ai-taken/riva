"""Push rolled-up fleet telemetry from this machine to a Riva Server.

This complements the heartbeat (agents + metrics) by sending the *summary*
tiers that light up the server dashboard's Security and Usage tabs:

* security findings  → ``POST /api/v1/security/findings``  (full — metadata only)
* usage rollups      → ``POST /api/v1/usage/rollups``      (per-day/model aggregates)

Design boundary (privacy): only metadata and aggregates leave the machine.
Security findings carry the check name / severity / short detail — never file
contents or secrets. Usage is per-day/agent/model counts — never per-call
prompts. Raw forensic transcripts are deliberately *not* sent by this reporter.

Data is collected in-process from Riva's own modules (``run_audit`` and the
agent registry) — no dependency on the local web UI. Authentication reuses the
client API key minted by ``/clients/register`` (the same credential the
heartbeat uses), stored in ``~/.riva/fleet-client.json``.
"""

from __future__ import annotations

import json
import logging
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".riva"
CLIENT_FILE = CONFIG_DIR / "fleet-client.json"
_TIMEOUT = 10


class FleetReportError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _post(url: str, payload: dict, api_key: str | None = None) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise FleetReportError(f"{url} -> HTTP {e.code}: {e.read().decode()[:200]}") from e
    except urllib.error.URLError as e:
        raise FleetReportError(f"{url} -> {e.reason}") from e


# ---------------------------------------------------------------------------
# Client credential (reused from / compatible with the heartbeat flow)
# ---------------------------------------------------------------------------


def load_client(
    server_url: str, machine_name: str, org_name: str, lat: float | None = None, lon: float | None = None
) -> str:
    """Return a client API key, registering the machine once if needed."""
    if CLIENT_FILE.exists():
        try:
            cfg = json.loads(CLIENT_FILE.read_text())
            if cfg.get("server_url") == server_url and cfg.get("api_key"):
                return cfg["api_key"]
        except (json.JSONDecodeError, OSError):
            pass

    resp = _post(
        f"{server_url}/api/v1/clients/register",
        {
            "machine_name": machine_name,
            "org_name": org_name,
            "latitude": lat,
            "longitude": lon,
        },
    )
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_FILE.write_text(
        json.dumps(
            {
                "server_url": server_url,
                "client_id": resp["client_id"],
                "api_key": resp["api_key"],
            }
        )
    )
    return resp["api_key"]


# ---------------------------------------------------------------------------
# In-process collectors (Riva internals — no web UI dependency)
# ---------------------------------------------------------------------------


def collect_security() -> tuple[str, list[dict]]:
    """Run the local security audit and return ``(scan_id, findings)``."""
    from riva.core.audit import run_audit

    results = run_audit()
    findings = [
        {
            "category": getattr(r, "category", None),
            "check": r.check,
            "severity": getattr(r, "severity", "info"),
            "status": r.status,
            "detail": r.detail,
        }
        for r in results
    ]
    scan_id = datetime.now(timezone.utc).strftime("scan-%Y%m%dT%H%M%SZ")
    return scan_id, findings


def collect_usage() -> list[dict]:
    """Build per-agent, per-day usage rollups from the agent registry.

    Tokens/sessions come from each detector's daily activity; the model is the
    agent's dominant model (by tokens) when known, else ``"all"``. This keeps
    the fleet totals correct (no double counting) while preserving a real
    per-day trend.
    """
    from riva.agents.registry import get_default_registry

    registry = get_default_registry()
    rollups: list[dict] = []
    for det in registry.detectors:
        try:
            if not det.is_installed():
                continue
            usage = det.parse_usage()
        except Exception:  # a single detector must not sink the whole report
            logger.debug("usage parse failed for %s", getattr(det, "agent_name", "?"), exc_info=True)
            continue
        if not usage:
            continue

        # Dominant model by total tokens, if any model stats exist.
        model = "all"
        if getattr(usage, "model_stats", None):
            model = max(usage.model_stats.items(), key=lambda kv: kv[1].usage.total_tokens)[0] or "all"

        for d in getattr(usage, "daily_activity", []):
            rollups.append(
                {
                    "day": d.date,
                    "agent": det.agent_name,
                    "model": model,
                    "total_tokens": int(getattr(d, "total_tokens", 0) or 0),
                    "session_count": int(getattr(d, "session_count", 0) or 0),
                }
            )
    return rollups


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def report_once(
    server_url: str, org_name: str, machine_name: str | None = None, lat: float | None = None, lon: float | None = None
) -> dict:
    """Collect security + usage in-process and push one round. Returns a summary."""
    machine_name = machine_name or socket.gethostname()
    key = load_client(server_url, machine_name, org_name, lat, lon)

    scan_id, findings = collect_security()
    sec_resp = _post(f"{server_url}/api/v1/security/findings", {"scan_id": scan_id, "findings": findings}, api_key=key)

    rollups = collect_usage()
    usage_resp = _post(f"{server_url}/api/v1/usage/rollups", {"rollups": rollups}, api_key=key)

    summary = {
        "security_findings": sec_resp.get("accepted", 0),
        "usage_rollups": usage_resp.get("accepted", 0),
    }
    logger.info("Fleet report pushed to %s: %s", server_url, summary)
    return summary
