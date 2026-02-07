"""Flask web dashboard for Riva."""

from __future__ import annotations

import time
from pathlib import Path

from flask import Flask, jsonify, request

from riva.agents.base import AgentStatus
from riva.agents.registry import AgentRegistry, get_default_registry
from riva.core.env_scanner import scan_env_vars
from riva.core.monitor import ResourceMonitor
from riva.utils.formatting import format_mb, format_number, format_uptime

# ---------------------------------------------------------------------------
# Module-level singletons (initialised lazily by run_server / create_app)
# ---------------------------------------------------------------------------

_monitor: ResourceMonitor | None = None
_registry: AgentRegistry | None = None
_storage = None  # RivaStorage | None

# Simple time-based cache for expensive endpoints
_stats_cache: dict[str, tuple[float, object]] = {}
_CACHE_TTL = 30.0  # seconds


def _get_monitor() -> ResourceMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ResourceMonitor(storage=_storage)
    return _monitor


def _get_registry() -> AgentRegistry:
    global _registry
    if _registry is None:
        _registry = get_default_registry()
    return _registry


def _get_storage():
    global _storage
    if _storage is None:
        try:
            from riva.core.storage import RivaStorage

            _storage = RivaStorage()
        except Exception:
            pass
    return _storage


def _cached(key: str, fetch):
    """Return cached value or call *fetch* and cache for ``_CACHE_TTL`` seconds."""
    now = time.time()
    if key in _stats_cache:
        ts, value = _stats_cache[key]
        if now - ts < _CACHE_TTL:
            return value
    value = fetch()
    _stats_cache[key] = (now, value)
    return value


# ---------------------------------------------------------------------------
# Flask app factory
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).parent / "static"


def create_app(auth_token: str | None = None) -> Flask:
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    if auth_token:

        @app.before_request
        def check_auth_token():
            if request.path.startswith("/api/"):
                auth_header = request.headers.get("Authorization", "")
                if auth_header != f"Bearer {auth_token}":
                    return jsonify({"error": "Unauthorized"}), 401

    # ---- HTML route -------------------------------------------------------

    @app.route("/")
    def index():
        index_path = STATIC_DIR / "index.html"
        return index_path.read_text(), 200, {"Content-Type": "text/html; charset=utf-8"}

    # ---- Fast-poll endpoints (2s) -----------------------------------------

    @app.route("/api/agents")
    def api_agents():
        monitor = _get_monitor()
        instances = monitor.instances
        agents = []
        for inst in instances:
            agents.append(
                {
                    "name": inst.name,
                    "status": inst.status.value,
                    "pid": inst.pid,
                    "binary_path": inst.binary_path,
                    "config_dir": inst.config_dir,
                    "api_domain": inst.api_domain,
                    "cpu_percent": round(inst.cpu_percent, 1),
                    "memory_mb": round(inst.memory_mb, 1),
                    "memory_formatted": format_mb(inst.memory_mb),
                    "uptime_seconds": round(inst.uptime_seconds, 1),
                    "uptime_formatted": format_uptime(inst.uptime_seconds),
                    "working_directory": inst.working_directory,
                    "parent_pid": inst.parent_pid,
                    "parent_name": inst.parent_name,
                    "launched_by": inst.launched_by,
                    "launcher": inst.extra.get("launcher"),
                    "sandbox": inst.extra.get("sandbox"),
                }
            )
        return jsonify({"agents": agents, "timestamp": time.time()})

    @app.route("/api/agents/history")
    def api_agents_history():
        monitor = _get_monitor()
        histories = monitor.histories
        result = {}
        for key, hist in histories.items():
            result[key] = {
                "agent_name": hist.agent_name,
                "pid": hist.pid,
                "cpu_history": hist.cpu_history,
                "memory_history": hist.memory_history,
            }
        return jsonify({"histories": result})

    # ---- Network endpoint -------------------------------------------------

    @app.route("/api/network")
    def api_network():
        monitor = _get_monitor()
        instances = monitor.instances
        result = []
        for inst in instances:
            if inst.status != AgentStatus.RUNNING or not inst.pid:
                continue
            network = inst.extra.get("network", [])
            result.append(
                {
                    "agent": inst.name,
                    "pid": inst.pid,
                    "connection_count": len(network),
                    "connections": network,
                }
            )
        return jsonify({"network": result, "timestamp": time.time()})

    # ---- Audit endpoint ---------------------------------------------------

    @app.route("/api/audit")
    def api_audit():
        def _fetch():
            from riva.core.audit import run_audit

            include_network = request.args.get("network", "false").lower() == "true"
            results = run_audit(include_network=include_network)

            # Persist to storage if available
            storage = _get_storage()
            if storage:
                for r in results:
                    try:
                        storage.record_audit_event(r.check, r.status, r.detail, r.severity)
                    except Exception:
                        pass

            return [
                {
                    "check": r.check,
                    "status": r.status,
                    "detail": r.detail,
                    "severity": r.severity,
                    "category": r.category,
                }
                for r in results
            ]

        return jsonify({"audit": _cached("audit", _fetch), "timestamp": time.time()})

    # ---- History endpoints ------------------------------------------------

    @app.route("/api/history")
    def api_history():
        storage = _get_storage()
        if not storage:
            return jsonify({"snapshots": [], "error": "Storage not available"})
        agent = request.args.get("agent")
        hours = float(request.args.get("hours", 1.0))
        snapshots = storage.get_snapshots(agent_name=agent, hours=hours)
        return jsonify({"snapshots": snapshots})

    @app.route("/api/network/history")
    def api_network_history():
        storage = _get_storage()
        if not storage:
            return jsonify({"connections": [], "error": "Storage not available"})
        hours = float(request.args.get("hours", 1.0))
        connections = storage.get_network_history(hours=hours)
        return jsonify({"connections": connections})

    # ---- Slow-poll endpoints (30s) ----------------------------------------

    @app.route("/api/stats")
    def api_stats():
        def _fetch():
            registry = _get_registry()
            stats = []
            for det in registry.detectors:
                installed = det.is_installed()
                if not installed:
                    continue
                inst = det.build_instance()
                usage = det.parse_usage()
                entry: dict = {
                    "name": det.agent_name,
                    "status": inst.status.value,
                    "total_tokens": 0,
                    "total_tokens_formatted": "0",
                    "total_sessions": 0,
                    "total_messages": 0,
                    "total_tool_calls": 0,
                    "time_range_start": None,
                    "time_range_end": None,
                    "models": {},
                    "top_tools": [],
                    "daily_activity": [],
                }
                if usage:
                    entry["total_tokens"] = usage.total_tokens
                    entry["total_tokens_formatted"] = format_number(usage.total_tokens)
                    entry["total_sessions"] = usage.total_sessions
                    entry["total_messages"] = usage.total_messages
                    entry["total_tool_calls"] = usage.total_tool_calls
                    entry["time_range_start"] = usage.time_range_start
                    entry["time_range_end"] = usage.time_range_end
                    entry["models"] = {
                        mid: {
                            "input_tokens": ms.usage.input_tokens,
                            "output_tokens": ms.usage.output_tokens,
                            "cache_read_input_tokens": ms.usage.cache_read_input_tokens,
                            "cache_creation_input_tokens": ms.usage.cache_creation_input_tokens,
                            "total_tokens": ms.usage.total_tokens,
                        }
                        for mid, ms in usage.model_stats.items()
                    }
                    entry["top_tools"] = [
                        {"tool_name": t.tool_name, "call_count": t.call_count, "last_used": t.last_used}
                        for t in usage.top_tools[:20]
                    ]
                    entry["daily_activity"] = [
                        {
                            "date": d.date,
                            "message_count": d.message_count,
                            "session_count": d.session_count,
                            "tool_call_count": d.tool_call_count,
                            "total_tokens": d.total_tokens,
                        }
                        for d in usage.daily_activity
                    ]
                stats.append(entry)
            return stats

        return jsonify({"stats": _cached("stats", _fetch)})

    @app.route("/api/env")
    def api_env():
        def _fetch():
            return scan_env_vars()

        return jsonify({"env_vars": _cached("env", _fetch)})

    @app.route("/api/registry")
    def api_registry():
        def _fetch():
            registry = _get_registry()
            agents = []
            for det in registry.detectors:
                agents.append(
                    {
                        "name": det.agent_name,
                        "binaries": det.binary_names,
                        "config_dir": str(det.config_dir),
                        "config_dir_exists": det.config_dir.exists(),
                        "api_domain": det.api_domain,
                        "installed": det.is_installed(),
                    }
                )
            return agents

        return jsonify({"agents": _cached("registry", _fetch)})

    # ---- Orphan endpoint ---------------------------------------------------

    @app.route("/api/orphans")
    def api_orphans():
        storage = _get_storage()
        if not storage:
            return jsonify({"orphans": [], "error": "Storage not available"})
        hours = float(request.args.get("hours", 24.0))
        show_all = request.args.get("all", "false").lower() == "true"
        orphans = storage.get_orphans(resolved=show_all, hours=hours)
        return jsonify({"orphans": orphans, "timestamp": time.time()})

    # ---- Timeline / Replay endpoints --------------------------------------

    @app.route("/api/timeline")
    def api_timeline():
        storage = _get_storage()
        if not storage:
            return jsonify({"buckets": [], "error": "Storage not available"})
        hours = float(request.args.get("hours", 1.0))
        bucket = int(request.args.get("bucket", 60))
        buckets = storage.get_timeline_summary(hours=hours, bucket_seconds=bucket)
        return jsonify({"buckets": buckets, "timestamp": time.time()})

    @app.route("/api/replay")
    def api_replay():
        storage = _get_storage()
        if not storage:
            return jsonify({"state": [], "error": "Storage not available"})
        t = request.args.get("t")
        if t is None:
            return jsonify({"state": [], "error": "Missing 't' parameter (unix timestamp)"}), 400
        try:
            ts = float(t)
        except ValueError:
            return jsonify({"state": [], "error": "Invalid timestamp"}), 400
        state = storage.get_state_at(ts)
        orphans = storage.get_orphans(resolved=False, hours=24.0)
        return jsonify({"state": state, "orphans": orphans, "timestamp": ts})

    @app.route("/api/config")
    def api_config():
        def _fetch():
            registry = _get_registry()
            configs = []
            for det in registry.detectors:
                if not det.is_installed():
                    continue
                parsed = det.parse_config()
                configs.append(
                    {
                        "name": det.agent_name,
                        "config": parsed,
                    }
                )
            return configs

        return jsonify({"configs": _cached("config", _fetch)})

    return app


def run_server(host: str = "127.0.0.1", port: int = 8585, auth_token: str | None = None) -> None:
    """Create the app, start the monitor, and run Flask."""
    # Initialize storage
    _get_storage()

    monitor = _get_monitor()
    monitor.start()
    try:
        app = create_app(auth_token=auth_token)
        app.run(host=host, port=port)
    finally:
        monitor.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8585)
    parser.add_argument("--auth-token", default=None)
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, auth_token=args.auth_token)
