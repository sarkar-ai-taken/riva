"""Flask web dashboard for Riva."""

from __future__ import annotations

import json
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

# Simple time-based cache for expensive endpoints
_stats_cache: dict[str, tuple[float, object]] = {}
_CACHE_TTL = 30.0  # seconds


def _get_monitor() -> ResourceMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ResourceMonitor()
    return _monitor


def _get_registry() -> AgentRegistry:
    global _registry
    if _registry is None:
        _registry = get_default_registry()
    return _registry


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
            agents.append({
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
            })
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
                agents.append({
                    "name": det.agent_name,
                    "binaries": det.binary_names,
                    "config_dir": str(det.config_dir),
                    "config_dir_exists": det.config_dir.exists(),
                    "api_domain": det.api_domain,
                    "installed": det.is_installed(),
                })
            return agents
        return jsonify({"agents": _cached("registry", _fetch)})

    @app.route("/api/config")
    def api_config():
        def _fetch():
            registry = _get_registry()
            configs = []
            for det in registry.detectors:
                if not det.is_installed():
                    continue
                parsed = det.parse_config()
                configs.append({
                    "name": det.agent_name,
                    "config": parsed,
                })
            return configs
        return jsonify({"configs": _cached("config", _fetch)})

    return app


def run_server(host: str = "127.0.0.1", port: int = 8585, auth_token: str | None = None) -> None:
    """Create the app, start the monitor, and run Flask."""
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
