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
            if request.path.startswith("/api/") or request.path.startswith("/otlp/"):
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

    # ---- Forensic endpoints -------------------------------------------------

    @app.route("/api/forensic/sessions")
    def api_forensic_sessions():
        def _fetch():
            from riva.core.forensic import discover_sessions

            project = request.args.get("project")
            limit = int(request.args.get("limit", 30))
            return discover_sessions(project_filter=project, limit=limit)

        return jsonify({"sessions": _cached("forensic_sessions", _fetch), "timestamp": time.time()})

    @app.route("/api/forensic/session/<identifier>")
    def api_forensic_session(identifier):
        from riva.core.forensic import parse_session, resolve_session

        path = resolve_session(identifier)
        if not path:
            return jsonify({"error": "Session not found"}), 404

        session = parse_session(path)

        def _fmt_duration(seconds):
            if not seconds:
                return None
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m{secs}s" if mins > 0 else f"{secs}s"

        timeline = []
        for turn in session.turns:
            entry = {
                "index": turn.index,
                "prompt": turn.prompt[:200],
                "timestamp_start": turn.timestamp_start,
                "timestamp_end": turn.timestamp_end,
                "duration": _fmt_duration(turn.duration_seconds),
                "tokens": turn.total_tokens,
                "is_dead_end": turn.is_dead_end,
                "actions": [
                    {
                        "tool_name": a.tool_name,
                        "input_summary": a.input_summary[:120],
                        "duration_ms": a.duration_ms,
                        "success": a.success,
                        "timestamp": a.timestamp,
                        "files": a.files_touched,
                    }
                    for a in turn.actions
                ],
            }
            timeline.append(entry)

        patterns = [
            {
                "pattern_type": p.pattern_type,
                "description": p.description,
                "turn_indices": p.turn_indices,
                "severity": p.severity,
            }
            for p in session.patterns
        ]

        decisions = []
        for turn in session.turns:
            if not turn.thinking or not turn.actions:
                continue
            decisions.append(
                {
                    "turn_index": turn.index,
                    "timestamp": turn.timestamp_start,
                    "actions": [a.tool_name for a in turn.actions[:8]],
                    "thinking_preview": turn.thinking[0][:300] if turn.thinking else "",
                    "files": turn.files_read + turn.files_written,
                    "is_dead_end": turn.is_dead_end,
                }
            )

        return jsonify(
            {
                "session": {
                    "session_id": session.session_id,
                    "slug": session.slug,
                    "project": session.project,
                    "model": session.model,
                    "git_branch": session.git_branch,
                    "timestamp_start": session.timestamp_start,
                    "timestamp_end": session.timestamp_end,
                    "duration": _fmt_duration(session.duration_seconds),
                    "turns": len(session.turns),
                    "actions": session.total_actions,
                    "tokens": session.total_tokens,
                    "files_read": session.total_files_read,
                    "files_written": session.total_files_written,
                    "dead_ends": session.dead_end_count,
                    "efficiency": round(session.efficiency, 2),
                    "files_modified": session.all_files_written,
                    "files_read_only": [f for f in session.all_files_read if f not in session.all_files_written],
                },
                "timeline": timeline,
                "patterns": patterns,
                "decisions": decisions,
            }
        )

    @app.route("/api/forensic/trends")
    def api_forensic_trends():
        def _fetch():
            from riva.core.forensic import compute_trends, discover_sessions, parse_session

            project = request.args.get("project")
            limit = int(request.args.get("limit", 20))
            session_list = discover_sessions(project_filter=project, limit=limit)

            parsed = []
            for s in session_list[:limit]:
                try:
                    parsed.append(parse_session(s["file_path"]))
                except Exception:
                    continue

            trends = compute_trends(parsed)
            # Convert top_tools tuples to dicts for JSON
            if trends.get("top_tools"):
                trends["top_tools"] = [{"tool_name": t[0], "call_count": t[1]} for t in trends["top_tools"]]
            if trends.get("efficiency_series"):
                trends["efficiency_series"] = [{"label": e[0], "value": e[1]} for e in trends["efficiency_series"]]
            return trends

        return jsonify({"trends": _cached("forensic_trends", _fetch), "timestamp": time.time()})

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

    # ---- Workspace endpoints -----------------------------------------------

    @app.route("/api/workspace")
    def api_workspace():
        from riva.core.workspace import find_workspace, load_workspace_config

        riva_dir = find_workspace()
        if not riva_dir:
            return jsonify({"workspace": None})

        config = load_workspace_config(riva_dir)
        return jsonify(
            {
                "workspace": {
                    "root_dir": str(config.root_dir),
                    "riva_dir": str(config.riva_dir),
                    "name": config.name,
                    "scan_interval": config.scan_interval,
                    "enabled_agents": config.enabled_agents,
                    "disabled_agents": config.disabled_agents,
                    "hooks_enabled": config.hooks_enabled,
                    "hooks_timeout": config.hooks_timeout,
                    "rules_injection_mode": config.rules_injection_mode,
                    "rules_targets": config.rules_targets,
                },
                "timestamp": time.time(),
            }
        )

    @app.route("/api/workspace/hooks")
    def api_workspace_hooks():
        from riva.core.hooks import HookEvent, HookRunner
        from riva.core.workspace import find_workspace, load_workspace_config

        riva_dir = find_workspace()
        if not riva_dir:
            return jsonify({"hooks": {}})

        config = load_workspace_config(riva_dir)
        runner = HookRunner(riva_dir, timeout=config.hooks_timeout)
        hooks: dict[str, list[str]] = {}
        for event in HookEvent:
            found = runner.discover_hooks(event)
            if found:
                hooks[event.value] = [str(h) for h in found]

        return jsonify({"hooks": hooks, "timestamp": time.time()})

    @app.route("/api/workspace/rules")
    def api_workspace_rules():
        from riva.core.rules import load_rules
        from riva.core.workspace import find_workspace

        riva_dir = find_workspace()
        if not riva_dir:
            return jsonify({"rules": None})

        rules = load_rules(riva_dir)
        return jsonify(
            {
                "rules": {
                    "files": [str(f) for f in rules.files],
                    "contents": rules.contents,
                    "combined": rules.combined,
                    "is_empty": rules.is_empty,
                },
                "timestamp": time.time(),
            }
        )

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

    @app.route("/api/open-file", methods=["POST"])
    def api_open_file():
        import subprocess
        import platform

        data = request.get_json(silent=True) or {}
        path = data.get("path", "")
        if not path:
            return jsonify({"error": "missing path"}), 400
        from pathlib import Path

        if not Path(path).exists():
            return jsonify({"error": "file not found"}), 404
        try:
            if platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            elif platform.system() == "Windows":
                subprocess.Popen(["start", path], shell=True)
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"ok": True})

    @app.route("/api/skills")
    def api_skills():
        def _fetch():
            from riva.core.skills import (
                compute_forensic_stats,
                load_global_skills,
                load_workspace_skills,
            )
            from riva.core.workspace import find_workspace

            all_skills: list = []
            all_skills.extend(load_global_skills())

            workspace_dir = find_workspace()
            if workspace_dir:
                all_skills.extend(load_workspace_skills(workspace_dir))

            registry = _get_registry()
            existing_ids = {s.id for s in all_skills}
            for det in registry.detectors:
                if det.is_installed():
                    try:
                        for sk in det.parse_skills():
                            if sk.id not in existing_ids:
                                all_skills.append(sk)
                                existing_ids.add(sk.id)
                    except Exception:
                        pass

            storage = _get_storage()
            result = []
            for sk in all_skills:
                stats = None
                if storage:
                    try:
                        invocations = storage.get_skill_invocations(sk.id, workspace=sk.workspace or "")
                        stats = compute_forensic_stats(invocations)
                    except Exception:
                        pass
                result.append(
                    {
                        "id": sk.id,
                        "name": sk.name,
                        "description": sk.description,
                        "agent": sk.agent,
                        "invocation": sk.invocation,
                        "tags": sk.tags,
                        "shared": sk.shared,
                        "workspace": sk.workspace,
                        "file_path": sk.file_path,
                        "forensic_stats": {
                            "usage_count": stats.usage_count if stats else 0,
                            "success_count": stats.success_count if stats else 0,
                            "success_rate": round(stats.success_rate, 3) if stats else 0,
                            "backtrack_count": stats.backtrack_count if stats else 0,
                            "backtrack_rate": round(stats.backtrack_rate, 3) if stats else 0,
                            "avg_tokens": stats.avg_tokens if stats else 0,
                            "avg_actions": stats.avg_actions if stats else 0,
                            "last_used": stats.last_used if stats else None,
                        }
                        if stats
                        else None,
                    }
                )
            return result

        return jsonify({"skills": _cached("skills", _fetch)})

    # ---- Skill export endpoint -------------------------------------------

    @app.route("/api/skills/send", methods=["POST"])
    def api_skills_send():
        """Export a skill to a target workspace in an agent's native format."""
        from riva.core.skills import export_skill_to_agent

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Expected JSON body"}), 400

        skill_name = data.get("skill_name")
        target_workspace = data.get("target_workspace")
        if not skill_name or not target_workspace:
            return jsonify({"error": "skill_name and target_workspace are required"}), 400

        ok, msg = export_skill_to_agent(
            skill_name=skill_name,
            target_workspace=str(Path(target_workspace).resolve()),
            source_agent=data.get("source_agent"),
            target_agent=data.get("target_agent"),
        )
        if ok:
            return jsonify({"ok": True, "message": msg})
        return jsonify({"ok": False, "error": msg}), 400

    # ---- Phase 1: Hook event ingestion -----------------------------------

    @app.route("/api/events", methods=["POST"])
    def api_events_ingest():
        """Receive a hook event from the Claude Code hook script or any agent adapter."""
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Expected JSON body"}), 400

        agent_name = str(data.get("agent_name") or "unknown")[:128]
        session_id = str(data.get("session_id") or "unknown")[:256]
        event_type = str(data.get("event_type") or "unknown")[:128]

        if not agent_name or not session_id or not event_type:
            return jsonify({"error": "agent_name, session_id, and event_type are required"}), 400

        # Reject obviously invalid event_type values (allow known prefixes and hook names)
        _valid_prefixes = ("jsonl:", "otlp:", "hook:")
        _known_types = {
            "SessionStart",
            "PreToolUse",
            "PostToolUse",
            "SubagentStop",
            "Stop",
            "Error",
            "unknown",
        }
        if event_type not in _known_types and not any(event_type.startswith(p) for p in _valid_prefixes):
            # Accept unknown types from future agents — just tag them instead of rejecting
            event_type = f"hook:{event_type}"

        # Parse timestamp — accept float (Unix) or ISO-8601 string
        raw_ts = data.get("timestamp")
        ts: float = time.time()
        if isinstance(raw_ts, (int, float)):
            ts = float(raw_ts)
        elif isinstance(raw_ts, str):
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                ts = dt.timestamp()
            except (ValueError, TypeError):
                pass

        tool_input = data.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = None

        storage = _get_storage()
        if not storage:
            return jsonify({"error": "Storage not available"}), 503

        try:
            event_id = storage.record_hook_event(
                agent_name=agent_name,
                session_id=session_id,
                event_type=event_type,
                timestamp=ts,
                tool_name=data.get("tool_name"),
                tool_input=tool_input,
                tool_output=data.get("tool_output"),
                success=bool(data.get("success", True)),
                duration_ms=data.get("duration_ms"),
                metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else None,
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({"ok": True, "event_id": event_id})

    @app.route("/api/events", methods=["GET"])
    def api_events_query():
        """Query recent hook events (all sources: hooks, JSONL tail, OTLP)."""
        storage = _get_storage()
        if not storage:
            return jsonify({"events": [], "error": "Storage not available"})

        agent_name = request.args.get("agent")
        session_id = request.args.get("session")
        event_type_prefix = request.args.get("type_prefix")
        hours = float(request.args.get("hours", 1.0))
        limit = int(request.args.get("limit", 200))

        events = storage.get_hook_events(
            agent_name=agent_name,
            session_id=session_id,
            event_type_prefix=event_type_prefix,
            hours=hours,
            limit=limit,
        )
        return jsonify({"events": events, "timestamp": time.time()})

    # ---- Phase 4: OTLP HTTP receiver ------------------------------------

    def _otlp_accept() -> bool:
        """Return True only if Content-Length is within the 10 MB safety limit."""
        cl = request.content_length
        return cl is None or cl <= 10 * 1024 * 1024

    def _otlp_attrs_to_dict(attributes) -> dict:
        """Convert a list of OTLP KeyValue attributes to a plain dict."""
        result: dict = {}
        for kv in attributes:
            key = kv.key if hasattr(kv, "key") else kv.get("key", "")
            # Protobuf AnyValue
            if hasattr(kv, "value"):
                v = kv.value
                for field in ("string_value", "int_value", "double_value", "bool_value"):
                    if v.HasField(field) if hasattr(v, "HasField") else False:
                        result[key] = getattr(v, field)
                        break
                else:
                    result[key] = str(v)
            else:
                # JSON format: {"key": "...", "value": {"stringValue": "..."}}
                val = kv.get("value", {})
                for json_field in ("stringValue", "intValue", "doubleValue", "boolValue"):
                    if json_field in val:
                        result[key] = val[json_field]
                        break
                else:
                    result[key] = str(val)
        return result

    @app.route("/otlp/v1/traces", methods=["POST"])
    def otlp_traces():
        """OTLP HTTP trace receiver. Accepts protobuf or JSON."""
        if not _otlp_accept():
            return jsonify({"error": "Payload too large (max 10 MB)"}), 413

        storage = _get_storage()
        ct = request.content_type or ""

        if "application/x-protobuf" in ct:
            try:
                from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
                    ExportTraceServiceRequest,
                    ExportTraceServiceResponse,
                )

                req = ExportTraceServiceRequest()
                req.ParseFromString(request.get_data())
                for rs in req.resource_spans:
                    svc = ""
                    for kv in rs.resource.attributes:
                        if kv.key == "service.name":
                            svc = kv.value.string_value
                            break
                    for scope_spans in rs.scope_spans:
                        for span in scope_spans.spans:
                            trace_id_hex = span.trace_id.hex() if span.trace_id else ""
                            if not trace_id_hex:
                                continue  # skip spans with no trace_id
                            if storage:
                                try:
                                    storage.record_hook_event(
                                        agent_name=svc or "otlp",
                                        session_id=trace_id_hex,
                                        event_type="otlp:trace",
                                        timestamp=span.start_time_unix_nano / 1e9
                                        if span.start_time_unix_nano
                                        else time.time(),
                                        tool_name=span.name or None,
                                        metadata=_otlp_attrs_to_dict(span.attributes),
                                    )
                                except Exception:
                                    pass
                resp = ExportTraceServiceResponse()
                return resp.SerializeToString(), 200, {"Content-Type": "application/x-protobuf"}
            except ImportError:
                return jsonify({"error": "Protobuf not available; use Content-Type: application/json"}), 415
            except Exception as exc:
                return jsonify({"error": f"Protobuf parse error: {exc}"}), 400

        # JSON format
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400

        for rs in body.get("resourceSpans", []):
            svc = ""
            for kv in rs.get("resource", {}).get("attributes", []):
                if kv.get("key") == "service.name":
                    svc = kv.get("value", {}).get("stringValue", "")
            for scope_spans in rs.get("scopeSpans", []):
                for span in scope_spans.get("spans", []):
                    start_ns = int(span.get("startTimeUnixNano", 0) or 0)
                    attrs: dict = {}
                    for kv in span.get("attributes", []):
                        key = kv.get("key", "")
                        val = kv.get("value", {})
                        for jf in ("stringValue", "intValue", "doubleValue", "boolValue"):
                            if jf in val:
                                attrs[key] = val[jf]
                                break
                    if storage:
                        try:
                            storage.record_hook_event(
                                agent_name=svc or "otlp",
                                session_id=span.get("traceId", "unknown"),
                                event_type="otlp:trace",
                                timestamp=start_ns / 1e9 if start_ns else time.time(),
                                tool_name=span.get("name"),
                                metadata=attrs,
                            )
                        except Exception:
                            pass

        return jsonify({"partialSuccess": {}}), 200

    @app.route("/otlp/v1/metrics", methods=["POST"])
    def otlp_metrics():
        """OTLP HTTP metrics receiver. Accepts protobuf or JSON."""
        if not _otlp_accept():
            return jsonify({"error": "Payload too large (max 10 MB)"}), 413

        storage = _get_storage()
        ct = request.content_type or ""

        if "application/x-protobuf" in ct:
            try:
                from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
                    ExportMetricsServiceRequest,
                    ExportMetricsServiceResponse,
                )

                req = ExportMetricsServiceRequest()
                req.ParseFromString(request.get_data())
                for rm in req.resource_metrics:
                    svc = ""
                    for kv in rm.resource.attributes:
                        if kv.key == "service.name":
                            svc = kv.value.string_value
                            break
                    for scope_metrics in rm.scope_metrics:
                        for metric in scope_metrics.metrics:
                            if storage:
                                try:
                                    storage.record_hook_event(
                                        agent_name=svc or "otlp",
                                        session_id=svc or "otlp",
                                        event_type="otlp:metric",
                                        timestamp=time.time(),
                                        tool_name=metric.name,
                                        metadata={"description": metric.description, "unit": metric.unit},
                                    )
                                except Exception:
                                    pass
                resp = ExportMetricsServiceResponse()
                return resp.SerializeToString(), 200, {"Content-Type": "application/x-protobuf"}
            except ImportError:
                return jsonify({"error": "Protobuf not available; use Content-Type: application/json"}), 415
            except Exception as exc:
                return jsonify({"error": f"Protobuf parse error: {exc}"}), 400

        # JSON format
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400

        for rm in body.get("resourceMetrics", []):
            svc = ""
            for kv in rm.get("resource", {}).get("attributes", []):
                if kv.get("key") == "service.name":
                    svc = kv.get("value", {}).get("stringValue", "")
            for scope_metrics in rm.get("scopeMetrics", []):
                for metric in scope_metrics.get("metrics", []):
                    if storage:
                        try:
                            storage.record_hook_event(
                                agent_name=svc or "otlp",
                                session_id=svc or "otlp",
                                event_type="otlp:metric",
                                timestamp=time.time(),
                                tool_name=metric.get("name"),
                                metadata={
                                    "description": metric.get("description", ""),
                                    "unit": metric.get("unit", ""),
                                },
                            )
                        except Exception:
                            pass

        return jsonify({"partialSuccess": {}}), 200

    @app.route("/otlp/v1/logs", methods=["POST"])
    def otlp_logs():
        """OTLP HTTP log receiver. Accepts protobuf or JSON."""
        if not _otlp_accept():
            return jsonify({"error": "Payload too large (max 10 MB)"}), 413

        storage = _get_storage()
        ct = request.content_type or ""

        if "application/x-protobuf" in ct:
            try:
                from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
                    ExportLogsServiceRequest,
                    ExportLogsServiceResponse,
                )

                req = ExportLogsServiceRequest()
                req.ParseFromString(request.get_data())
                for rl in req.resource_logs:
                    svc = ""
                    for kv in rl.resource.attributes:
                        if kv.key == "service.name":
                            svc = kv.value.string_value
                            break
                    for scope_logs in rl.scope_logs:
                        for log_record in scope_logs.log_records:
                            body_str = ""
                            try:
                                if hasattr(log_record, "body") and log_record.body:
                                    if hasattr(log_record.body, "HasField"):
                                        try:
                                            if log_record.body.HasField("string_value"):
                                                body_str = log_record.body.string_value
                                        except ValueError:
                                            pass
                                    elif hasattr(log_record.body, "string_value"):
                                        body_str = log_record.body.string_value or ""
                            except Exception:
                                pass
                            ts_ns = log_record.time_unix_nano or log_record.observed_time_unix_nano
                            if storage:
                                try:
                                    storage.record_hook_event(
                                        agent_name=svc or "otlp",
                                        session_id=svc or "otlp",
                                        event_type="otlp:log",
                                        timestamp=ts_ns / 1e9 if ts_ns else time.time(),
                                        tool_output=body_str[:2000] if body_str else None,
                                        metadata=_otlp_attrs_to_dict(log_record.attributes),
                                    )
                                except Exception:
                                    pass
                resp = ExportLogsServiceResponse()
                return resp.SerializeToString(), 200, {"Content-Type": "application/x-protobuf"}
            except ImportError:
                return jsonify({"error": "Protobuf not available; use Content-Type: application/json"}), 415
            except Exception as exc:
                return jsonify({"error": f"Protobuf parse error: {exc}"}), 400

        # JSON format
        try:
            body = request.get_json(force=True, silent=True) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400

        for rl in body.get("resourceLogs", []):
            svc = ""
            for kv in rl.get("resource", {}).get("attributes", []):
                if kv.get("key") == "service.name":
                    svc = kv.get("value", {}).get("stringValue", "")
            for scope_logs in rl.get("scopeLogs", []):
                for log_record in scope_logs.get("logRecords", []):
                    ts_ns = int(log_record.get("timeUnixNano", 0) or 0)
                    log_body = log_record.get("body", {}).get("stringValue", "")
                    attrs: dict = {}
                    for kv in log_record.get("attributes", []):
                        key = kv.get("key", "")
                        val = kv.get("value", {})
                        for jf in ("stringValue", "intValue", "doubleValue", "boolValue"):
                            if jf in val:
                                attrs[key] = val[jf]
                                break
                    if storage:
                        try:
                            storage.record_hook_event(
                                agent_name=svc or "otlp",
                                session_id=svc or "otlp",
                                event_type="otlp:log",
                                timestamp=ts_ns / 1e9 if ts_ns else time.time(),
                                tool_output=log_body[:2000] if log_body else None,
                                metadata=attrs,
                            )
                        except Exception:
                            pass

        return jsonify({"partialSuccess": {}}), 200

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
