"""Session forensics for AI agent transcripts.

Parses agent session transcripts (JSONL) into structured turn chains,
detects behavioral patterns, and computes efficiency metrics.

Philosophy:
    - Append, never erase: source JSONL is read-only, we index but don't modify
    - Time is first-class: every event is timestamped and ordered
    - Mistakes are signal: dead-ends and retries are tracked, not hidden
    - Decisions matter more than outputs: thinking blocks are first-class
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from riva.utils.jsonl import find_recent_sessions, stream_jsonl

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Action:
    """A single tool invocation within a turn."""

    tool_name: str
    input_summary: str
    output_preview: str = ""
    duration_ms: int | None = None
    files_touched: list[str] = field(default_factory=list)
    timestamp: str | None = None
    success: bool = True


@dataclass
class Turn:
    """One user prompt -> full agent response cycle."""

    index: int
    prompt: str
    thinking: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    response_text: str = ""
    model: str | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_cache_read: int = 0
    tokens_cache_create: int = 0
    timestamp_start: str | None = None
    timestamp_end: str | None = None
    git_branch: str | None = None
    cwd: str | None = None
    is_dead_end: bool = False

    @property
    def total_tokens(self) -> int:
        return self.tokens_in + self.tokens_out + self.tokens_cache_read + self.tokens_cache_create

    @property
    def duration_seconds(self) -> float | None:
        if self.timestamp_start and self.timestamp_end:
            try:
                t0 = _parse_ts(self.timestamp_start)
                t1 = _parse_ts(self.timestamp_end)
                if t0 and t1:
                    return (t1 - t0).total_seconds()
            except (ValueError, TypeError):
                pass
        return None

    @property
    def files_read(self) -> list[str]:
        return _unique([f for a in self.actions if a.tool_name in ("Read", "Grep", "Glob") for f in a.files_touched])

    @property
    def files_written(self) -> list[str]:
        return _unique(
            [f for a in self.actions if a.tool_name in ("Edit", "Write", "NotebookEdit") for f in a.files_touched]
        )


@dataclass
class SessionPattern:
    """A detected behavioral pattern in a session."""

    pattern_type: str  # dead_end, retry_loop, search_thrash, write_without_read
    description: str
    turn_indices: list[int] = field(default_factory=list)
    severity: str = "info"  # info, warning


@dataclass
class ForensicSession:
    """A fully parsed agent session with forensic analysis."""

    session_id: str
    slug: str | None = None
    project: str | None = None
    agent: str = "Claude Code"
    model: str | None = None
    git_branch: str | None = None
    source_file: str | None = None

    turns: list[Turn] = field(default_factory=list)
    patterns: list[SessionPattern] = field(default_factory=list)

    timestamp_start: str | None = None
    timestamp_end: str | None = None

    total_tokens: int = 0
    total_actions: int = 0
    total_files_read: int = 0
    total_files_written: int = 0

    @property
    def duration_seconds(self) -> float | None:
        if self.timestamp_start and self.timestamp_end:
            try:
                t0 = _parse_ts(self.timestamp_start)
                t1 = _parse_ts(self.timestamp_end)
                if t0 and t1:
                    return (t1 - t0).total_seconds()
            except (ValueError, TypeError):
                pass
        return None

    @property
    def dead_end_count(self) -> int:
        return sum(1 for t in self.turns if t.is_dead_end)

    @property
    def efficiency(self) -> float:
        """Fraction of tokens spent on non-dead-end turns."""
        if self.total_tokens == 0:
            return 1.0
        dead_tokens = sum(t.total_tokens for t in self.turns if t.is_dead_end)
        return 1.0 - (dead_tokens / self.total_tokens)

    @property
    def all_files_read(self) -> list[str]:
        return _unique([f for t in self.turns for f in t.files_read])

    @property
    def all_files_written(self) -> list[str]:
        return _unique([f for t in self.turns for f in t.files_written])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


_FAILURE_SIGNALS = (
    "error",
    "Error",
    "ERROR",
    "FAIL",
    "FAILED",
    "fail",
    "failed",
    "traceback",
    "Traceback",
    "exception",
    "Exception",
    "command not found",
    "No such file",
    "Permission denied",
    "exit code",
)


def _extract_input_summary(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Read":
        return tool_input.get("file_path", "?")
    if tool_name in ("Edit", "Write"):
        return tool_input.get("file_path", "?")
    if tool_name == "Glob":
        return tool_input.get("pattern", "?")
    if tool_name == "Grep":
        pat = tool_input.get("pattern", "?")
        path = tool_input.get("path", "")
        return f'"{pat}" {path}'.strip()
    if tool_name == "Bash":
        desc = tool_input.get("description", "")
        if desc:
            return desc
        cmd = tool_input.get("command", "?")
        return cmd[:80] + ("..." if len(cmd) > 80 else "")
    if tool_name == "Task":
        return tool_input.get("description", tool_input.get("prompt", "?"))[:80]
    if tool_name in ("WebSearch", "WebFetch"):
        return (tool_input.get("query") or tool_input.get("url", "?"))[:80]
    if tool_name == "NotebookEdit":
        return tool_input.get("notebook_path", "?")
    return str(tool_input)[:80]


def _extract_files(tool_name: str, tool_input: dict) -> list[str]:
    if tool_name in ("Read", "Edit", "Write"):
        fp = tool_input.get("file_path")
        return [fp] if fp else []
    if tool_name == "NotebookEdit":
        fp = tool_input.get("notebook_path")
        return [fp] if fp else []
    return []


def _looks_like_failure(output: str) -> bool:
    if not output:
        return False
    check = output[:500]
    return any(sig in check for sig in _FAILURE_SIGNALS)


# ---------------------------------------------------------------------------
# Session discovery
# ---------------------------------------------------------------------------


def discover_sessions(
    config_dir: Path | None = None,
    project_filter: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Find available Claude Code sessions.

    Returns list of dicts with session metadata, sorted newest first.
    """
    config_dir = config_dir or Path.home() / ".claude"
    projects_dir = config_dir / "projects"
    if not projects_dir.is_dir():
        return []

    session_files = find_recent_sessions(projects_dir, "**/*.jsonl", limit=limit * 3)
    sessions: list[dict] = []

    for sf in session_files:
        # Skip subagent transcripts
        if "subagents" in sf.parts:
            continue

        project_dir = sf.parent.name

        if project_filter and project_filter.lower() not in project_dir.lower():
            continue

        session_id = sf.stem
        slug = None
        first_timestamp = None

        for record in stream_jsonl(sf, max_lines=15):
            if not slug and record.get("slug"):
                slug = record["slug"]
            if not first_timestamp and record.get("timestamp"):
                first_timestamp = record["timestamp"]
            if slug and first_timestamp:
                break

        try:
            stat = sf.stat()
            sessions.append(
                {
                    "session_id": session_id,
                    "slug": slug,
                    "project": project_dir,
                    "file_path": str(sf),
                    "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "size_bytes": stat.st_size,
                    "first_timestamp": first_timestamp,
                }
            )
        except OSError:
            continue

    return sessions[:limit]


def resolve_session(identifier: str, config_dir: Path | None = None) -> Path | None:
    """Resolve a session identifier to a JSONL file path.

    Accepts: "latest", a slug, a UUID prefix, or a full UUID.
    """
    sessions = discover_sessions(config_dir=config_dir, limit=200)
    if not sessions:
        return None

    if identifier == "latest":
        return Path(sessions[0]["file_path"])

    # Try slug match
    for s in sessions:
        if s.get("slug") == identifier:
            return Path(s["file_path"])

    # Try UUID prefix match
    for s in sessions:
        if s["session_id"].startswith(identifier):
            return Path(s["file_path"])

    # Try substring match on slug
    for s in sessions:
        if s.get("slug") and identifier.lower() in s["slug"].lower():
            return Path(s["file_path"])

    return None


# ---------------------------------------------------------------------------
# Session parsing
# ---------------------------------------------------------------------------


def parse_session(file_path: Path | str) -> ForensicSession:
    """Parse a Claude Code session JSONL into a ForensicSession."""
    file_path = Path(file_path)

    session = ForensicSession(
        session_id=file_path.stem,
        source_file=str(file_path),
        project=file_path.parent.name,
    )

    events = list(stream_jsonl(file_path))
    if not events:
        return session

    current_turn: Turn | None = None
    turn_index = 0
    pending_tools: dict[str, Action] = {}  # tool_use_id -> Action
    all_timestamps: list[str] = []

    for event in events:
        event_type = event.get("type")
        timestamp = event.get("timestamp")

        if timestamp:
            all_timestamps.append(timestamp)

        # Session metadata
        if not session.slug and event.get("slug"):
            session.slug = event["slug"]
        if not session.git_branch and event.get("gitBranch"):
            session.git_branch = event["gitBranch"]
        sid = event.get("sessionId")
        if sid:
            session.session_id = sid

        if event_type not in ("user", "assistant"):
            continue

        message = event.get("message", {})
        role = message.get("role")
        content = message.get("content")

        # --- User prompt (string content = actual human message) ---
        if event_type == "user" and role == "user" and isinstance(content, str):
            if current_turn is not None:
                if timestamp:
                    current_turn.timestamp_end = timestamp
                session.turns.append(current_turn)

            current_turn = Turn(
                index=turn_index,
                prompt=content.strip(),
                timestamp_start=timestamp,
                cwd=event.get("cwd"),
                git_branch=event.get("gitBranch"),
            )
            turn_index += 1
            continue

        # --- Tool result (user event with tool_result content blocks) ---
        if event_type == "user" and isinstance(content, list):
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue

                tool_use_id = block.get("tool_use_id", "")
                result_content = block.get("content", "")

                if isinstance(result_content, list):
                    parts = []
                    for part in result_content:
                        if isinstance(part, dict):
                            parts.append(part.get("text", str(part)))
                        else:
                            parts.append(str(part))
                    result_content = "\n".join(parts)

                result_str = str(result_content)

                if tool_use_id in pending_tools:
                    action = pending_tools.pop(tool_use_id)
                    action.output_preview = result_str[:200]
                    action.success = not _looks_like_failure(result_str)

                    tur = event.get("toolUseResult")
                    if isinstance(tur, dict) and tur.get("durationMs"):
                        action.duration_ms = tur["durationMs"]
                    if isinstance(tur, dict) and tur.get("filenames"):
                        for fn in tur["filenames"]:
                            if fn not in action.files_touched:
                                action.files_touched.append(fn)

                    # Only Bash failures mark a turn as dead-end
                    if not action.success and action.tool_name == "Bash" and current_turn:
                        current_turn.is_dead_end = True
            continue

        # --- Assistant message ---
        if event_type == "assistant" and isinstance(content, list):
            model = message.get("model")
            if model and current_turn:
                current_turn.model = model
                if not session.model:
                    session.model = model

            usage = message.get("usage", {})
            if usage and current_turn:
                current_turn.tokens_in += usage.get("input_tokens", 0)
                current_turn.tokens_out += usage.get("output_tokens", 0)
                current_turn.tokens_cache_read += usage.get("cache_read_input_tokens", 0)
                current_turn.tokens_cache_create += usage.get("cache_creation_input_tokens", 0)

            for block in content:
                if not isinstance(block, dict):
                    continue

                btype = block.get("type")

                if btype == "thinking" and current_turn:
                    text = block.get("thinking", "")
                    if text:
                        current_turn.thinking.append(text)

                elif btype == "text" and current_turn:
                    current_turn.response_text += block.get("text", "")

                elif btype == "tool_use" and current_turn:
                    tool_name = block.get("name", "unknown")
                    tool_input = block.get("input", {})
                    tool_id = block.get("id", "")

                    action = Action(
                        tool_name=tool_name,
                        input_summary=_extract_input_summary(tool_name, tool_input),
                        files_touched=_extract_files(tool_name, tool_input),
                        timestamp=timestamp,
                    )
                    current_turn.actions.append(action)
                    if tool_id:
                        pending_tools[tool_id] = action

    # Save last turn
    if current_turn is not None:
        if all_timestamps:
            current_turn.timestamp_end = all_timestamps[-1]
        session.turns.append(current_turn)

    # Aggregates
    if all_timestamps:
        session.timestamp_start = all_timestamps[0]
        session.timestamp_end = all_timestamps[-1]

    all_r: set[str] = set()
    all_w: set[str] = set()
    for turn in session.turns:
        session.total_tokens += turn.total_tokens
        session.total_actions += len(turn.actions)
        all_r.update(turn.files_read)
        all_w.update(turn.files_written)
    session.total_files_read = len(all_r)
    session.total_files_written = len(all_w)

    session.patterns = detect_patterns(session)
    return session


# ---------------------------------------------------------------------------
# Pattern detection
# ---------------------------------------------------------------------------


def detect_patterns(session: ForensicSession) -> list[SessionPattern]:
    """Analyze a session for behavioral patterns."""
    patterns: list[SessionPattern] = []

    # Dead ends
    dead_ends = [t.index for t in session.turns if t.is_dead_end]
    if dead_ends:
        patterns.append(
            SessionPattern(
                pattern_type="dead_end",
                description=f"{len(dead_ends)} turn(s) hit failures requiring backtracking",
                turn_indices=dead_ends,
            )
        )

    for turn in session.turns:
        # Search thrashing: >4 consecutive read/search ops
        consec = 0
        max_consec = 0
        for action in turn.actions:
            if action.tool_name in ("Grep", "Glob", "Read"):
                consec += 1
                max_consec = max(max_consec, consec)
            else:
                consec = 0

        if max_consec > 4:
            patterns.append(
                SessionPattern(
                    pattern_type="search_thrash",
                    description=f"Turn {turn.index}: {max_consec} consecutive search operations",
                    turn_indices=[turn.index],
                )
            )

        # Retry loops: same tool+same target called >2 times
        # Only flag tools where repetition signals a problem (Bash, Grep).
        # Read/Write/Edit naturally hit many different files.
        seen: dict[str, int] = {}
        for action in turn.actions:
            if action.tool_name in ("Read", "Write", "Edit", "NotebookEdit", "TaskCreate", "TaskUpdate"):
                continue
            key = f"{action.tool_name}:{action.input_summary}"
            seen[key] = seen.get(key, 0) + 1

        for call_key, count in seen.items():
            if count > 2:
                tool = call_key.split(":", 1)[0]
                target = call_key.split(":", 1)[1]
                if len(target) > 50:
                    target = target[:47] + "..."
                patterns.append(
                    SessionPattern(
                        pattern_type="retry_loop",
                        description=f"Turn {turn.index}: {tool} called {count}x — {target}",
                        turn_indices=[turn.index],
                        severity="warning",
                    )
                )

        # Write without read
        has_read = False
        for action in turn.actions:
            if action.tool_name in ("Read", "Grep", "Glob"):
                has_read = True
            if action.tool_name in ("Edit", "Write") and not has_read:
                patterns.append(
                    SessionPattern(
                        pattern_type="write_without_read",
                        description=f"Turn {turn.index}: wrote files without reading first",
                        turn_indices=[turn.index],
                        severity="warning",
                    )
                )
                break

    return patterns


# ---------------------------------------------------------------------------
# Cross-session trends
# ---------------------------------------------------------------------------


def compute_trends(sessions: list[ForensicSession]) -> dict:
    """Compute aggregate trends across multiple sessions."""
    if not sessions:
        return {}

    n = len(sessions)
    total_turns = sum(len(s.turns) for s in sessions)
    total_actions = sum(s.total_actions for s in sessions)
    total_tokens = sum(s.total_tokens for s in sessions)
    total_dead_ends = sum(s.dead_end_count for s in sessions)
    avg_efficiency = sum(s.efficiency for s in sessions) / n

    tool_counts: dict[str, int] = {}
    for s in sessions:
        for t in s.turns:
            for a in t.actions:
                tool_counts[a.tool_name] = tool_counts.get(a.tool_name, 0) + 1

    top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)

    # Per-session efficiency for trend line
    efficiency_series = [(s.slug or s.session_id[:8], s.efficiency) for s in sessions]

    return {
        "total_sessions": n,
        "total_turns": total_turns,
        "total_actions": total_actions,
        "total_tokens": total_tokens,
        "total_dead_ends": total_dead_ends,
        "avg_turns_per_session": round(total_turns / n, 1),
        "avg_efficiency": round(avg_efficiency, 2),
        "dead_end_rate": round(total_dead_ends / total_turns, 2) if total_turns else 0,
        "top_tools": top_tools[:10],
        "efficiency_series": efficiency_series,
    }


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_timeline(session: ForensicSession) -> list[str]:
    """Human-readable event timeline."""
    lines: list[str] = []
    if not session.turns:
        lines.append("  (empty session)")
        return lines

    t0 = _parse_ts(session.timestamp_start) if session.timestamp_start else None

    for turn in session.turns:
        time_str = _relative_time(t0, turn.timestamp_start)

        prompt = turn.prompt.replace("\n", " ").strip()
        if len(prompt) > 70:
            prompt = prompt[:67] + "..."
        lines.append(f"  {time_str}  User: {prompt}")

        for action in turn.actions:
            atime = _relative_time(t0, action.timestamp)
            status = "" if action.success else " [red][FAIL][/red]"
            dur = f" [{action.duration_ms / 1000:.1f}s]" if action.duration_ms else ""
            summary = action.input_summary
            if len(summary) > 55:
                summary = summary[:52] + "..."
            lines.append(f"  {atime}  {action.tool_name:<8} {summary}{dur}{status}")

        if turn.is_dead_end:
            lines.append(f"  {'':5}  [yellow]** dead end -- agent backtracked **[/yellow]")

    duration = session.duration_seconds
    dur_str = _fmt_duration(duration) if duration else "?"
    lines.append("")
    lines.append(
        f"  Done {dur_str}  |  {len(session.turns)} turns  |  "
        f"{session.total_actions} actions  |  "
        f"{session.total_tokens:,} tokens  |  "
        f"efficiency: {session.efficiency:.0%}"
    )
    return lines


def format_summary(session: ForensicSession) -> list[str]:
    """Short session summary."""
    dur = _fmt_duration(session.duration_seconds) if session.duration_seconds else "?"
    return [
        f"  Session:     {session.slug or session.session_id[:12]}",
        f"  Project:     {session.project or '?'}",
        f"  Model:       {session.model or '?'}",
        f"  Branch:      {session.git_branch or '?'}",
        f"  Duration:    {dur}",
        f"  Turns:       {len(session.turns)}",
        f"  Actions:     {session.total_actions}",
        f"  Tokens:      {session.total_tokens:,}",
        f"  Files read:  {session.total_files_read}",
        f"  Files wrote: {session.total_files_written}",
        f"  Dead ends:   {session.dead_end_count}",
        f"  Efficiency:  {session.efficiency:.0%}",
    ]


def format_patterns(session: ForensicSession) -> list[str]:
    """Format detected patterns."""
    if not session.patterns:
        return ["  No notable patterns detected."]

    lines: list[str] = []
    by_type: dict[str, list[SessionPattern]] = {}
    for p in session.patterns:
        by_type.setdefault(p.pattern_type, []).append(p)

    labels = {
        "dead_end": "Dead Ends",
        "search_thrash": "Search Thrashing",
        "retry_loop": "Retry Loops",
        "write_without_read": "Write Without Read",
    }

    for ptype, plist in by_type.items():
        label = labels.get(ptype, ptype)
        lines.append(f"  {label}: {len(plist)}")
        for p in plist:
            marker = "[yellow]![/yellow]" if p.severity == "warning" else " "
            lines.append(f"   {marker} {p.description}")

    return lines


def format_files(session: ForensicSession) -> list[str]:
    """File access report."""
    lines: list[str] = []
    written = session.all_files_written
    read = session.all_files_read

    if written:
        lines.append("  [bold]Files Modified:[/bold]")
        for f in written:
            lines.append(f"    W  {f}")

    read_only = [f for f in read if f not in written]
    if read_only:
        lines.append("  [bold]Files Read (only):[/bold]")
        for f in read_only[:30]:
            lines.append(f"    R  {f}")
        if len(read_only) > 30:
            lines.append(f"    ... and {len(read_only) - 30} more")

    if not read and not written:
        lines.append("  No file operations detected.")

    return lines


def format_decisions(session: ForensicSession) -> list[str]:
    """Extract key decision points from thinking blocks."""
    lines: list[str] = []
    count = 0

    for turn in session.turns:
        if not turn.thinking or not turn.actions:
            continue

        count += 1
        ts = turn.timestamp_start[:19] if turn.timestamp_start else "?"
        lines.append(f"  [bold]Decision {count}[/bold] ({ts}):")

        action_names = [a.tool_name for a in turn.actions]
        summary = ", ".join(action_names[:5])
        if len(action_names) > 5:
            summary += f" +{len(action_names) - 5} more"
        lines.append(f"    Actions: {summary}")

        preview = turn.thinking[0].replace("\n", " ").strip()
        if len(preview) > 120:
            preview = preview[:117] + "..."
        lines.append(f"    Reasoning: {preview}")

        all_files = turn.files_read + turn.files_written
        if all_files:
            lines.append(f"    Files: {', '.join(all_files[:5])}")

        if turn.is_dead_end:
            lines.append("    [yellow]Outcome: BACKTRACKED[/yellow]")

        lines.append("")

    if count == 0:
        lines.append("  No decision points with thinking blocks found.")

    return lines


def format_trends(trends: dict) -> list[str]:
    """Format cross-session trend data."""
    if not trends:
        return ["  No trend data available."]

    lines = [
        f"  Sessions:         {trends['total_sessions']}",
        f"  Total turns:      {trends['total_turns']}",
        f"  Total actions:    {trends['total_actions']}",
        f"  Total tokens:     {trends['total_tokens']:,}",
        f"  Avg turns/session:{trends['avg_turns_per_session']}",
        f"  Avg efficiency:   {trends['avg_efficiency']:.0%}",
        f"  Dead-end rate:    {trends['dead_end_rate']:.0%}",
        "",
        "  [bold]Top Tools:[/bold]",
    ]

    for name, count in trends.get("top_tools", []):
        lines.append(f"    {name:<12} {count}")

    return lines


# ---------------------------------------------------------------------------
# Internal formatting helpers
# ---------------------------------------------------------------------------


def _relative_time(t0: datetime | None, ts: str | None) -> str:
    if not t0 or not ts:
        return "     "
    t1 = _parse_ts(ts)
    if not t1:
        return "     "
    delta = (t1 - t0).total_seconds()
    if delta < 0:
        delta = 0
    mins = int(delta // 60)
    secs = int(delta % 60)
    return f"{mins:02d}:{secs:02d}"


def _fmt_duration(seconds: float | None) -> str:
    if not seconds:
        return "?"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    if mins > 0:
        return f"{mins}m{secs}s"
    return f"{secs}s"
