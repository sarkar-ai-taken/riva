"""Real-time JSONL session file tailer for Riva.

Watches active session files written by Claude Code and Cursor (and any future
agent that stores sessions as JSONL files) and streams new entries into Riva's
hook_events storage table as they are appended.

No external dependencies — uses pure-Python file position tracking and a
5-second poll loop. watchdog / inotify can replace this in a future iteration
without changing the public interface.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.core.storage import RivaStorage

logger = logging.getLogger(__name__)

# Agents whose session dirs contain JSONL files and the glob pattern to find them.
# Format: agent_name -> (base_dir, glob_pattern)
_WATCHED_AGENTS: dict[str, tuple[Path, str]] = {
    "Claude Code": (Path.home() / ".claude" / "projects", "**/*.jsonl"),
    "Cursor": (Path.home() / ".cursor" / "projects", "**/*.jsonl"),
}

_POLL_INTERVAL = 5.0  # seconds between full directory scans


@dataclass
class _FileState:
    """Tracked state for a single tailed file."""

    path: Path
    agent_name: str
    position: int = 0  # byte offset of next unread byte


class SessionTailer:
    """Watch active JSONL session files and forward new entries to storage.

    Thread-safe. Designed to be started/stopped by ResourceMonitor alongside
    its own background thread.
    """

    def __init__(self, storage: "RivaStorage") -> None:
        self._storage = storage
        self._states: dict[str, _FileState] = {}  # path_str -> _FileState
        self._state_access: dict[str, float] = {}  # path_str -> last access time (for eviction)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background tail thread (idempotent)."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="riva-session-tailer", daemon=True)
        self._thread.start()
        logger.debug("SessionTailer started")

    def stop(self) -> None:
        """Stop the background tail thread and wait for it to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=8.0)
            self._thread = None
        logger.debug("SessionTailer stopped")

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._scan_all()
            except Exception:
                logger.debug("SessionTailer scan error", exc_info=True)
            self._stop_event.wait(_POLL_INTERVAL)

    def _scan_all(self) -> None:
        for agent_name, (base_dir, pattern) in _WATCHED_AGENTS.items():
            if not base_dir.is_dir():
                continue
            try:
                for jsonl_path in base_dir.glob(pattern):
                    self._tail_file(jsonl_path, agent_name)
            except OSError:
                pass

    def _tail_file(self, path: Path, agent_name: str) -> None:
        path_str = str(path)

        now = time.time()
        with self._lock:
            # Evict entries not accessed in 7 days when dict grows large
            if len(self._states) > 5000:
                cutoff = now - 7 * 86400
                stale = [p for p, t in self._state_access.items() if t < cutoff]
                for p in stale:
                    self._states.pop(p, None)
                    self._state_access.pop(p, None)

            state = self._states.get(path_str)
            if state is None:
                state = _FileState(path=path, agent_name=agent_name)
                self._states[path_str] = state
            self._state_access[path_str] = now
            last_pos = state.position

        try:
            current_size = path.stat().st_size
        except OSError:
            return

        if current_size < last_pos:
            last_pos = 0  # file was truncated / rotated

        if current_size == last_pos:
            return  # no new data

        new_entries: list[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(last_pos)
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        new_entries.append(json.loads(raw_line))
                    except json.JSONDecodeError:
                        pass
                new_pos = fh.tell()
        except OSError:
            return

        with self._lock:
            self._states[path_str].position = new_pos

        # session_id: Claude Code names its JSONL files by session UUID
        session_id = path.stem
        if not session_id or not session_id.strip():
            return  # skip files with empty or whitespace-only names

        for entry in new_entries:
            self._forward(entry, agent_name, session_id, path)

    # ------------------------------------------------------------------
    # Event forwarding
    # ------------------------------------------------------------------

    def _forward(
        self,
        entry: dict,
        agent_name: str,
        session_id: str,
        path: Path,
    ) -> None:
        entry_type = entry.get("type", "unknown")
        tool_name: str | None = None
        tool_input: dict | None = None
        tool_output: str | None = None
        success = True
        ts = time.time()

        # Claude Code JSONL: top-level tool_use messages
        if entry_type == "tool_use":
            tool_name = entry.get("name")
            inp = entry.get("input")
            tool_input = inp if isinstance(inp, dict) else None

        elif entry_type == "tool_result":
            content = entry.get("content", "")
            if isinstance(content, str):
                tool_output = content[:2000]
            elif isinstance(content, list):
                parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
                tool_output = "\n".join(parts)[:2000]
            success = not entry.get("is_error", False)

        # Nested content blocks (assistant messages wrapping tool_use)
        for block in entry.get("content", []):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and tool_name is None:
                tool_name = block.get("name")
                inp = block.get("input")
                tool_input = inp if isinstance(inp, dict) else None

        # Parse timestamp from entry
        raw_ts = entry.get("timestamp")
        if raw_ts:
            try:
                from datetime import datetime, timezone

                dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                ts = dt.timestamp()
            except (ValueError, TypeError):
                pass

        try:
            self._storage.record_hook_event(
                agent_name=agent_name,
                session_id=session_id,
                event_type=f"jsonl:{entry_type}",
                timestamp=ts,
                tool_name=tool_name,
                tool_input=tool_input,
                tool_output=tool_output,
                success=success,
                metadata={"source": "jsonl_tail", "file": path.name},
            )
        except Exception:
            logger.debug("SessionTailer storage error", exc_info=True)
