"""Cline (Claude Dev) agent detector."""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from riva.agents.base import AgentDetector
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)

# Editors whose globalStorage may host the Cline extension state
_EDITOR_DIRS = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"]


class ClineDetector(AgentDetector):
    """Detect Cline (formerly Claude Dev) VS Code extension."""

    @property
    def agent_name(self) -> str:
        return "Cline"

    @property
    def binary_names(self) -> list[str]:
        return ["cline"]

    @property
    def config_dir(self) -> Path:
        # Cline stores state in VS Code extension directory
        return Path.home() / ".vscode" / "extensions"

    @property
    def api_domain(self) -> str:
        return "api.anthropic.com"

    def _find_extension_dir(self) -> Path | None:
        """Find the Cline/Claude Dev extension directory."""
        ext_dir = self.config_dir
        if not ext_dir.is_dir():
            return None
        try:
            # Look for saoudrizwan.claude-dev-* extensions
            dirs = sorted(
                [d for d in ext_dir.iterdir() if d.name.startswith("saoudrizwan.claude-dev") and d.is_dir()],
                key=lambda p: p.name,
                reverse=True,
            )
            return dirs[0] if dirs else None
        except OSError:
            return None

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        # Cline is extension-only, no standalone process
        # But it may spawn helper processes
        if cmdline:
            joined = " ".join(cmdline)
            if "claude-dev" in joined or "saoudrizwan.claude-dev" in joined:
                return True
        return False

    def is_installed(self) -> bool:
        return self._find_extension_dir() is not None

    # ------------------------------------------------------------------
    # Usage statistics
    # ------------------------------------------------------------------

    def _tasks_dirs(self) -> list[Path]:
        """Find Cline task-history directories across editor globalStorage roots."""
        home = Path.home()
        bases: list[Path] = []
        if sys.platform == "darwin":
            bases.append(home / "Library" / "Application Support")
        elif sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            if appdata:
                bases.append(Path(appdata))
        else:
            bases.append(home / ".config")

        dirs: list[Path] = []
        for base in bases:
            for editor in _EDITOR_DIRS:
                tasks = base / editor / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "tasks"
                if tasks.is_dir():
                    dirs.append(tasks)
        return dirs

    def parse_usage(self) -> UsageStats | None:
        """Parse usage stats from Cline task history.

        Scans ``<globalStorage>/saoudrizwan.claude-dev/tasks/<id>/``:
        - ``ui_messages.json`` — ``api_req_started`` entries carry
          tokensIn/tokensOut/cacheWrites/cacheReads; ``tool`` entries name tools
        - ``task_metadata.json`` — ``model_usage`` records the model ids
        """
        try:
            return self._parse_usage_inner()
        except Exception:
            return None

    def _parse_usage_inner(self) -> UsageStats | None:
        task_dirs: list[Path] = []
        for root in self._tasks_dirs():
            try:
                task_dirs.extend(d for d in root.iterdir() if d.is_dir())
            except OSError:
                continue
        if not task_dirs:
            return None

        # Most recent 50 tasks by directory mtime
        task_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
        task_dirs = task_dirs[:50]

        model_tokens: dict[str, TokenUsage] = defaultdict(TokenUsage)
        tool_counts: dict[str, int] = defaultdict(int)
        tool_last_used: dict[str, str] = {}
        daily_counts: dict[str, dict] = defaultdict(lambda: {"messages": 0, "sessions": 0, "tokens": 0, "tools": 0})
        total_sessions = 0
        total_messages = 0
        total_tool_calls = 0

        for task_dir in task_dirs:
            ui_file = task_dir / "ui_messages.json"
            if not ui_file.is_file():
                continue
            try:
                entries = json.loads(ui_file.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(entries, list):
                continue

            # Model id for this task (last one wins) from task_metadata.json
            model_id = "unknown"
            meta_file = task_dir / "task_metadata.json"
            if meta_file.is_file():
                try:
                    meta = json.loads(meta_file.read_text(errors="replace"))
                    usage_entries = meta.get("model_usage", [])
                    if isinstance(usage_entries, list) and usage_entries:
                        last = usage_entries[-1]
                        if isinstance(last, dict):
                            model_id = last.get("model_id", model_id)
                except (json.JSONDecodeError, OSError):
                    pass

            total_sessions += 1
            task_date = ""

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                ts_ms = entry.get("ts")
                date_key = ""
                ts_iso = ""
                if isinstance(ts_ms, (int, float)) and ts_ms > 0:
                    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
                    date_key = dt.strftime("%Y-%m-%d")
                    ts_iso = dt.isoformat()
                    if not task_date:
                        task_date = date_key

                say = entry.get("say", "")
                if say == "api_req_started":
                    try:
                        info = json.loads(entry.get("text", "") or "{}")
                    except (json.JSONDecodeError, ValueError):
                        info = {}
                    if not isinstance(info, dict):
                        continue
                    usage = model_tokens[model_id]
                    usage.input_tokens += info.get("tokensIn", 0)
                    usage.output_tokens += info.get("tokensOut", 0)
                    usage.cache_read_input_tokens += info.get("cacheReads", 0)
                    usage.cache_creation_input_tokens += info.get("cacheWrites", 0)
                    total_messages += 1
                    if date_key:
                        daily_counts[date_key]["messages"] += 1
                        daily_counts[date_key]["tokens"] += info.get("tokensIn", 0) + info.get("tokensOut", 0)
                elif say == "tool" or entry.get("ask") == "tool":
                    try:
                        info = json.loads(entry.get("text", "") or "{}")
                    except (json.JSONDecodeError, ValueError):
                        info = {}
                    name = info.get("tool", "unknown") if isinstance(info, dict) else "unknown"
                    tool_counts[name] += 1
                    total_tool_calls += 1
                    if ts_iso:
                        tool_last_used[name] = ts_iso
                    if date_key:
                        daily_counts[date_key]["tools"] += 1

            if task_date:
                daily_counts[task_date]["sessions"] += 1

        if not total_messages and not total_tool_calls:
            return None

        model_stats: dict[str, ModelStats] = {}
        total_tokens = 0
        for mid, usage in model_tokens.items():
            model_stats[mid] = ModelStats(model_id=mid, usage=usage)
            total_tokens += usage.total_tokens

        tool_stats = [
            ToolCallStats(tool_name=name, call_count=count, last_used=tool_last_used.get(name))
            for name, count in tool_counts.items()
        ]

        daily_activity = [
            DailyStats(
                date=date_str,
                message_count=dc["messages"],
                session_count=dc["sessions"],
                tool_call_count=dc["tools"],
                total_tokens=dc["tokens"],
            )
            for date_str, dc in sorted(daily_counts.items())
        ]

        return UsageStats(
            model_stats=model_stats,
            tool_stats=tool_stats,
            daily_activity=daily_activity,
            total_tokens=total_tokens,
            total_messages=total_messages,
            total_sessions=total_sessions,
            total_tool_calls=total_tool_calls,
            time_range_start=daily_activity[0].date if daily_activity else None,
            time_range_end=daily_activity[-1].date if daily_activity else None,
        )

    def parse_config(self) -> dict:
        config: dict = {}

        ext_dir = self._find_extension_dir()
        if ext_dir:
            config["extension_dir"] = str(ext_dir)

            # Extract version from package.json
            pkg_json = ext_dir / "package.json"
            if pkg_json.is_file():
                try:
                    pkg = json.loads(pkg_json.read_text())
                    config["version"] = pkg.get("version", "unknown")
                    config["display_name"] = pkg.get("displayName", "Cline")
                except (json.JSONDecodeError, OSError):
                    pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config

    def write_skill(self, skill, workspace=None):
        """Append a skill section to .clinerules in the target workspace."""
        base = Path(workspace) if workspace else Path.cwd()
        path = base / ".clinerules"

        section = f"\n\n## {skill.name}\n\n{skill.description or ''}\n"

        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if f"## {skill.name}" in existing:
                return path
            path.write_text(existing.rstrip() + section, encoding="utf-8")
        else:
            path.write_text(f"# Cline Rules{section}", encoding="utf-8")
        return path

    def parse_skills(self) -> list:
        """Discover Cline rules files as skills.

        Reads:
        - ~/.clinerules  (global custom instructions)
        - .clinerules in cwd  (project-level rules)
        """
        from riva.core.skills import Skill

        skills: list[Skill] = []

        for f, workspace in [
            (Path.home() / ".clinerules", None),
            (Path.cwd() / ".clinerules", str(Path.cwd())),
        ]:
            if not f.is_file():
                continue
            try:
                description = ""
                for line in f.read_text(errors="replace").splitlines():
                    stripped = line.strip().lstrip("#").strip()
                    if stripped:
                        description = stripped[:120]
                        break
                skill_id = "cline-rules" if workspace is None else "cline-project-rules"
                skills.append(
                    Skill(
                        id=skill_id,
                        name=".clinerules",
                        description=description,
                        agent=self.agent_name,
                        invocation=None,
                        tags=["rule"],
                        workspace=workspace,
                    )
                )
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ClineDetector()
