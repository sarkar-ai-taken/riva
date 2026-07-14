"""Gemini CLI (Google) agent detector."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from riva.agents.base import AgentDetector
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)
from riva.utils.jsonl import find_recent_sessions


class GeminiCLIDetector(AgentDetector):
    """Detect and parse Google Gemini CLI."""

    @property
    def agent_name(self) -> str:
        return "Gemini CLI"

    @property
    def binary_names(self) -> list[str]:
        return ["gemini"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".gemini"

    @property
    def api_domain(self) -> str:
        return "generativelanguage.googleapis.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Gemini CLI also runs as a Node.js script
        if name == "node" and cmdline:
            cmdline_str = " ".join(cmdline)
            if "gemini-cli" in cmdline_str or "@google/gemini" in cmdline_str:
                return True
        return False

    # ------------------------------------------------------------------
    # Usage statistics
    # ------------------------------------------------------------------

    def parse_usage(self) -> UsageStats | None:
        """Parse usage stats from Gemini CLI session data.

        Scans ``~/.gemini/tmp/<project_hash>/``:
        - ``logs.json`` — array of user message log entries (sessions, messages)
        - ``chats/*.json`` — saved sessions with per-message token counts,
          model ids, and tool calls (format varies across CLI versions)
        """
        try:
            return self._parse_usage_inner()
        except Exception:
            return None

    def _parse_usage_inner(self) -> UsageStats | None:
        tmp_dir = self.config_dir / "tmp"
        if not tmp_dir.is_dir():
            return None

        model_tokens: dict[str, TokenUsage] = defaultdict(TokenUsage)
        tool_counts: dict[str, int] = defaultdict(int)
        tool_last_used: dict[str, str] = {}
        daily_counts: dict[str, dict] = defaultdict(lambda: {"messages": 0, "sessions": 0, "tokens": 0, "tools": 0})
        session_ids: set[str] = set()
        total_messages = 0
        total_tool_calls = 0
        found_data = False

        for project_dir in tmp_dir.iterdir():
            if not project_dir.is_dir():
                continue

            # --- logs.json: user message log ---------------------------------
            logs_file = project_dir / "logs.json"
            if logs_file.is_file():
                try:
                    entries = json.loads(logs_file.read_text(errors="replace"))
                except (json.JSONDecodeError, OSError):
                    entries = []
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        found_data = True
                        total_messages += 1
                        sid = entry.get("sessionId", "")
                        ts = str(entry.get("timestamp", ""))
                        date_key = ts[:10] if len(ts) >= 10 else ""
                        if date_key:
                            daily_counts[date_key]["messages"] += 1
                        if sid and sid not in session_ids:
                            session_ids.add(sid)
                            if date_key:
                                daily_counts[date_key]["sessions"] += 1

            # --- chats/*.json: saved sessions with token counts --------------
            chats_dir = project_dir / "chats"
            if not chats_dir.is_dir():
                continue
            for chat_file in find_recent_sessions(chats_dir, "*.json", limit=20):
                try:
                    data = json.loads(chat_file.read_text(errors="replace"))
                except (json.JSONDecodeError, OSError):
                    continue

                # Session format: {"sessionId": ..., "messages": [...]}
                # Checkpoint format: bare list of Content objects
                if isinstance(data, dict):
                    messages = data.get("messages", data.get("history", []))
                    sid = data.get("sessionId", "")
                    if sid:
                        session_ids.add(sid)
                else:
                    messages = data
                if not isinstance(messages, list):
                    continue

                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    found_data = True
                    ts = str(msg.get("timestamp", ""))
                    date_key = ts[:10] if len(ts) >= 10 else ""

                    # Token counts: {"tokens": {"input": .., "output": .., "cached": ..}}
                    # or Gemini API usageMetadata {"promptTokenCount": .., ...}
                    model = msg.get("model", "unknown")
                    tokens = msg.get("tokens")
                    meta = msg.get("usageMetadata")
                    turn_tokens = 0
                    if isinstance(tokens, dict):
                        usage = model_tokens[model]
                        usage.input_tokens += tokens.get("input", 0)
                        usage.output_tokens += tokens.get("output", 0) + tokens.get("thoughts", 0)
                        usage.cache_read_input_tokens += tokens.get("cached", 0)
                        turn_tokens = tokens.get("input", 0) + tokens.get("output", 0)
                    elif isinstance(meta, dict):
                        usage = model_tokens[model]
                        usage.input_tokens += meta.get("promptTokenCount", 0)
                        usage.output_tokens += meta.get("candidatesTokenCount", 0)
                        usage.cache_read_input_tokens += meta.get("cachedContentTokenCount", 0)
                        turn_tokens = meta.get("promptTokenCount", 0) + meta.get("candidatesTokenCount", 0)
                    if turn_tokens and date_key:
                        daily_counts[date_key]["tokens"] += turn_tokens

                    # Tool calls: functionCall parts (checkpoint/session formats)
                    for part in msg.get("parts", []) or []:
                        if not isinstance(part, dict):
                            continue
                        fc = part.get("functionCall")
                        if isinstance(fc, dict):
                            name = fc.get("name", "unknown")
                            tool_counts[name] += 1
                            total_tool_calls += 1
                            if ts:
                                tool_last_used[name] = ts
                            if date_key:
                                daily_counts[date_key]["tools"] += 1

        if not found_data:
            return None

        model_stats: dict[str, ModelStats] = {}
        total_tokens = 0
        for model_id, usage in model_tokens.items():
            model_stats[model_id] = ModelStats(model_id=model_id, usage=usage)
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
            total_sessions=len(session_ids),
            total_tool_calls=total_tool_calls,
            time_range_start=daily_activity[0].date if daily_activity else None,
            time_range_end=daily_activity[-1].date if daily_activity else None,
        )

    def parse_config(self) -> dict:
        config: dict = {}

        settings = self._parse_json_config("settings.json")
        if settings:
            config["settings"] = settings

        extra = self._parse_json_config("config.json")
        if extra:
            config["config"] = extra

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config

    def write_skill(self, skill, workspace=None):
        """Append a skill section to GEMINI.md in the target workspace."""
        base = Path(workspace) if workspace else Path.cwd()
        path = base / "GEMINI.md"

        section = f"\n\n## {skill.name}\n\n{skill.description or ''}\n"

        if path.exists():
            existing = path.read_text(encoding="utf-8")
            if f"## {skill.name}" in existing:
                return path
            path.write_text(existing.rstrip() + section, encoding="utf-8")
        else:
            path.write_text(f"# Gemini Instructions{section}", encoding="utf-8")
        return path

    def parse_skills(self) -> list:
        """Discover Gemini CLI instruction files as skills.

        Reads:
        - ~/.gemini/GEMINI.md  (global system instructions)
        - GEMINI.md in cwd  (project-level instructions)
        """
        from riva.core.skills import Skill

        skills: list[Skill] = []

        for f, workspace in [
            (self.config_dir / "GEMINI.md", None),
            (Path.cwd() / "GEMINI.md", str(Path.cwd())),
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
                skill_id = "gemini-instructions" if workspace is None else "gemini-project-instructions"
                skills.append(
                    Skill(
                        id=skill_id,
                        name="GEMINI.md",
                        description=description,
                        agent=self.agent_name,
                        invocation=None,
                        tags=["instruction"],
                        workspace=workspace,
                        file_path=str(f),
                    )
                )
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return GeminiCLIDetector()
