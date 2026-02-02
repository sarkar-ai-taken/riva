"""Cursor IDE agent detector."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from riva.agents.base import AgentDetector, filter_secrets
from riva.utils.jsonl import find_recent_sessions, stream_jsonl


class CursorDetector(AgentDetector):
    """Detect and parse Cursor IDE (AI-powered code editor)."""

    @property
    def agent_name(self) -> str:
        return "Cursor"

    @property
    def binary_names(self) -> list[str]:
        return ["Cursor", "Cursor Helper"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".cursor"

    @property
    def api_domain(self) -> str:
        return "api2.cursor.sh"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Cursor Helper (Renderer) processes
        if name == "Cursor Helper (Renderer)":
            return True
        # Check exe path for Cursor.app on macOS
        if exe and "Cursor.app" in exe:
            return True
        return False

    def is_installed(self) -> bool:
        if self.config_dir.exists():
            return True
        # macOS app bundle
        app_path = Path("/Applications/Cursor.app")
        if app_path.exists():
            return True
        return super().is_installed()

    def parse_config(self) -> dict:
        config: dict = {}

        # Settings
        settings = self._parse_json_config("settings.json")
        if settings:
            config["settings"] = settings

        # MCP configuration
        mcp_config = self._parse_mcp_config()
        if mcp_config:
            config["mcp"] = mcp_config

        # AI tracking database stats
        tracking_stats = self._parse_tracking_db()
        if tracking_stats:
            config["tracking"] = tracking_stats

        # Session files count
        session_count = self._count_sessions()
        if session_count:
            config["session_count"] = session_count

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config

    def _parse_mcp_config(self) -> dict | None:
        """Parse MCP server configuration from mcp.json."""
        mcp_path = self.config_dir / "mcp.json"
        try:
            if mcp_path.is_file():
                data = json.loads(mcp_path.read_text())
                if isinstance(data, dict):
                    return filter_secrets(data)
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def _parse_tracking_db(self) -> dict | None:
        """Parse AI code tracking database (read-only) for summary stats."""
        db_path = self.config_dir / "ai-tracking" / "ai-code-tracking.db"
        if not db_path.is_file():
            return None
        try:
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
            try:
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = [row["name"] for row in cursor.fetchall()]
                stats: dict = {"tables": tables}

                # Try to get row counts for known tables
                for table in tables[:5]:  # limit to prevent slow queries
                    try:
                        row = conn.execute(f"SELECT COUNT(*) as cnt FROM [{table}]").fetchone()
                        if row:
                            stats[f"{table}_count"] = row["cnt"]
                    except sqlite3.Error:
                        pass

                return stats
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return None

    def _count_sessions(self) -> int | None:
        """Count session JSONL files in projects directory."""
        projects_dir = self.config_dir / "projects"
        if not projects_dir.is_dir():
            return None
        try:
            sessions = find_recent_sessions(projects_dir, "**/*.jsonl", limit=1000)
            return len(sessions) if sessions else None
        except OSError:
            return None


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return CursorDetector()
