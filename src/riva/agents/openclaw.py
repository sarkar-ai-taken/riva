"""OpenClaw (Clawdbot) agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class OpenClawDetector(AgentDetector):
    """Detect and parse OpenClaw / Clawdbot."""

    @property
    def agent_name(self) -> str:
        return "OpenClaw"

    @property
    def binary_names(self) -> list[str]:
        return ["openclaw", "moltbot", "clawdbot"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".openclaw"

    @property
    def api_domain(self) -> str:
        return "varies"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # OpenClaw runs as Node.js with cmdline args like "openclaw-gateway",
        # "openclaw-tui", etc.  Match any process whose first cmdline arg
        # starts with one of the known binary names.
        if cmdline:
            arg0 = cmdline[0].rsplit("/", 1)[-1]
            if any(arg0.startswith(b) for b in self.binary_names):
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}
        settings = self._parse_json_config("config.json")
        if settings:
            config["settings"] = settings

        # Check for launchd plist (macOS auto-start)
        launchd_dir = Path.home() / "Library" / "LaunchAgents"
        try:
            if launchd_dir.exists():
                for plist in launchd_dir.iterdir():
                    if "openclaw" in plist.name.lower() or "clawdbot" in plist.name.lower():
                        config["launchd_plist"] = str(plist)
                        break
        except OSError:
            pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return OpenClawDetector()
