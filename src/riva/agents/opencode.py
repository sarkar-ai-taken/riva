"""OpenCode agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class OpenCodeDetector(AgentDetector):
    """Detect OpenCode — open-source AI coding agent for the terminal.

    OpenCode is a Go-based CLI that provides a TUI for interacting with
    various AI providers.  Config lives in ``~/.config/opencode/`` and the
    binary is simply ``opencode``.
    """

    @property
    def agent_name(self) -> str:
        return "OpenCode"

    @property
    def binary_names(self) -> list[str]:
        return ["opencode"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".config" / "opencode"

    @property
    def api_domain(self) -> str:
        return "varies"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # OpenCode may also appear in cmdline arguments
        if cmdline:
            joined = " ".join(cmdline)
            if "opencode" in joined:
                return True
        return False

    def is_installed(self) -> bool:
        if self.config_dir.exists():
            return True
        return super().is_installed()

    def parse_config(self) -> dict:
        config: dict = {}

        # OpenCode uses opencode.json as its main config
        settings = self._parse_json_config("opencode.json")
        if settings:
            config["settings"] = settings

        # Also check config.yaml via a simple existence check
        config_yaml = self.config_dir / "config.yaml"
        if config_yaml.is_file():
            config["has_config_yaml"] = True

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return OpenCodeDetector()
