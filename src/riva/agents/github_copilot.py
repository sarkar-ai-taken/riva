"""GitHub Copilot agent detector."""

from __future__ import annotations

import json
from pathlib import Path

from riva.agents.base import AgentDetector


class GitHubCopilotDetector(AgentDetector):
    """Detect GitHub Copilot via VS Code extension and language server."""

    @property
    def agent_name(self) -> str:
        return "GitHub Copilot"

    @property
    def binary_names(self) -> list[str]:
        return ["copilot-language-server"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".vscode"

    @property
    def api_domain(self) -> str:
        return "api.github.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Copilot runs as a node process with copilot in the path
        if cmdline:
            joined = " ".join(cmdline)
            if "copilot-language-server" in joined or "github.copilot" in joined:
                return True
        return False

    def is_installed(self) -> bool:
        # Check VS Code extensions directory for Copilot
        extensions_dir = self.config_dir / "extensions"
        if extensions_dir.is_dir():
            try:
                for entry in extensions_dir.iterdir():
                    if entry.name.startswith("github.copilot-") and entry.is_dir():
                        return True
            except OSError:
                pass
        return super().is_installed()

    def parse_config(self) -> dict:
        config: dict = {}

        # Find Copilot extension and extract version
        extensions_dir = self.config_dir / "extensions"
        if extensions_dir.is_dir():
            try:
                copilot_dirs = sorted(
                    [d for d in extensions_dir.iterdir()
                     if d.name.startswith("github.copilot-") and d.is_dir()],
                    key=lambda p: p.name,
                    reverse=True,
                )
                if copilot_dirs:
                    ext_dir = copilot_dirs[0]
                    config["extension_dir"] = str(ext_dir)

                    # Extract version from package.json
                    pkg_json = ext_dir / "package.json"
                    if pkg_json.is_file():
                        try:
                            pkg = json.loads(pkg_json.read_text())
                            config["version"] = pkg.get("version", "unknown")
                            config["display_name"] = pkg.get("displayName", "GitHub Copilot")
                        except (json.JSONDecodeError, OSError):
                            pass

                    # List of Copilot-related extensions
                    all_copilot = [d.name for d in extensions_dir.iterdir()
                                   if d.name.startswith("github.copilot") and d.is_dir()]
                    if all_copilot:
                        config["extensions"] = all_copilot
            except OSError:
                pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return GitHubCopilotDetector()
