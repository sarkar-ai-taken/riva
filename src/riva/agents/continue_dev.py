"""Continue.dev agent detector."""

from __future__ import annotations

import json
from pathlib import Path

from riva.agents.base import AgentDetector, filter_secrets


class ContinueDevDetector(AgentDetector):
    """Detect Continue.dev AI coding assistant."""

    @property
    def agent_name(self) -> str:
        return "Continue"

    @property
    def binary_names(self) -> list[str]:
        return ["continue"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".continue"

    @property
    def api_domain(self) -> str:
        return "api.continue.dev"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Continue runs as a VS Code extension with a language server
        if cmdline:
            joined = " ".join(cmdline)
            if "continue" in joined and ("language-server" in joined or "extension" in joined):
                return True
        return False

    def is_installed(self) -> bool:
        if self.config_dir.exists():
            return True
        # Check VS Code extensions
        vscode_ext = Path.home() / ".vscode" / "extensions"
        if vscode_ext.is_dir():
            try:
                for entry in vscode_ext.iterdir():
                    if entry.name.startswith("continue.continue-") and entry.is_dir():
                        return True
            except OSError:
                pass
        return super().is_installed()

    def parse_config(self) -> dict:
        config: dict = {}

        # Parse config.json
        config_json = self.config_dir / "config.json"
        if config_json.is_file():
            try:
                data = json.loads(config_json.read_text())
                filtered = filter_secrets(data)

                # Extract model info if available
                models = data.get("models", [])
                if models:
                    config["models"] = [
                        {"title": m.get("title", ""), "provider": m.get("provider", "")}
                        for m in models
                        if isinstance(m, dict)
                    ]

                # Extract tab autocomplete model
                tab_model = data.get("tabAutocompleteModel", {})
                if isinstance(tab_model, dict) and tab_model:
                    config["tab_autocomplete"] = {
                        "title": tab_model.get("title", ""),
                        "provider": tab_model.get("provider", ""),
                    }

                config["settings"] = filtered
            except (json.JSONDecodeError, OSError):
                config["settings"] = {"_error": "Could not parse config.json"}

        # Parse config.ts if exists (newer Continue versions)
        config_ts = self.config_dir / "config.ts"
        if config_ts.is_file():
            config["has_config_ts"] = True

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ContinueDevDetector()
