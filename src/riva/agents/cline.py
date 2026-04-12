"""Cline (Claude Dev) agent detector."""

from __future__ import annotations

import json
from pathlib import Path

from riva.agents.base import AgentDetector


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
                skills.append(Skill(
                    id=skill_id,
                    name=".clinerules",
                    description=description,
                    agent=self.agent_name,
                    invocation=None,
                    tags=["rule"],
                    workspace=workspace,
                ))
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ClineDetector()
