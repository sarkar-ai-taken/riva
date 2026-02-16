"""Policy rule loading and injection into AI agent config files."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

RULES_DIR = "rules"
MARKER_BEGIN = "<!-- RIVA:BEGIN -->"
MARKER_END = "<!-- RIVA:END -->"


@dataclass
class RuleSet:
    """Loaded rules from ``.riva/rules/*.md``."""

    files: list[Path] = field(default_factory=list)
    contents: dict[str, str] = field(default_factory=dict)

    @property
    def combined(self) -> str:
        """Return all rules concatenated with file headers."""
        parts: list[str] = []
        for path in self.files:
            content = self.contents.get(path.name, "")
            if content.strip():
                parts.append(f"## {path.stem}\n\n{content.strip()}")
        return "\n\n---\n\n".join(parts)

    @property
    def is_empty(self) -> bool:
        return not any(c.strip() for c in self.contents.values())


def load_rules(riva_dir: Path) -> RuleSet:
    """Load all ``.md`` files from ``.riva/rules/``."""
    rules_dir = riva_dir / RULES_DIR
    if not rules_dir.is_dir():
        return RuleSet()

    files = sorted(rules_dir.glob("*.md"))
    contents: dict[str, str] = {}
    for f in files:
        try:
            contents[f.name] = f.read_text()
        except OSError:
            logger.warning("Could not read rule file %s", f, exc_info=True)

    return RuleSet(files=files, contents=contents)


def _wrap_with_markers(content: str) -> str:
    """Wrap content in riva marker comments."""
    return f"{MARKER_BEGIN}\n{content}\n{MARKER_END}"


def _strip_markers(text: str) -> str:
    """Remove any riva-marked block from text."""
    pattern = re.compile(
        rf"{re.escape(MARKER_BEGIN)}.*?{re.escape(MARKER_END)}",
        re.DOTALL,
    )
    return pattern.sub("", text).strip()


def inject_rules_claude_code(rules: RuleSet, project_dir: Path) -> Path:
    """Inject rules into ``CLAUDE.md`` using idempotent marker block.

    Creates the file if it doesn't exist; updates the marker block if it does.
    Returns the path to the modified file.
    """
    target = project_dir / "CLAUDE.md"
    block = _wrap_with_markers(rules.combined)

    if target.is_file():
        existing = target.read_text()
        cleaned = _strip_markers(existing)
        new_content = f"{cleaned}\n\n{block}\n" if cleaned else f"{block}\n"
    else:
        new_content = f"{block}\n"

    target.write_text(new_content)
    return target


def inject_rules_cursor(rules: RuleSet, project_dir: Path) -> Path:
    """Inject rules into ``.cursorrules`` using idempotent marker block.

    Returns the path to the modified file.
    """
    target = project_dir / ".cursorrules"
    block = _wrap_with_markers(rules.combined)

    if target.is_file():
        existing = target.read_text()
        cleaned = _strip_markers(existing)
        new_content = f"{cleaned}\n\n{block}\n" if cleaned else f"{block}\n"
    else:
        new_content = f"{block}\n"

    target.write_text(new_content)
    return target


def inject_rules_codex(rules: RuleSet, project_dir: Path) -> Path:
    """Inject rules into ``AGENTS.md`` using idempotent marker block.

    Returns the path to the modified file.
    """
    target = project_dir / "AGENTS.md"
    block = _wrap_with_markers(rules.combined)

    if target.is_file():
        existing = target.read_text()
        cleaned = _strip_markers(existing)
        new_content = f"{cleaned}\n\n{block}\n" if cleaned else f"{block}\n"
    else:
        new_content = f"{block}\n"

    target.write_text(new_content)
    return target


# Map of agent slug -> injection function
INJECTION_FUNCTIONS = {
    "claude-code": inject_rules_claude_code,
    "cursor": inject_rules_cursor,
    "codex-cli": inject_rules_codex,
}


def inject_rules(rules: RuleSet, project_dir: Path, agent_slug: str) -> Path | None:
    """Inject rules for a specific agent by slug.

    Returns the path to the modified file, or None if the agent is unknown.
    """
    func = INJECTION_FUNCTIONS.get(agent_slug)
    if func is None:
        return None
    return func(rules, project_dir)


def remove_injected_rules(project_dir: Path) -> list[Path]:
    """Strip riva-marked content from all known injection targets.

    Returns the list of files that were modified.
    """
    targets = [
        project_dir / "CLAUDE.md",
        project_dir / ".cursorrules",
        project_dir / "AGENTS.md",
    ]
    modified: list[Path] = []
    for target in targets:
        if not target.is_file():
            continue
        original = target.read_text()
        cleaned = _strip_markers(original)
        if cleaned != original:
            if cleaned:
                target.write_text(cleaned + "\n")
            else:
                target.unlink()
            modified.append(target)
    return modified
