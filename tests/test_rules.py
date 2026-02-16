"""Tests for riva.core.rules."""

from __future__ import annotations

from riva.core.rules import (
    MARKER_BEGIN,
    MARKER_END,
    inject_rules,
    inject_rules_claude_code,
    inject_rules_codex,
    inject_rules_cursor,
    load_rules,
    remove_injected_rules,
)


def _make_rules(tmp_path):
    """Create a .riva/rules/ dir with sample rules."""
    riva_dir = tmp_path / ".riva"
    rules_dir = riva_dir / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "security.md").write_text("# Security\n\nDo not expose secrets.\n")
    (rules_dir / "coding.md").write_text("# Coding\n\nUse type hints.\n")
    return riva_dir


class TestLoadRules:
    def test_loads_md_files(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        assert len(rules.files) == 2
        assert "security.md" in rules.contents
        assert "coding.md" in rules.contents

    def test_missing_dir(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        rules = load_rules(riva_dir)
        assert rules.is_empty
        assert rules.files == []

    def test_combined_output(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        combined = rules.combined
        assert "Security" in combined
        assert "Coding" in combined
        assert "---" in combined


class TestInjectRulesClaudeCode:
    def test_creates_new_file(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        result = inject_rules_claude_code(rules, tmp_path)
        assert result == tmp_path / "CLAUDE.md"
        content = result.read_text()
        assert MARKER_BEGIN in content
        assert MARKER_END in content
        assert "Do not expose secrets" in content

    def test_preserves_existing_content(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        (tmp_path / "CLAUDE.md").write_text("# My Project\n\nExisting content.\n")
        inject_rules_claude_code(rules, tmp_path)
        content = (tmp_path / "CLAUDE.md").read_text()
        assert "Existing content" in content
        assert MARKER_BEGIN in content

    def test_idempotent(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        inject_rules_claude_code(rules, tmp_path)
        first = (tmp_path / "CLAUDE.md").read_text()
        inject_rules_claude_code(rules, tmp_path)
        second = (tmp_path / "CLAUDE.md").read_text()
        assert first == second


class TestInjectRulesCursor:
    def test_creates_cursorrules(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        result = inject_rules_cursor(rules, tmp_path)
        assert result == tmp_path / ".cursorrules"
        content = result.read_text()
        assert MARKER_BEGIN in content


class TestInjectRulesCodex:
    def test_creates_agents_md(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        result = inject_rules_codex(rules, tmp_path)
        assert result == tmp_path / "AGENTS.md"
        content = result.read_text()
        assert MARKER_BEGIN in content


class TestInjectRulesDispatch:
    def test_known_agent(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        result = inject_rules(rules, tmp_path, "claude-code")
        assert result is not None
        assert result.name == "CLAUDE.md"

    def test_unknown_agent(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        result = inject_rules(rules, tmp_path, "unknown-agent")
        assert result is None


class TestRemoveInjectedRules:
    def test_removes_from_all_targets(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        inject_rules_claude_code(rules, tmp_path)
        inject_rules_cursor(rules, tmp_path)
        inject_rules_codex(rules, tmp_path)

        modified = remove_injected_rules(tmp_path)
        assert len(modified) == 3

        # Files with only riva content should be removed
        assert not (tmp_path / "CLAUDE.md").exists()
        assert not (tmp_path / ".cursorrules").exists()
        assert not (tmp_path / "AGENTS.md").exists()

    def test_preserves_non_riva_content(self, tmp_path):
        riva_dir = _make_rules(tmp_path)
        rules = load_rules(riva_dir)
        (tmp_path / "CLAUDE.md").write_text("# My Project\n")
        inject_rules_claude_code(rules, tmp_path)
        remove_injected_rules(tmp_path)

        assert (tmp_path / "CLAUDE.md").is_file()
        content = (tmp_path / "CLAUDE.md").read_text()
        assert "My Project" in content
        assert MARKER_BEGIN not in content

    def test_no_files_to_modify(self, tmp_path):
        modified = remove_injected_rules(tmp_path)
        assert modified == []
