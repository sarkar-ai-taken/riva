"""Tests for riva.core.workspace and riva.core.workspace_init."""

from __future__ import annotations

from riva.core.workspace import (
    _merge_toml,
    _slugify_agent_name,
    find_workspace,
    load_agent_config,
    load_workspace_config,
)
from riva.core.workspace_init import init_workspace


class TestSlugify:
    def test_basic(self):
        assert _slugify_agent_name("Claude Code") == "claude-code"

    def test_special_chars(self):
        assert _slugify_agent_name("GitHub Copilot") == "github-copilot"

    def test_already_slug(self):
        assert _slugify_agent_name("cursor") == "cursor"

    def test_extra_spaces(self):
        assert _slugify_agent_name("  Some   Agent  ") == "some-agent"

    def test_dots_and_underscores(self):
        assert _slugify_agent_name("continue.dev") == "continue-dev"


class TestMergeToml:
    def test_shallow_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        assert _merge_toml(base, override) == {"a": 1, "b": 3, "c": 4}

    def test_deep_merge(self):
        base = {"x": {"a": 1, "b": 2}}
        override = {"x": {"b": 3, "c": 4}}
        result = _merge_toml(base, override)
        assert result == {"x": {"a": 1, "b": 3, "c": 4}}

    def test_list_replaced(self):
        base = {"items": [1, 2]}
        override = {"items": [3, 4, 5]}
        assert _merge_toml(base, override) == {"items": [3, 4, 5]}

    def test_empty_override(self):
        base = {"a": 1}
        assert _merge_toml(base, {}) == {"a": 1}

    def test_nested_new_key(self):
        base = {"x": {"a": 1}}
        override = {"x": {"b": 2}, "y": 3}
        result = _merge_toml(base, override)
        assert result == {"x": {"a": 1, "b": 2}, "y": 3}


class TestFindWorkspace:
    def test_finds_riva_dir(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        assert find_workspace(tmp_path) == riva_dir

    def test_finds_in_parent(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        child = tmp_path / "sub" / "deep"
        child.mkdir(parents=True)
        assert find_workspace(child) == riva_dir

    def test_not_found(self, tmp_path):
        child = tmp_path / "no_riva"
        child.mkdir()
        # tmp_path won't have .riva unless we create it
        assert find_workspace(child) is None

    def test_default_cwd(self, tmp_path, monkeypatch):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        assert find_workspace() == riva_dir


class TestLoadWorkspaceConfig:
    def test_loads_config(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        (riva_dir / "config.toml").write_text(
            '[workspace]\nname = "test-project"\nscan_interval = 5.0\n'
            '[agents]\nenabled = ["Claude Code"]\n'
            "[hooks]\nenabled = false\ntimeout = 10\n"
            '[rules]\ninjection_mode = "on_detect"\ntargets = ["cursor"]\n'
        )
        config = load_workspace_config(riva_dir)
        assert config.name == "test-project"
        assert config.scan_interval == 5.0
        assert config.enabled_agents == ["Claude Code"]
        assert config.hooks_enabled is False
        assert config.hooks_timeout == 10
        assert config.rules_injection_mode == "on_detect"
        assert config.rules_targets == ["cursor"]
        assert config.root_dir == tmp_path

    def test_local_override(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        (riva_dir / "config.toml").write_text('[workspace]\nname = "base"\nscan_interval = 2.0\n')
        (riva_dir / "config.local.toml").write_text("[workspace]\nscan_interval = 1.0\n")
        config = load_workspace_config(riva_dir)
        assert config.name == "base"
        assert config.scan_interval == 1.0

    def test_missing_config_uses_defaults(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        config = load_workspace_config(riva_dir)
        assert config.name == tmp_path.name
        assert config.scan_interval == 2.0
        assert config.hooks_enabled is True

    def test_metadata_has_raw_dict(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        (riva_dir / "config.toml").write_text('[workspace]\nname = "meta-test"\n[custom]\nfoo = "bar"\n')
        config = load_workspace_config(riva_dir)
        assert config.metadata["custom"]["foo"] == "bar"


class TestLoadAgentConfig:
    def test_loads_agent_file(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        agents_dir = riva_dir / "agents"
        agents_dir.mkdir(parents=True)
        (agents_dir / "claude-code.toml").write_text("[settings]\nmax_tokens = 4096\n")
        result = load_agent_config(riva_dir, "Claude Code")
        assert result["settings"]["max_tokens"] == 4096

    def test_missing_file_returns_empty(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        result = load_agent_config(riva_dir, "Nonexistent Agent")
        assert result == {}


class TestInitWorkspace:
    def test_creates_scaffold(self, tmp_path):
        riva_dir = init_workspace(tmp_path)
        assert riva_dir == tmp_path / ".riva"
        assert (riva_dir / "config.toml").is_file()
        assert (riva_dir / ".gitignore").is_file()
        assert (riva_dir / "agents").is_dir()
        assert (riva_dir / "hooks").is_dir()
        assert (riva_dir / "detectors").is_dir()
        assert (riva_dir / "rules").is_dir()
        assert (riva_dir / "hooks" / "on_agent_detected.sh").is_file()
        assert (riva_dir / "hooks" / "on_scan_complete.py").is_file()
        assert (riva_dir / "rules" / "security.md").is_file()

    def test_with_agents(self, tmp_path):
        riva_dir = init_workspace(tmp_path, agents=["Claude Code", "Cursor"])
        config_text = (riva_dir / "config.toml").read_text()
        assert '"Claude Code"' in config_text
        assert '"Cursor"' in config_text
        assert (riva_dir / "agents" / "claude-code.toml").is_file()
        assert (riva_dir / "agents" / "cursor.toml").is_file()

    def test_no_hooks(self, tmp_path):
        riva_dir = init_workspace(tmp_path, include_hooks=False)
        assert not (riva_dir / "hooks").exists()

    def test_no_rules(self, tmp_path):
        riva_dir = init_workspace(tmp_path, include_rules=False)
        assert not (riva_dir / "rules").exists()

    def test_gitignore_content(self, tmp_path):
        riva_dir = init_workspace(tmp_path)
        gitignore = (riva_dir / ".gitignore").read_text()
        assert "config.local.toml" in gitignore

    def test_idempotent(self, tmp_path):
        init_workspace(tmp_path)
        # Modify a file
        (tmp_path / ".riva" / "rules" / "security.md").write_text("# Custom\n")
        # Re-init should not overwrite
        init_workspace(tmp_path)
        assert (tmp_path / ".riva" / "rules" / "security.md").read_text() == "# Custom\n"

    def test_config_is_valid_toml(self, tmp_path):
        import tomllib

        riva_dir = init_workspace(tmp_path, agents=["Claude Code"])
        config = tomllib.loads((riva_dir / "config.toml").read_text())
        assert config["workspace"]["name"] == tmp_path.name
        assert "Claude Code" in config["agents"]["enabled"]
