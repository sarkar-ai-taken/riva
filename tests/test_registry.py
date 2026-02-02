"""Tests for riva.agents.registry."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from riva.agents.base import AgentDetector, SimpleAgentDetector
from riva.agents.registry import (
    AgentRegistry,
    _REGISTERED_FACTORIES,
    _instantiate,
    get_default_registry,
    register_agent,
)


def _make_simple(name="TestAgent"):
    return SimpleAgentDetector(
        name=name,
        binaries=["test"],
        config="/tmp/riva_nonexistent",
        api="api.test.dev",
    )


class TestInstantiate:
    def test_instantiate_class(self):
        class Dummy(SimpleAgentDetector):
            def __init__(self):
                super().__init__(
                    name="Dummy", binaries=["d"], config="/tmp/x", api="a"
                )

        result = _instantiate(Dummy)
        assert result is not None
        assert result.agent_name == "Dummy"

    def test_instantiate_factory(self):
        def factory():
            return _make_simple("Factory")

        result = _instantiate(factory)
        assert result is not None
        assert result.agent_name == "Factory"

    def test_instantiate_bad_factory_returns_none(self):
        def bad():
            raise RuntimeError("boom")

        assert _instantiate(bad) is None

    def test_instantiate_non_detector_returns_none(self):
        def not_a_detector():
            return "not a detector"

        assert _instantiate(not_a_detector) is None


class TestAgentRegistry:
    def test_register_and_list(self):
        reg = AgentRegistry()
        det = _make_simple("A")
        reg.register(det)
        assert len(reg.detectors) == 1
        assert reg.detectors[0].agent_name == "A"

    def test_dedup_by_name(self):
        reg = AgentRegistry()
        reg.register(_make_simple("A"))
        reg.register(_make_simple("A"))
        assert len(reg.detectors) == 1

    def test_different_names_both_added(self):
        reg = AgentRegistry()
        reg.register(_make_simple("A"))
        reg.register(_make_simple("B"))
        assert len(reg.detectors) == 2

    def test_load_builtins(self):
        reg = AgentRegistry()
        reg.load_builtins()
        names = {d.agent_name for d in reg.detectors}
        assert "Claude Code" in names
        assert "Codex CLI" in names
        assert "Gemini CLI" in names
        assert "OpenClaw" in names

    def test_load_builtins_bad_module_skipped(self):
        reg = AgentRegistry()
        with patch(
            "riva.agents.registry._BUILTIN_MODULES",
            ["riva.agents.claude_code", "riva.agents.nonexistent_module"],
        ):
            reg.load_builtins()
        names = {d.agent_name for d in reg.detectors}
        assert "Claude Code" in names

    def test_load_plugins_from_dir(self, tmp_path):
        plugin = tmp_path / "my_agent.py"
        plugin.write_text(
            "from riva.agents.base import SimpleAgentDetector\n"
            "def create_detector():\n"
            "    return SimpleAgentDetector(\n"
            '        name="PluginAgent", binaries=["plug"],\n'
            '        config="/tmp/x", api="api.plug.dev",\n'
            "    )\n"
        )
        reg = AgentRegistry()
        reg.load_plugins(plugin_dir=tmp_path)
        names = {d.agent_name for d in reg.detectors}
        assert "PluginAgent" in names

    def test_load_plugins_bad_file_skipped(self, tmp_path):
        bad = tmp_path / "bad.py"
        bad.write_text("raise RuntimeError('broken')\n")
        reg = AgentRegistry()
        reg.load_plugins(plugin_dir=tmp_path)
        assert len(reg.detectors) == 0

    def test_load_plugins_nonexistent_dir(self):
        reg = AgentRegistry()
        reg.load_plugins(plugin_dir=Path("/tmp/riva_no_such_dir_xyz"))
        assert len(reg.detectors) == 0

    def test_load_all_loads_builtins(self):
        reg = AgentRegistry()
        # Avoid side effects from plugins/entry_points
        with patch.object(reg, "load_plugins"), patch.object(reg, "load_entry_points"):
            reg.load_all()
        assert len(reg.detectors) >= 4


class TestRegisterAgentDecorator:
    def setup_method(self):
        # Snapshot and restore the global list to avoid test pollution
        self._orig = _REGISTERED_FACTORIES.copy()

    def teardown_method(self):
        _REGISTERED_FACTORIES.clear()
        _REGISTERED_FACTORIES.extend(self._orig)

    def test_decorator_on_factory(self):
        @register_agent
        def create():
            return _make_simple("Decorated")

        reg = AgentRegistry()
        reg.load_decorated()
        names = {d.agent_name for d in reg.detectors}
        assert "Decorated" in names

    def test_decorator_returns_original(self):
        @register_agent
        def my_func():
            return _make_simple("X")

        # Decorator should return the original function
        assert callable(my_func)


class TestGetDefaultRegistry:
    def test_returns_populated_registry(self):
        reg = get_default_registry()
        assert len(reg.detectors) >= 4
        names = {d.agent_name for d in reg.detectors}
        assert "Claude Code" in names
