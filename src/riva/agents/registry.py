"""Agent registry with auto-discovery, decorator registration, and plugin loading."""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import logging
from pathlib import Path

from riva.agents.base import AgentDetector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level registry for @register_agent decorator
# ---------------------------------------------------------------------------

_REGISTERED_FACTORIES: list[type[AgentDetector] | callable] = []


def register_agent(cls_or_fn):
    """Decorator that registers a detector class or factory function.

    Works on either a class (must be an ``AgentDetector`` subclass) or a
    callable that returns one::

        @register_agent
        class MyDetector(AgentDetector):
            ...

        @register_agent
        def create_detector():
            return SimpleAgentDetector(name="X", ...)
    """
    _REGISTERED_FACTORIES.append(cls_or_fn)
    return cls_or_fn


# ---------------------------------------------------------------------------
# Builtin module paths — auto-discovered, no manual import list
# ---------------------------------------------------------------------------

_BUILTIN_MODULES = [
    "riva.agents.claude_code",
    "riva.agents.codex_cli",
    "riva.agents.gemini_cli",
    "riva.agents.openclaw",
    "riva.agents.langgraph",
    "riva.agents.crewai",
    "riva.agents.autogen",
    "riva.agents.cursor",
    "riva.agents.github_copilot",
    "riva.agents.windsurf",
    "riva.agents.continue_dev",
    "riva.agents.cline",
    "riva.agents.opencode",
]

# Entry-point group that third-party packages can use in their pyproject.toml:
#   [project.entry-points."riva.agents"]
#   my_agent = "my_package.detector:create_detector"
_ENTRY_POINT_GROUP = "riva.agents"


def _instantiate(cls_or_fn) -> AgentDetector | None:
    """Turn a class or factory into an AgentDetector instance."""
    try:
        if isinstance(cls_or_fn, type) and issubclass(cls_or_fn, AgentDetector):
            return cls_or_fn()
        result = cls_or_fn()
        if isinstance(result, AgentDetector):
            return result
    except Exception:
        logger.debug("Failed to instantiate %s", cls_or_fn, exc_info=True)
    return None


class AgentRegistry:
    """Registry of agent detectors.

    Detectors can be added in four ways (checked in this order):

    1. **@register_agent decorator** — any module that uses the decorator and
       has been imported will have its detectors picked up automatically.
    2. **Builtin auto-discovery** — the four shipped detector modules are
       imported automatically; each exposes a ``create_detector()`` factory.
    3. **entry_points** — third-party packages declare
       ``[project.entry-points."riva.agents"]`` in their pyproject.toml.
    4. **Plugin directory** — drop a ``.py`` file with ``create_detector()``
       into ``~/.config/riva/plugins/``.
    """

    def __init__(self) -> None:
        self._detectors: list[AgentDetector] = []
        self._seen_names: set[str] = set()

    def register(self, detector: AgentDetector) -> None:
        """Register a detector, deduplicating by agent_name."""
        if detector.agent_name in self._seen_names:
            return
        self._detectors.append(detector)
        self._seen_names.add(detector.agent_name)

    @property
    def detectors(self) -> list[AgentDetector]:
        return list(self._detectors)

    # --- Loading strategies ------------------------------------------------

    def load_decorated(self) -> None:
        """Pick up detectors registered via ``@register_agent``."""
        for cls_or_fn in _REGISTERED_FACTORIES:
            det = _instantiate(cls_or_fn)
            if det:
                self.register(det)

    def load_builtins(self) -> None:
        """Auto-import builtin detector modules and call create_detector()."""
        for modname in _BUILTIN_MODULES:
            try:
                mod = importlib.import_module(modname)
                if hasattr(mod, "create_detector"):
                    det = mod.create_detector()
                    if isinstance(det, AgentDetector):
                        self.register(det)
            except Exception:
                logger.debug("Could not load builtin %s", modname, exc_info=True)

    def load_entry_points(self) -> None:
        """Load detectors from pip-installed packages via entry_points."""
        try:
            eps = importlib.metadata.entry_points()
            # Python 3.12+: eps is a SelectableGroups / dict-like
            group = eps.select(group=_ENTRY_POINT_GROUP) if hasattr(eps, "select") else eps.get(_ENTRY_POINT_GROUP, [])
            for ep in group:
                try:
                    factory = ep.load()
                    det = _instantiate(factory)
                    if det:
                        self.register(det)
                except Exception:
                    logger.debug("Entry-point %s failed", ep.name, exc_info=True)
        except Exception:
            logger.debug("entry_points discovery failed", exc_info=True)

    def load_plugins(self, plugin_dir: Path | None = None) -> None:
        """Load plugin detectors from a directory of .py files.

        Each file must expose a ``create_detector()`` function that returns
        an ``AgentDetector``.
        """
        if plugin_dir is None:
            plugin_dir = Path.home() / ".config" / "riva" / "plugins"

        if not plugin_dir.exists():
            return

        for path in sorted(plugin_dir.glob("*.py")):
            try:
                spec = importlib.util.spec_from_file_location(f"riva_plugin_{path.stem}", path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, "create_detector"):
                        det = _instantiate(module.create_detector)
                        if det:
                            self.register(det)
            except Exception:
                logger.debug("Plugin %s failed", path, exc_info=True)

    def load_all(self) -> None:
        """Load from every source in priority order."""
        self.load_decorated()
        self.load_builtins()
        self.load_entry_points()
        self.load_plugins()


def get_default_registry() -> AgentRegistry:
    """Create a fully-loaded registry (builtins + entry_points + plugins)."""
    registry = AgentRegistry()
    registry.load_all()
    return registry
