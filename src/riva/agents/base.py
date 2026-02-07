"""Base classes for agent detection."""

from __future__ import annotations

import enum
import json
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from riva.core.usage_stats import UsageStats


class AgentStatus(enum.Enum):
    """Status of an AI agent."""

    RUNNING = "running"
    INSTALLED = "installed"
    NOT_FOUND = "not_found"


@dataclass
class AgentInstance:
    """A detected AI agent instance."""

    name: str
    status: AgentStatus
    pid: int | None = None
    binary_path: str | None = None
    config_dir: str | None = None
    version: str | None = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    uptime_seconds: float = 0.0
    working_directory: str | None = None
    command_line: list[str] = field(default_factory=list)
    api_domain: str | None = None
    usage_stats: UsageStats | None = None
    extra: dict = field(default_factory=dict)
    parent_pid: int | None = None
    parent_name: str | None = None
    launched_by: str | None = None


# Secret key names filtered out of parsed configs
SECRET_KEYWORDS = frozenset({"key", "token", "secret", "password", "credential"})


def filter_secrets(data: dict) -> dict:
    """Return a copy of `data` with secret-looking keys removed."""
    return {k: v for k, v in data.items() if not any(s in k.lower() for s in SECRET_KEYWORDS)}


class AgentDetector(ABC):
    """Abstract base class for agent detectors.

    Subclass this for agents that need custom process matching or config
    parsing logic.  For simple agents that just match on process name and
    read a JSON/TOML config, prefer ``SimpleAgentDetector`` instead.
    """

    @property
    @abstractmethod
    def agent_name(self) -> str:
        """Human-readable agent name."""

    @property
    @abstractmethod
    def binary_names(self) -> list[str]:
        """Process names to search for."""

    @property
    @abstractmethod
    def config_dir(self) -> Path:
        """Default configuration directory."""

    @property
    @abstractmethod
    def api_domain(self) -> str:
        """Primary API domain used by this agent."""

    def is_installed(self) -> bool:
        """Check if the agent is installed (binary or config dir exists)."""
        if self.config_dir.exists():
            return True
        for name in self.binary_names:
            if shutil.which(name):
                return True
        return False

    @abstractmethod
    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        """Return True if a process belongs to this agent."""

    @abstractmethod
    def parse_config(self) -> dict:
        """Parse agent configuration. Returns best-effort dict."""

    def parse_usage(self) -> UsageStats | None:
        """Parse usage statistics. Returns ``None`` by default."""
        return None

    def build_instance(
        self,
        *,
        pid: int | None = None,
        cpu_percent: float = 0.0,
        memory_mb: float = 0.0,
        uptime_seconds: float = 0.0,
        working_directory: str | None = None,
        command_line: list[str] | None = None,
        extra: dict | None = None,
        parent_pid: int | None = None,
        parent_name: str | None = None,
        launched_by: str | None = None,
    ) -> AgentInstance:
        """Build an AgentInstance with common fields filled in."""
        binary_path = None
        for name in self.binary_names:
            path = shutil.which(name)
            if path:
                binary_path = path
                break

        status = AgentStatus.RUNNING if pid else AgentStatus.INSTALLED
        if not pid and not self.is_installed():
            status = AgentStatus.NOT_FOUND

        return AgentInstance(
            name=self.agent_name,
            status=status,
            pid=pid,
            binary_path=binary_path,
            config_dir=str(self.config_dir) if self.config_dir.exists() else None,
            cpu_percent=cpu_percent,
            memory_mb=memory_mb,
            uptime_seconds=uptime_seconds,
            working_directory=working_directory,
            command_line=command_line or [],
            api_domain=self.api_domain,
            extra=extra or {},
            parent_pid=parent_pid,
            parent_name=parent_name,
            launched_by=launched_by,
        )

    # --- Helpers available to subclasses -----------------------------------

    def _match_by_name(self, name: str, cmdline: list[str], exe: str) -> bool:
        """Default matching: process name, exe tail, or first cmdline arg."""
        targets = set(self.binary_names)
        if name in targets:
            return True
        if exe:
            exe_tail = exe.rsplit("/", 1)[-1]
            if exe_tail in targets:
                return True
        if cmdline:
            for arg in cmdline[:2]:
                if arg.rsplit("/", 1)[-1] in targets:
                    return True
        return False

    def _parse_json_config(self, filename: str = "settings.json") -> dict:
        """Best-effort JSON config parse with secret filtering."""
        path = self.config_dir / filename
        try:
            if path.exists():
                return filter_secrets(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            return {"_error": f"Could not parse {filename}"}
        return {}

    def _parse_toml_config(self, filename: str = "config.toml") -> dict:
        """Best-effort TOML config parse with secret filtering."""
        import tomllib

        path = self.config_dir / filename
        try:
            if path.exists():
                return filter_secrets(tomllib.loads(path.read_text()))
        except (tomllib.TOMLDecodeError, OSError):
            return {"_error": f"Could not parse {filename}"}
        return {}


# ---------------------------------------------------------------------------
# Data-driven detector for simple agents
# ---------------------------------------------------------------------------


class SimpleAgentDetector(AgentDetector):
    """A data-driven detector that needs no subclassing.

    Use this when an agent can be fully described by its names, paths, and a
    standard config file.  For anything more complex, subclass
    ``AgentDetector`` directly.

    Example::

        detector = SimpleAgentDetector(
            name="My Agent",
            binaries=["myagent"],
            config="~/.myagent",
            api="api.myagent.dev",
        )
    """

    def __init__(
        self,
        *,
        name: str,
        binaries: list[str],
        config: str | Path,
        api: str,
        config_filenames: list[str] | None = None,
        process_matcher: Callable[[str, list[str], str], bool] | None = None,
        config_parser: Callable[[Path], dict] | None = None,
        cmdline_contains: list[str] | None = None,
    ) -> None:
        self._name = name
        self._binaries = binaries
        self._config_dir = Path(config).expanduser()
        self._api = api
        self._config_filenames = config_filenames or ["settings.json", "config.json", "config.toml"]
        self._process_matcher = process_matcher
        self._config_parser = config_parser
        self._cmdline_contains = cmdline_contains or []

    @property
    def agent_name(self) -> str:
        return self._name

    @property
    def binary_names(self) -> list[str]:
        return self._binaries

    @property
    def config_dir(self) -> Path:
        return self._config_dir

    @property
    def api_domain(self) -> str:
        return self._api

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        # Custom matcher takes priority
        if self._process_matcher:
            return self._process_matcher(name, cmdline, exe)

        # Default name-based match
        if self._match_by_name(name, cmdline, exe):
            return True

        # Extra cmdline substring matching (e.g. node + "gemini-cli")
        if self._cmdline_contains and cmdline:
            joined = " ".join(cmdline)
            if any(pat in joined for pat in self._cmdline_contains):
                return True

        return False

    def parse_config(self) -> dict:
        # Custom parser takes priority
        if self._config_parser:
            try:
                return self._config_parser(self.config_dir)
            except Exception:
                return {"_error": "Custom config parser failed"}

        # Auto-detect config files
        config: dict = {}
        for filename in self._config_filenames:
            path = self.config_dir / filename
            if not path.exists():
                continue
            if filename.endswith(".toml"):
                parsed = self._parse_toml_config(filename)
            else:
                parsed = self._parse_json_config(filename)
            if parsed:
                config["settings"] = parsed
                break

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config
