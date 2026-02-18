"""Lifecycle hook discovery and execution for .riva/ workspaces."""

from __future__ import annotations

import enum
import importlib.util
import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

HOOKS_DIR = "hooks"


class HookEvent(enum.Enum):
    """Lifecycle events that can trigger hooks."""

    AGENT_DETECTED = "agent_detected"
    AGENT_STOPPED = "agent_stopped"
    SCAN_COMPLETE = "scan_complete"
    AUDIT_FINDING = "audit_finding"
    WORKSPACE_LOADED = "workspace_loaded"
    BOUNDARY_VIOLATION = "boundary_violation"


@dataclass
class HookContext:
    """Structured context passed to hook scripts."""

    event: str
    timestamp: float
    workspace_root: str
    agents: list[dict] = field(default_factory=list)
    extras: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(
            {
                "event": self.event,
                "timestamp": self.timestamp,
                "workspace_root": self.workspace_root,
                "agents": self.agents,
                **self.extras,
            },
            default=str,
        )


@dataclass
class HookResult:
    """Result of a single hook execution."""

    hook_path: str
    success: bool
    output: str = ""
    error: str = ""
    duration: float = 0.0


class HookRunner:
    """Discovers and executes hook scripts from ``.riva/hooks/``."""

    def __init__(self, riva_dir: Path, timeout: int = 30) -> None:
        self._hooks_dir = riva_dir / HOOKS_DIR
        self._timeout = timeout

    def discover_hooks(self, event: HookEvent) -> list[Path]:
        """Find scripts matching an event name prefix.

        For ``AGENT_DETECTED``, matches files like
        ``on_agent_detected.sh``, ``on_agent_detected_notify.py``, etc.
        """
        if not self._hooks_dir.is_dir():
            return []

        prefix = f"on_{event.value}"
        hooks: list[Path] = []
        for path in sorted(self._hooks_dir.iterdir()):
            if path.stem.startswith(prefix) and path.suffix in (".sh", ".py"):
                hooks.append(path)
        return hooks

    def execute(self, event: HookEvent, context: HookContext) -> list[HookResult]:
        """Run all hooks for *event* and return results."""
        hooks = self.discover_hooks(event)
        results: list[HookResult] = []
        for hook_path in hooks:
            result = self._run_hook(hook_path, context)
            results.append(result)
        return results

    def _run_hook(self, hook_path: Path, context: HookContext) -> HookResult:
        """Execute a single hook script."""
        start = time.monotonic()
        try:
            if hook_path.suffix == ".sh":
                return self._run_shell_hook(hook_path, context, start)
            elif hook_path.suffix == ".py":
                return self._run_python_hook(hook_path, context, start)
            else:
                return HookResult(
                    hook_path=str(hook_path),
                    success=False,
                    error=f"Unsupported hook type: {hook_path.suffix}",
                    duration=time.monotonic() - start,
                )
        except Exception as exc:
            return HookResult(
                hook_path=str(hook_path),
                success=False,
                error=str(exc),
                duration=time.monotonic() - start,
            )

    def _run_shell_hook(self, hook_path: Path, context: HookContext, start: float) -> HookResult:
        """Run a .sh hook via subprocess with JSON on stdin."""
        try:
            proc = subprocess.run(
                [str(hook_path)],
                input=context.to_json(),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=str(Path(context.workspace_root)),
            )
            return HookResult(
                hook_path=str(hook_path),
                success=proc.returncode == 0,
                output=proc.stdout,
                error=proc.stderr,
                duration=time.monotonic() - start,
            )
        except subprocess.TimeoutExpired:
            return HookResult(
                hook_path=str(hook_path),
                success=False,
                error=f"Hook timed out after {self._timeout}s",
                duration=time.monotonic() - start,
            )

    def _run_python_hook(self, hook_path: Path, context: HookContext, start: float) -> HookResult:
        """Run a .py hook by importing it and calling run(context)."""
        spec = importlib.util.spec_from_file_location(f"riva_hook_{hook_path.stem}", hook_path)
        if not spec or not spec.loader:
            return HookResult(
                hook_path=str(hook_path),
                success=False,
                error="Could not load module spec",
                duration=time.monotonic() - start,
            )

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if not hasattr(module, "run"):
            return HookResult(
                hook_path=str(hook_path),
                success=False,
                error="Hook module has no run() function",
                duration=time.monotonic() - start,
            )

        context_dict = json.loads(context.to_json())
        module.run(context_dict)

        return HookResult(
            hook_path=str(hook_path),
            success=True,
            duration=time.monotonic() - start,
        )
