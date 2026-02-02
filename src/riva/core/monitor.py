"""Threaded resource monitor with history ring buffer."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

from riva.agents.base import AgentInstance, AgentStatus
from riva.agents.registry import AgentRegistry, get_default_registry
from riva.core.scanner import ProcessScanner


@dataclass
class ResourceSnapshot:
    """A point-in-time resource snapshot for an agent."""

    timestamp: float
    cpu_percent: float
    memory_mb: float


@dataclass
class AgentHistory:
    """Resource history for a single agent instance."""

    agent_name: str
    pid: int | None
    snapshots: deque[ResourceSnapshot] = field(
        default_factory=lambda: deque(maxlen=60)
    )

    @property
    def cpu_history(self) -> list[float]:
        return [s.cpu_percent for s in self.snapshots]

    @property
    def memory_history(self) -> list[float]:
        return [s.memory_mb for s in self.snapshots]


class ResourceMonitor:
    """Monitor agent resources in a background thread."""

    def __init__(
        self,
        registry: AgentRegistry | None = None,
        interval: float = 2.0,
        history_size: int = 60,
    ) -> None:
        self._registry = registry or get_default_registry()
        self._scanner = ProcessScanner(cache_ttl=interval)
        self._interval = interval
        self._history_size = history_size

        self._instances: list[AgentInstance] = []
        self._histories: dict[str, AgentHistory] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def instances(self) -> list[AgentInstance]:
        with self._lock:
            return list(self._instances)

    @property
    def histories(self) -> dict[str, AgentHistory]:
        with self._lock:
            return dict(self._histories)

    def _history_key(self, instance: AgentInstance) -> str:
        if instance.pid:
            return f"{instance.name}:{instance.pid}"
        return instance.name

    def _poll(self) -> None:
        """Run one scan cycle."""
        instances = self._scanner.scan(self._registry.detectors)

        # Refresh resource stats for running instances
        refreshed = []
        for inst in instances:
            if inst.status == AgentStatus.RUNNING and inst.pid:
                updated = self._scanner.refresh_instance(inst)
                if updated:
                    refreshed.append(updated)
                # Process vanished, skip
            else:
                refreshed.append(inst)

        now = time.time()
        with self._lock:
            self._instances = refreshed
            for inst in refreshed:
                if inst.status != AgentStatus.RUNNING:
                    continue
                key = self._history_key(inst)
                if key not in self._histories:
                    self._histories[key] = AgentHistory(
                        agent_name=inst.name,
                        pid=inst.pid,
                        snapshots=deque(maxlen=self._history_size),
                    )
                self._histories[key].snapshots.append(
                    ResourceSnapshot(
                        timestamp=now,
                        cpu_percent=inst.cpu_percent,
                        memory_mb=inst.memory_mb,
                    )
                )

    def _run(self) -> None:
        """Background thread loop."""
        while not self._stop_event.is_set():
            try:
                self._poll()
            except Exception:
                pass
            self._stop_event.wait(self._interval)

    def start(self) -> None:
        """Start the background monitor thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background monitor thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

    def scan_once(self) -> list[AgentInstance]:
        """Run a single scan without starting the background thread."""
        self._poll()
        return self.instances
