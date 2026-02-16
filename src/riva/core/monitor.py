"""Threaded resource monitor with history ring buffer."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from riva.agents.base import AgentInstance, AgentStatus
from riva.agents.registry import AgentRegistry, get_default_registry
from riva.core.scanner import ProcessScanner

logger = logging.getLogger(__name__)


@dataclass
class ResourceSnapshot:
    """A point-in-time resource snapshot for an agent."""

    timestamp: float
    cpu_percent: float
    memory_mb: float
    connection_count: int = 0
    tree_cpu_percent: float = 0.0
    tree_memory_mb: float = 0.0
    child_count: int = 0


@dataclass
class AgentHistory:
    """Resource history for a single agent instance."""

    agent_name: str
    pid: int | None
    snapshots: deque[ResourceSnapshot] = field(default_factory=lambda: deque(maxlen=60))

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
        storage: Any | None = None,
        workspace_config: Any | None = None,
        otel_exporter: Any | None = None,
    ) -> None:
        self._registry = registry or get_default_registry()
        self._scanner = ProcessScanner(cache_ttl=interval)
        self._interval = interval
        self._history_size = history_size
        self._storage = storage
        self._workspace_config = workspace_config
        self._otel_exporter = otel_exporter

        self._instances: list[AgentInstance] = []
        self._histories: dict[str, AgentHistory] = {}
        self._orphans: list = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._poll_count = 0
        self._previous_running_pids: set[int] = set()

        # Event emitter for lifecycle events
        self._emitter: Any | None = None
        try:
            from riva.core.events import EventEmitter

            self._emitter = EventEmitter()
        except Exception:
            pass

        # Hook runner (if workspace configured)
        self._hook_runner = None
        if workspace_config is not None:
            try:
                from riva.core.hooks import HookRunner

                wc = workspace_config
                if hasattr(wc, "hooks_enabled") and wc.hooks_enabled:
                    self._hook_runner = HookRunner(wc.riva_dir, timeout=getattr(wc, "hooks_timeout", 30))
            except Exception:
                pass

        # Child process tree collector
        self._tree_collector: Any | None = None
        try:
            from riva.core.children import ProcessTreeCollector

            self._tree_collector = ProcessTreeCollector()
        except Exception:
            pass

    @property
    def instances(self) -> list[AgentInstance]:
        with self._lock:
            return list(self._instances)

    @property
    def histories(self) -> dict[str, AgentHistory]:
        with self._lock:
            return dict(self._histories)

    @property
    def orphans(self) -> list:
        with self._lock:
            return list(self._orphans)

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

        # Collect network connections for running agents
        try:
            from riva.core.network import collect_connections

            for inst in refreshed:
                if inst.status == AgentStatus.RUNNING and inst.pid:
                    conns = collect_connections(inst.pid)
                    inst.extra["network"] = [
                        {
                            "local_addr": c.local_addr,
                            "local_port": c.local_port,
                            "remote_addr": c.remote_addr,
                            "remote_port": c.remote_port,
                            "status": c.status,
                            "hostname": c.hostname,
                            "known_service": c.known_service,
                            "is_tls": c.is_tls,
                        }
                        for c in conns
                    ]
        except Exception:
            pass

        # Detect sandbox / container status for running agents
        try:
            from riva.core.sandbox import detect_sandbox

            for inst in refreshed:
                if inst.status == AgentStatus.RUNNING and inst.pid:
                    sandbox = detect_sandbox(inst.pid)
                    inst.extra["sandbox"] = sandbox.to_dict()
        except Exception:
            pass

        # Collect child process trees for running agents
        trees = []
        if self._tree_collector:
            try:
                current_pids: set[int] = set()
                for inst in refreshed:
                    if inst.status == AgentStatus.RUNNING and inst.pid:
                        current_pids.add(inst.pid)
                        tree = self._tree_collector.collect_tree(inst.pid, inst.name)
                        trees.append(tree)
                        inst.extra["process_tree"] = {
                            "tree_cpu_percent": tree.tree_cpu_percent,
                            "tree_memory_mb": tree.tree_memory_mb,
                            "child_count": tree.child_count,
                            "children": [
                                {
                                    "pid": c.pid,
                                    "ppid": c.ppid,
                                    "name": c.name,
                                    "exe": c.exe,
                                    "cpu_percent": c.cpu_percent,
                                    "memory_mb": round(c.memory_mb, 2),
                                    "status": c.status,
                                }
                                for c in tree.children
                            ],
                        }

                # Detect orphans
                new_orphans = self._tree_collector.detect_orphans(current_pids)
                self._tree_collector.update_tracking(trees)
                self._tree_collector.cleanup_orphans()

                # Persist orphans to storage
                if self._storage is not None and new_orphans:
                    for orphan in new_orphans:
                        try:
                            self._storage.record_orphan(
                                {
                                    "agent_name": orphan.agent_name,
                                    "original_parent_pid": orphan.original_parent_pid,
                                    "pid": orphan.pid,
                                    "name": orphan.name,
                                    "exe": orphan.exe,
                                    "detected_at": orphan.detected_at,
                                    "cpu_percent": orphan.cpu_percent,
                                    "memory_mb": orphan.memory_mb,
                                }
                            )
                        except Exception:
                            pass
            except Exception:
                new_orphans = []
        else:
            new_orphans = []

        now = time.time()
        with self._lock:
            self._instances = refreshed
            self._orphans = self._tree_collector.orphans if self._tree_collector else []
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
                conn_count = len(inst.extra.get("network", []))
                tree_data = inst.extra.get("process_tree", {})
                self._histories[key].snapshots.append(
                    ResourceSnapshot(
                        timestamp=now,
                        cpu_percent=inst.cpu_percent,
                        memory_mb=inst.memory_mb,
                        connection_count=conn_count,
                        tree_cpu_percent=tree_data.get("tree_cpu_percent", 0.0),
                        tree_memory_mb=tree_data.get("tree_memory_mb", 0.0),
                        child_count=tree_data.get("child_count", 0),
                    )
                )

        # Emit lifecycle events and fire hooks
        self._emit_lifecycle_events(refreshed)

        # Persist to storage if available
        if self._storage is not None:
            try:
                for inst in refreshed:
                    if inst.status == AgentStatus.RUNNING:
                        conn_count = len(inst.extra.get("network", []))
                        self._storage.record_snapshot(inst, connection_count=conn_count)
                        # Persist child processes
                        tree_data = inst.extra.get("process_tree", {})
                        children = tree_data.get("children", [])
                        if children and inst.pid:
                            # Get the latest snapshot_id for this agent
                            try:
                                conn = self._storage._get_conn()
                                row = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
                                if row:
                                    self._storage.record_child_processes(row["id"], inst.pid, children)
                            except Exception:
                                pass
            except Exception:
                pass

        # Push to OTel exporter if available
        if self._otel_exporter is not None:
            try:
                self._otel_exporter.on_poll(refreshed)
            except Exception:
                pass

        # Periodic cleanup (every ~1800 polls = ~1 hour at 2s interval)
        self._poll_count += 1
        if self._storage is not None and self._poll_count % 1800 == 0:
            try:
                self._storage.cleanup()
            except Exception:
                pass

    @property
    def emitter(self):
        """Return the event emitter (if available)."""
        return self._emitter

    def _emit_lifecycle_events(self, instances: list[AgentInstance]) -> None:
        """Compare current vs previous PIDs and emit lifecycle events."""
        current_pids: set[int] = set()
        for inst in instances:
            if inst.status == AgentStatus.RUNNING and inst.pid:
                current_pids.add(inst.pid)

        new_pids = current_pids - self._previous_running_pids
        gone_pids = self._previous_running_pids - current_pids
        self._previous_running_pids = current_pids

        # Build agent info for hooks
        agent_dicts = [
            {"name": inst.name, "pid": inst.pid, "status": inst.status.value}
            for inst in instances
            if inst.status == AgentStatus.RUNNING
        ]

        if self._emitter:
            for inst in instances:
                if inst.pid in new_pids:
                    self._emitter.emit("agent_detected", agent_name=inst.name, pid=inst.pid)
            for pid in gone_pids:
                self._emitter.emit("agent_stopped", pid=pid)
            self._emitter.emit(
                "scan_complete",
                agents=agent_dicts,
                running_count=len(current_pids),
            )

        # Push lifecycle events to OTel exporter
        if self._otel_exporter is not None:
            try:
                for inst in instances:
                    if inst.pid in new_pids:
                        self._otel_exporter.on_agent_detected(inst.name, inst.pid)
                # Build a name lookup for stopped PIDs
                for pid in gone_pids:
                    self._otel_exporter.on_agent_stopped("unknown", pid)
            except Exception:
                pass

        # Fire hooks in a daemon thread (never blocks polling)
        if self._hook_runner and self._workspace_config:
            self._fire_hooks_async(new_pids, gone_pids, agent_dicts, instances)

    def _fire_hooks_async(
        self,
        new_pids: set[int],
        gone_pids: set[int],
        agent_dicts: list[dict],
        instances: list[AgentInstance],
    ) -> None:
        """Fire hooks in a daemon thread so they never block polling."""
        import time as _time

        from riva.core.hooks import HookContext, HookEvent

        wc = self._workspace_config

        def _run_hooks():
            now = _time.time()
            ws_root = str(wc.root_dir)

            if new_pids:
                detected = [{"name": inst.name, "pid": inst.pid} for inst in instances if inst.pid in new_pids]
                ctx = HookContext(
                    event="agent_detected",
                    timestamp=now,
                    workspace_root=ws_root,
                    agents=detected,
                )
                self._hook_runner.execute(HookEvent.AGENT_DETECTED, ctx)

            if gone_pids:
                ctx = HookContext(
                    event="agent_stopped",
                    timestamp=now,
                    workspace_root=ws_root,
                    extras={"stopped_pids": list(gone_pids)},
                )
                self._hook_runner.execute(HookEvent.AGENT_STOPPED, ctx)

            ctx = HookContext(
                event="scan_complete",
                timestamp=now,
                workspace_root=ws_root,
                agents=agent_dicts,
            )
            self._hook_runner.execute(HookEvent.SCAN_COMPLETE, ctx)

        t = threading.Thread(target=_run_hooks, daemon=True)
        t.start()

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
