"""Child process tracking and orphan detection for Riva."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import psutil


@dataclass
class ChildProcessInfo:
    """Information about a single child process."""

    pid: int
    ppid: int
    name: str = ""
    cmdline: str = ""
    exe: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    create_time: float = 0.0
    status: str = ""


@dataclass
class ProcessTree:
    """Aggregated process tree for an agent."""

    parent_pid: int
    agent_name: str
    children: list[ChildProcessInfo] = field(default_factory=list)
    tree_cpu_percent: float = 0.0
    tree_memory_mb: float = 0.0
    child_count: int = 0


@dataclass
class OrphanProcess:
    """A child process whose parent agent has died."""

    pid: int
    original_parent_pid: int
    agent_name: str
    name: str = ""
    cmdline: str = ""
    exe: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    detected_at: float = 0.0
    current_ppid: int = 0


class ProcessTreeCollector:
    """Collects child process trees and detects orphans."""

    def __init__(self) -> None:
        # Maps parent PID -> set of child PIDs from previous cycle
        self._prev_children: dict[int, set[int]] = {}
        # Maps parent PID -> agent name from previous cycle
        self._parent_agent_map: dict[int, str] = {}
        # Currently tracked orphans
        self._orphans: list[OrphanProcess] = []
        # Persist psutil.Process objects so cpu_percent() has a baseline.
        self._child_proc_map: dict[int, psutil.Process] = {}

    def collect_tree(self, pid: int, agent_name: str) -> ProcessTree:
        """Collect the child process tree for a given agent PID.

        Uses psutil.Process.children(recursive=True) and aggregates
        resource usage across all children.
        """
        tree = ProcessTree(parent_pid=pid, agent_name=agent_name)

        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return tree

        total_cpu = 0.0
        total_mem = 0.0
        seen_child_pids: set[int] = set()

        for child in children:
            try:
                # Reuse the cached Process object so cpu_percent() has a
                # prior baseline instead of always returning 0.0.
                cached = self._child_proc_map.get(child.pid)
                if cached is not None:
                    try:
                        # Verify it's still the same process
                        if cached.create_time() == child.create_time():
                            child = cached
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self._child_proc_map[child.pid] = child
                seen_child_pids.add(child.pid)

                with child.oneshot():
                    child_info = ChildProcessInfo(
                        pid=child.pid,
                        ppid=child.ppid(),
                        name=child.name(),
                        cpu_percent=child.cpu_percent(),
                        memory_mb=child.memory_info().rss / (1024 * 1024),
                        create_time=child.create_time(),
                        status=child.status(),
                    )
                    try:
                        child_info.cmdline = " ".join(child.cmdline())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    try:
                        child_info.exe = child.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                total_cpu += child_info.cpu_percent
                total_mem += child_info.memory_mb
                tree.children.append(child_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Evict dead child PIDs to avoid unbounded growth.
        dead = set(self._child_proc_map) - seen_child_pids
        for cpid in dead:
            del self._child_proc_map[cpid]

        tree.tree_cpu_percent = round(total_cpu, 2)
        tree.tree_memory_mb = round(total_mem, 2)
        tree.child_count = len(tree.children)
        return tree

    def detect_orphans(self, current_agent_pids: set[int]) -> list[OrphanProcess]:
        """Detect orphan processes by comparing current agent PIDs with previous cycle.

        If a parent PID from the previous cycle is no longer in the current set
        of agent PIDs, check if its children are still running. Those still-alive
        children become orphans.
        """
        new_orphans: list[OrphanProcess] = []
        now = time.time()

        dead_parents = set(self._prev_children.keys()) - current_agent_pids

        for dead_pid in dead_parents:
            agent_name = self._parent_agent_map.get(dead_pid, "unknown")
            child_pids = self._prev_children.get(dead_pid, set())

            for cpid in child_pids:
                try:
                    proc = self._child_proc_map.get(cpid) or psutil.Process(cpid)
                    with proc.oneshot():
                        orphan = OrphanProcess(
                            pid=cpid,
                            original_parent_pid=dead_pid,
                            agent_name=agent_name,
                            name=proc.name(),
                            cpu_percent=proc.cpu_percent(),
                            memory_mb=proc.memory_info().rss / (1024 * 1024),
                            detected_at=now,
                            current_ppid=proc.ppid(),
                        )
                        try:
                            orphan.cmdline = " ".join(proc.cmdline())
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        try:
                            orphan.exe = proc.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                    new_orphans.append(orphan)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        self._orphans.extend(new_orphans)
        return new_orphans

    def update_tracking(self, trees: list[ProcessTree]) -> None:
        """Update internal tracking state for the next detection cycle."""
        self._prev_children.clear()
        self._parent_agent_map.clear()
        for tree in trees:
            child_pids = {c.pid for c in tree.children}
            self._prev_children[tree.parent_pid] = child_pids
            self._parent_agent_map[tree.parent_pid] = tree.agent_name

    def cleanup_orphans(self) -> None:
        """Remove orphans that are no longer running."""
        alive: list[OrphanProcess] = []
        for orphan in self._orphans:
            if psutil.pid_exists(orphan.pid):
                alive.append(orphan)
        self._orphans = alive

    @property
    def orphans(self) -> list[OrphanProcess]:
        """Return currently tracked orphans."""
        return list(self._orphans)
