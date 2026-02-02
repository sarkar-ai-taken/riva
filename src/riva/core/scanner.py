"""Process scanner using psutil for agent discovery."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import psutil

from riva.agents.base import AgentDetector, AgentInstance
from riva.core.launcher import classify_launcher


@dataclass
class ProcessInfo:
    """Lightweight snapshot of a process."""

    pid: int
    name: str
    cmdline: list[str]
    exe: str
    cpu_percent: float
    memory_mb: float
    create_time: float
    cwd: str | None


class ProcessScanner:
    """Scan running processes and match them against agent detectors."""

    def __init__(self, cache_ttl: float = 2.0) -> None:
        self._cache_ttl = cache_ttl
        self._cache: list[ProcessInfo] = []
        self._cache_time: float = 0.0
        # Persist psutil.Process objects across polls so that
        # cpu_percent(interval=None) has a prior baseline to compare against.
        # Without this, every call is a "first call" and returns 0.0.
        self._proc_map: dict[int, psutil.Process] = {}

    def _refresh_cache(self) -> None:
        """Refresh the process list cache if stale."""
        now = time.monotonic()
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            return

        processes: list[ProcessInfo] = []
        seen_pids: set[int] = set()
        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "exe", "cpu_percent", "memory_info", "create_time"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                seen_pids.add(pid)
                # Keep a reference to the psutil.Process so its internal
                # CPU-time baseline is preserved for the next poll cycle.
                self._proc_map[pid] = proc
                cmdline = info.get("cmdline") or []
                mem_info = info.get("memory_info")
                memory_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0

                try:
                    cwd = proc.cwd()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    cwd = None

                processes.append(
                    ProcessInfo(
                        pid=pid,
                        name=info.get("name") or "",
                        cmdline=cmdline if isinstance(cmdline, list) else [],
                        exe=info.get("exe") or "",
                        cpu_percent=info.get("cpu_percent") or 0.0,
                        memory_mb=memory_mb,
                        create_time=info.get("create_time") or 0.0,
                        cwd=cwd,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Evict dead PIDs from the process map to avoid unbounded growth.
        dead = set(self._proc_map) - seen_pids
        for pid in dead:
            del self._proc_map[pid]

        self._cache = processes
        self._cache_time = now

    def scan(self, detectors: list[AgentDetector]) -> list[AgentInstance]:
        """Scan processes and return matched agent instances."""
        self._refresh_cache()
        now = time.time()
        instances: list[AgentInstance] = []

        # Track which detectors found running processes
        found_detectors: set[str] = set()

        for proc in self._cache:
            for detector in detectors:
                try:
                    if detector.match_process(proc.name, proc.cmdline, proc.exe):
                        uptime = max(0.0, now - proc.create_time) if proc.create_time else 0.0
                        launcher_info = classify_launcher(proc.pid)
                        instance = detector.build_instance(
                            pid=proc.pid,
                            cpu_percent=proc.cpu_percent,
                            memory_mb=proc.memory_mb,
                            uptime_seconds=uptime,
                            working_directory=proc.cwd,
                            command_line=proc.cmdline,
                            parent_pid=launcher_info.parent_pid,
                            parent_name=launcher_info.parent_name,
                            launched_by=launcher_info.launched_by,
                        )
                        instance.extra["launcher"] = launcher_info.to_dict()
                        instances.append(instance)
                        found_detectors.add(detector.agent_name)
                except Exception:
                    continue

        # Add installed-but-not-running agents
        for detector in detectors:
            if detector.agent_name not in found_detectors:
                if detector.is_installed():
                    instances.append(detector.build_instance())

        return instances

    def get_process_info(self, pid: int) -> ProcessInfo | None:
        """Get cached info for a specific PID."""
        self._refresh_cache()
        for proc in self._cache:
            if proc.pid == pid:
                return proc
        return None

    def refresh_instance(self, instance: AgentInstance) -> AgentInstance | None:
        """Refresh resource stats for a running instance.

        CPU is intentionally NOT re-read here.  ``process_iter`` already
        called ``cpu_percent()`` during ``_refresh_cache()`` which set the
        internal baseline.  Calling it again milliseconds later would
        return ~0.0 (near-zero delta) and *overwrite* the correct value
        that ``scan()`` already placed on the instance.  Memory and uptime
        are cheap point-in-time reads and safe to refresh.
        """
        if not instance.pid:
            return instance
        try:
            proc = self._proc_map.get(instance.pid)
            if proc is None:
                proc = psutil.Process(instance.pid)
                self._proc_map[instance.pid] = proc
            mem_info = proc.memory_info()
            instance.memory_mb = mem_info.rss / (1024 * 1024)
            instance.uptime_seconds = max(0.0, time.time() - proc.create_time())
            return instance
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._proc_map.pop(instance.pid, None)
            return None
