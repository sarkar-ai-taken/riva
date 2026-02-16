"""Sandbox / container detection for agent processes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import psutil

# Container runtime process names
_CONTAINER_RUNTIMES: dict[str, str] = {
    "dockerd": "docker",
    "docker": "docker",
    "containerd": "containerd",
    "containerd-shim": "containerd",
    "podman": "podman",
    "crio": "cri-o",
    "lxc-start": "lxc",
    "runc": "runc",
}

# Sandbox tool process names
_SANDBOX_TOOLS = frozenset(
    {
        "firejail",
        "bubblewrap",
        "bwrap",
        "nsjail",
        "sandbox-exec",
        "flatpak",
    }
)


@dataclass
class SandboxInfo:
    """Sandbox status of a process."""

    is_sandboxed: bool
    sandbox_type: str  # "host", "container", "sandbox"
    runtime: str | None = None
    container_id: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "is_sandboxed": self.is_sandboxed,
            "sandbox_type": self.sandbox_type,
        }
        if self.runtime:
            d["runtime"] = self.runtime
        if self.container_id:
            d["container_id"] = self.container_id
        return d


_HOST = SandboxInfo(is_sandboxed=False, sandbox_type="host")


def detect_sandbox(pid: int) -> SandboxInfo:
    """Detect if a process is running inside a sandbox or container."""
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return _HOST

    # 1. Linux cgroup-based detection (most reliable)
    result = _check_cgroup(pid)
    if result:
        return result

    # 2. Walk parent process chain for container / sandbox runtimes
    result = _check_parent_chain(proc)
    if result:
        return result

    # 3. Check if *we* are inside a container (/.dockerenv, /run/.containerenv)
    if Path("/.dockerenv").exists():
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="docker",
        )
    if Path("/run/.containerenv").exists():
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="podman",
        )

    # 4. Process environment variables
    result = _check_env(proc)
    if result:
        return result

    return _HOST


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_cgroup(pid: int) -> SandboxInfo | None:
    """Check Linux /proc/{pid}/cgroup for container indicators."""
    cgroup_path = Path(f"/proc/{pid}/cgroup")
    if not cgroup_path.exists():
        return None
    try:
        content = cgroup_path.read_text()
    except OSError:
        return None

    if "/docker/" in content:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="docker",
            container_id=_extract_container_id(content, "/docker/"),
        )
    if "/libpod-" in content:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="podman",
            container_id=_extract_container_id(content, "/libpod-"),
        )
    if "/containerd/" in content:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="containerd",
        )
    if "/lxc/" in content:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="lxc",
        )
    return None


def _extract_container_id(content: str, marker: str) -> str | None:
    """Extract a short container ID from cgroup content."""
    for line in content.splitlines():
        idx = line.find(marker)
        if idx < 0:
            continue
        tail = line[idx + len(marker) :]
        # Grab the first path segment / hash
        cid = tail.split("/")[0].split(".")[0]
        if len(cid) >= 12:
            return cid[:12]
    return None


def _check_parent_chain(proc: psutil.Process) -> SandboxInfo | None:
    """Walk parent processes looking for container / sandbox runtimes."""
    try:
        parents = proc.parents()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    for parent in parents:
        try:
            pname = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        runtime = _CONTAINER_RUNTIMES.get(pname)
        if runtime:
            return SandboxInfo(
                is_sandboxed=True,
                sandbox_type="container",
                runtime=runtime,
            )
        if pname in _SANDBOX_TOOLS:
            return SandboxInfo(
                is_sandboxed=True,
                sandbox_type="sandbox",
                runtime=pname,
            )

    return None


def _check_env(proc: psutil.Process) -> SandboxInfo | None:
    """Check process environment for container indicators."""
    try:
        env = proc.environ()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None

    if "KUBERNETES_SERVICE_HOST" in env:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="kubernetes",
        )

    val = env.get("container") or env.get("CONTAINER")
    if val:
        return SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime=val,
        )

    return None
