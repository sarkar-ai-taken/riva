"""Resource map — aggregates all resources touched by each detected agent.

Covers: filesystem paths, live network connections, process tree (parent
chain + children), sandbox state, MCP servers, and AI environment variables.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from riva.agents.base import AgentInstance
    from riva.agents.registry import AgentRegistry

# ---------------------------------------------------------------------------
# Sub-resource dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FilesystemResources:
    """Filesystem paths touched or owned by an agent."""

    binary_path: str | None = None
    config_dir: str | None = None
    working_directory: str | None = None
    # Top-level files found directly inside config_dir (max 20)
    config_files: list[str] = field(default_factory=list)
    # Recent JSONL session files (max 10)
    session_files: list[str] = field(default_factory=list)


@dataclass
class ConnectionResource:
    """A single network connection endpoint."""

    remote: str = ""  # "host:port" or "ip:port"
    hostname: str | None = None
    service: str | None = None  # human label from KNOWN_API_DOMAINS
    is_tls: bool = False
    status: str = ""


@dataclass
class NetworkResources:
    """Network resources for an agent."""

    api_domain: str | None = None  # primary API domain from detector
    connections: list[ConnectionResource] = field(default_factory=list)


@dataclass
class ProcessResources:
    """Process-level resources for an agent."""

    pid: int | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    launched_by: str | None = None  # "User Terminal", "IDE", "Script", …
    ancestor_chain: list[dict] = field(default_factory=list)  # [{pid, name, exe}]
    children: list[dict] = field(default_factory=list)  # [{pid, name, exe, cpu%, mem_mb}]
    is_sandboxed: bool = False
    sandbox_type: str | None = None  # "docker", "cgroup", …


@dataclass
class MCPServer:
    """One MCP server configured for an agent."""

    name: str = ""
    transport: str = "stdio"  # "stdio" | "http" | "sse"
    command: str | None = None  # for stdio
    url: str | None = None  # for http/sse
    args: list[str] = field(default_factory=list)


@dataclass
class AgentResourceMap:
    """Complete resource map for a single agent."""

    agent_name: str
    status: str  # "running" | "installed" | "not_found"
    pid: int | None
    version: str | None
    filesystem: FilesystemResources
    network: NetworkResources
    processes: ProcessResources
    mcp_servers: list[MCPServer]
    scanned_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-safe)."""
        return {
            "agent_name": self.agent_name,
            "status": self.status,
            "pid": self.pid,
            "version": self.version,
            "scanned_at": self.scanned_at,
            "filesystem": {
                "binary_path": self.filesystem.binary_path,
                "config_dir": self.filesystem.config_dir,
                "working_directory": self.filesystem.working_directory,
                "config_files": self.filesystem.config_files,
                "session_files": self.filesystem.session_files,
            },
            "network": {
                "api_domain": self.network.api_domain,
                "connections": [
                    {
                        "remote": c.remote,
                        "hostname": c.hostname,
                        "service": c.service,
                        "is_tls": c.is_tls,
                        "status": c.status,
                    }
                    for c in self.network.connections
                ],
            },
            "processes": {
                "pid": self.processes.pid,
                "parent_pid": self.processes.parent_pid,
                "parent_name": self.processes.parent_name,
                "launched_by": self.processes.launched_by,
                "ancestor_chain": self.processes.ancestor_chain,
                "children": self.processes.children,
                "is_sandboxed": self.processes.is_sandboxed,
                "sandbox_type": self.processes.sandbox_type,
            },
            "mcp_servers": [
                {
                    "name": m.name,
                    "transport": m.transport,
                    "command": m.command,
                    "url": m.url,
                    "args": m.args,
                }
                for m in self.mcp_servers
            ],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_config_files(config_dir: str | None) -> list[str]:
    """List top-level files inside the agent config directory (max 20)."""
    if not config_dir:
        return []
    try:
        p = Path(config_dir)
        if not p.is_dir():
            return []
        return sorted(str(f) for f in p.iterdir() if f.is_file())[:20]
    except OSError:
        return []


def _collect_session_files(config_dir: str | None) -> list[str]:
    """Find recent JSONL session files under config_dir (max 10)."""
    if not config_dir:
        return []
    try:
        from riva.utils.jsonl import find_recent_sessions

        p = Path(config_dir)
        results = find_recent_sessions(p, "**/*.jsonl", limit=10)
        return [str(r) for r in results]
    except Exception:
        return []


def _extract_mcp_servers(parsed_config: dict) -> list[MCPServer]:
    """Extract MCP server definitions from a parsed agent config dict.

    Handles two common shapes:
      1. {"mcpServers": {name: {command, args, url, type}}}   (Claude Code / VS Code)
      2. {"mcp": {"mcpServers": {name: ...}}}                  (Cursor wrapping)
    """
    servers: list[MCPServer] = []

    # Unwrap Cursor-style nesting: {"mcp": {"mcpServers": {...}}}
    raw = parsed_config.get("mcp", parsed_config)
    mcp_servers_dict = raw.get("mcpServers", {})

    if not isinstance(mcp_servers_dict, dict):
        return servers

    for name, cfg in mcp_servers_dict.items():
        if not isinstance(cfg, dict):
            continue

        # Detect transport
        url = cfg.get("url") or cfg.get("serverUrl")
        transport_hint = cfg.get("type") or cfg.get("transport", "")
        if url:
            transport = "sse" if "sse" in transport_hint.lower() else "http"
        else:
            transport = "stdio"

        command = cfg.get("command")
        args = cfg.get("args", [])
        if isinstance(args, list):
            args = [str(a) for a in args]
        else:
            args = []

        servers.append(
            MCPServer(
                name=name,
                transport=transport,
                command=command,
                url=url,
                args=args,
            )
        )

    return servers


def _network_from_instance(instance: AgentInstance) -> NetworkResources:
    """Build NetworkResources from an AgentInstance."""
    from riva.agents.base import AgentStatus
    from riva.core.network import collect_connections

    net = NetworkResources(api_domain=instance.api_domain)

    if instance.status != AgentStatus.RUNNING or not instance.pid:
        return net

    try:
        conns = collect_connections(instance.pid)
        for c in conns:
            if not c.remote_addr:
                continue
            remote = f"{c.hostname or c.remote_addr}:{c.remote_port}"
            net.connections.append(
                ConnectionResource(
                    remote=remote,
                    hostname=c.hostname,
                    service=c.known_service,
                    is_tls=c.is_tls,
                    status=c.status,
                )
            )
    except Exception:
        pass

    return net


def _processes_from_instance(instance: AgentInstance) -> ProcessResources:
    """Build ProcessResources from an AgentInstance."""
    from riva.agents.base import AgentStatus

    proc = ProcessResources(
        pid=instance.pid,
        parent_pid=instance.parent_pid,
        parent_name=instance.parent_name,
        launched_by=instance.launched_by,
    )

    if instance.status != AgentStatus.RUNNING:
        return proc

    # Launcher ancestor chain (populated by ResourceMonitor)
    launcher = instance.extra.get("launcher", {})
    if isinstance(launcher, dict):
        proc.ancestor_chain = launcher.get("ancestor_chain", [])

    # Children (populated by ResourceMonitor)
    tree = instance.extra.get("process_tree", {})
    if isinstance(tree, dict):
        for child in tree.get("children", []):
            proc.children.append(
                {
                    "pid": child.get("pid"),
                    "name": child.get("name", ""),
                    "exe": child.get("exe", ""),
                    "cpu_percent": child.get("cpu_percent", 0.0),
                    "memory_mb": child.get("memory_mb", 0.0),
                }
            )

    # Sandbox
    sandbox = instance.extra.get("sandbox", {})
    if isinstance(sandbox, dict):
        proc.is_sandboxed = bool(sandbox.get("is_sandboxed", False))
        proc.sandbox_type = sandbox.get("sandbox_type")

    return proc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_resource_map(
    instance: AgentInstance,
    detector=None,
) -> AgentResourceMap:
    """Build an AgentResourceMap for a single agent instance.

    Parameters
    ----------
    instance:
        The scanned AgentInstance (from ResourceMonitor or scan_once).
    detector:
        Optional detector for the agent, used to parse MCP config.
    """
    # --- Filesystem ---------------------------------------------------------
    fs = FilesystemResources(
        binary_path=instance.binary_path,
        config_dir=instance.config_dir,
        working_directory=instance.working_directory,
        config_files=_collect_config_files(instance.config_dir),
        session_files=_collect_session_files(instance.config_dir),
    )

    # --- Network ------------------------------------------------------------
    net = _network_from_instance(instance)

    # --- Processes ----------------------------------------------------------
    proc = _processes_from_instance(instance)

    # --- MCP servers --------------------------------------------------------
    mcp_servers: list[MCPServer] = []
    if detector is not None:
        try:
            parsed = detector.parse_config()
            mcp_servers = _extract_mcp_servers(parsed)
        except Exception:
            pass
    # Also check instance.extra["mcp"] if monitor already populated it
    if not mcp_servers and "mcp" in instance.extra:
        mcp_servers = _extract_mcp_servers({"mcp": instance.extra["mcp"]})

    return AgentResourceMap(
        agent_name=instance.name,
        status=instance.status.value,
        pid=instance.pid,
        version=instance.version,
        filesystem=fs,
        network=net,
        processes=proc,
        mcp_servers=mcp_servers,
        scanned_at=time.time(),
    )


def build_all_resource_maps(
    instances: list[AgentInstance],
    registry: AgentRegistry | None = None,
) -> list[AgentResourceMap]:
    """Build resource maps for all agent instances.

    Parameters
    ----------
    instances:
        List of AgentInstance objects from a scan.
    registry:
        Optional registry to look up detectors for MCP config parsing.
    """
    detector_map = {}
    if registry is not None:
        detector_map = {d.agent_name: d for d in registry.detectors}

    maps = []
    for inst in instances:
        detector = detector_map.get(inst.name)
        maps.append(build_resource_map(inst, detector=detector))

    return maps
