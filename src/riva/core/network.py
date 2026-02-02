"""Network-level observation for agent processes."""

from __future__ import annotations

import functools
import socket
from dataclasses import dataclass, field

import psutil


# Known API domains mapped to service names
KNOWN_API_DOMAINS = {
    "api.anthropic.com": "Anthropic API",
    "api.openai.com": "OpenAI API",
    "api.github.com": "GitHub API",
    "api2.cursor.sh": "Cursor API",
    "api.codeium.com": "Codeium API",
    "api.continue.dev": "Continue API",
    "api.smith.langchain.com": "LangSmith API",
    "app.crewai.com": "CrewAI API",
    "generativelanguage.googleapis.com": "Google Gemini API",
    "copilot-proxy.githubusercontent.com": "GitHub Copilot Proxy",
    "default.exp-tas.com": "GitHub Copilot Telemetry",
    "dc.services.visualstudio.com": "VS Code Telemetry",
}


@dataclass
class ConnectionInfo:
    """A single network connection from an agent process."""

    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    status: str = ""
    hostname: str | None = None
    known_service: str | None = None
    is_tls: bool = False


@dataclass
class NetworkSnapshot:
    """Network connections for a single agent."""

    agent_name: str
    pid: int | None = None
    connections: list[ConnectionInfo] = field(default_factory=list)

    @property
    def connection_count(self) -> int:
        return len(self.connections)


@functools.lru_cache(maxsize=512)
def _reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup with caching."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _classify_connection(remote_addr: str, remote_port: int, hostname: str | None) -> tuple[str | None, bool]:
    """Classify a connection against known API domains.

    Returns (known_service, is_tls).
    """
    is_tls = remote_port == 443

    # Check hostname against known domains
    if hostname:
        for domain, service in KNOWN_API_DOMAINS.items():
            if hostname == domain or hostname.endswith("." + domain):
                return service, is_tls

    return None, is_tls


def collect_connections(pid: int | None) -> list[ConnectionInfo]:
    """Collect network connections for a given PID.

    Returns an empty list on permission errors or if the process is gone.
    """
    if pid is None:
        return []

    try:
        proc = psutil.Process(pid)
        raw_conns = proc.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return []

    connections: list[ConnectionInfo] = []
    for conn in raw_conns:
        local_addr = conn.laddr.ip if conn.laddr else ""
        local_port = conn.laddr.port if conn.laddr else 0
        remote_addr = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0
        status = conn.status if conn.status else ""

        # Reverse DNS for remote address
        hostname = None
        if remote_addr and remote_addr not in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            hostname = _reverse_dns(remote_addr)

        known_service, is_tls = _classify_connection(remote_addr, remote_port, hostname)

        connections.append(ConnectionInfo(
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            status=status,
            hostname=hostname,
            known_service=known_service,
            is_tls=is_tls,
        ))

    return connections


def collect_all_connections(instances: list) -> list[NetworkSnapshot]:
    """Collect network connections for all running agent instances.

    Parameters
    ----------
    instances:
        List of AgentInstance objects.

    Returns a list of NetworkSnapshot objects (one per agent with connections).
    """
    from riva.agents.base import AgentStatus

    snapshots: list[NetworkSnapshot] = []
    for inst in instances:
        if inst.status != AgentStatus.RUNNING or not inst.pid:
            continue
        conns = collect_connections(inst.pid)
        snapshots.append(NetworkSnapshot(
            agent_name=inst.name,
            pid=inst.pid,
            connections=conns,
        ))
    return snapshots
