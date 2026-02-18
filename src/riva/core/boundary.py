"""Continuous boundary monitoring for AI agent activity.

Evaluates agent behavior against configurable policies every poll cycle.
Flags violations for file access, network connections, process trees,
and privilege boundaries.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BoundaryPolicy:
    """Defines allowed and denied boundaries for agent behavior."""

    # File access boundaries (glob patterns)
    allowed_paths: list[str] = field(default_factory=list)
    denied_paths: list[str] = field(default_factory=list)

    # Network boundaries (domain patterns)
    allowed_domains: list[str] = field(default_factory=list)
    denied_domains: list[str] = field(default_factory=list)

    # Process boundaries
    max_child_processes: int | None = None
    denied_process_names: list[str] = field(default_factory=list)

    # Privilege boundaries
    deny_root: bool = True
    deny_unsandboxed: bool = False


@dataclass
class BoundaryViolation:
    """A detected boundary violation."""

    timestamp: float
    agent_name: str
    violation_type: str  # file_boundary, network_boundary, process_boundary, privilege
    detail: str
    severity: str  # low, medium, high, critical

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "agent_name": self.agent_name,
            "violation_type": self.violation_type,
            "detail": self.detail,
            "severity": self.severity,
        }


def load_boundary_policy(workspace_config) -> BoundaryPolicy | None:
    """Load boundary policy from workspace config [boundary] section.

    Returns None if no boundary section is configured.
    """
    if workspace_config is None:
        return None

    metadata = getattr(workspace_config, "metadata", {})
    boundary = metadata.get("boundary")
    if not boundary:
        return None

    return BoundaryPolicy(
        allowed_paths=list(boundary.get("allowed_paths", [])),
        denied_paths=list(boundary.get("denied_paths", [])),
        allowed_domains=list(boundary.get("allowed_domains", [])),
        denied_domains=list(boundary.get("denied_domains", [])),
        max_child_processes=boundary.get("max_child_processes"),
        denied_process_names=list(boundary.get("denied_process_names", [])),
        deny_root=bool(boundary.get("deny_root", True)),
        deny_unsandboxed=bool(boundary.get("deny_unsandboxed", False)),
    )


def _match_any(value: str, patterns: list[str]) -> bool:
    """Check if value matches any of the glob/fnmatch patterns."""
    for pattern in patterns:
        # Expand ~ in patterns
        expanded = str(Path(pattern).expanduser()) if "~" in pattern else pattern
        if fnmatch.fnmatch(value, expanded):
            return True
    return False


def evaluate_file_boundaries(
    policy: BoundaryPolicy,
    agent_name: str,
    files_accessed: list[str],
) -> list[BoundaryViolation]:
    """Check file access against boundary policy."""
    violations: list[BoundaryViolation] = []
    now = time.time()

    for file_path in files_accessed:
        # Check denied paths first
        if policy.denied_paths and _match_any(file_path, policy.denied_paths):
            violations.append(
                BoundaryViolation(
                    timestamp=now,
                    agent_name=agent_name,
                    violation_type="file_boundary",
                    detail=f"Access to denied path: {file_path}",
                    severity="high",
                )
            )
        # Check allowed paths (if set, everything else is denied)
        elif policy.allowed_paths and not _match_any(file_path, policy.allowed_paths):
            violations.append(
                BoundaryViolation(
                    timestamp=now,
                    agent_name=agent_name,
                    violation_type="file_boundary",
                    detail=f"Access outside allowed paths: {file_path}",
                    severity="medium",
                )
            )

    return violations


def evaluate_network_boundaries(
    policy: BoundaryPolicy,
    agent_name: str,
    connections: list[dict],
) -> list[BoundaryViolation]:
    """Check network connections against boundary policy."""
    violations: list[BoundaryViolation] = []
    now = time.time()

    seen_domains: set[str] = set()

    for conn in connections:
        hostname = conn.get("hostname") or conn.get("remote_addr", "")
        if not hostname or hostname in seen_domains:
            continue
        seen_domains.add(hostname)

        # Check denied domains
        if policy.denied_domains and _match_any(hostname, policy.denied_domains):
            violations.append(
                BoundaryViolation(
                    timestamp=now,
                    agent_name=agent_name,
                    violation_type="network_boundary",
                    detail=f"Connection to denied domain: {hostname}",
                    severity="high",
                )
            )
        # Check allowed domains (if set, everything else is denied)
        elif policy.allowed_domains and not _match_any(hostname, policy.allowed_domains):
            violations.append(
                BoundaryViolation(
                    timestamp=now,
                    agent_name=agent_name,
                    violation_type="network_boundary",
                    detail=f"Connection to unlisted domain: {hostname}",
                    severity="medium",
                )
            )

    return violations


def evaluate_process_boundaries(
    policy: BoundaryPolicy,
    agent_name: str,
    child_count: int,
    children: list[dict],
    is_root: bool = False,
    is_sandboxed: bool = True,
) -> list[BoundaryViolation]:
    """Check process tree against boundary policy."""
    violations: list[BoundaryViolation] = []
    now = time.time()

    # Root check
    if policy.deny_root and is_root:
        violations.append(
            BoundaryViolation(
                timestamp=now,
                agent_name=agent_name,
                violation_type="privilege",
                detail="Agent running as root (UID 0)",
                severity="critical",
            )
        )

    # Sandbox check
    if policy.deny_unsandboxed and not is_sandboxed:
        violations.append(
            BoundaryViolation(
                timestamp=now,
                agent_name=agent_name,
                violation_type="privilege",
                detail="Agent running without sandbox/container",
                severity="high",
            )
        )

    # Child process count
    if policy.max_child_processes is not None and child_count > policy.max_child_processes:
        violations.append(
            BoundaryViolation(
                timestamp=now,
                agent_name=agent_name,
                violation_type="process_boundary",
                detail=f"Child process count ({child_count}) exceeds limit ({policy.max_child_processes})",
                severity="medium",
            )
        )

    # Denied process names
    if policy.denied_process_names:
        for child in children:
            child_name = child.get("name", "")
            child_exe = child.get("exe", "")
            for pattern in policy.denied_process_names:
                if fnmatch.fnmatch(child_name, pattern) or fnmatch.fnmatch(child_exe, pattern):
                    violations.append(
                        BoundaryViolation(
                            timestamp=now,
                            agent_name=agent_name,
                            violation_type="process_boundary",
                            detail=f"Denied child process: {child_name} (PID {child.get('pid', '?')})",
                            severity="high",
                        )
                    )

    return violations


def evaluate_boundaries(
    policy: BoundaryPolicy,
    instances: list,
    *,
    forensic_files: dict[str, list[str]] | None = None,
) -> list[BoundaryViolation]:
    """Evaluate all boundary policies against current agent state.

    Args:
        policy: The boundary policy to evaluate.
        instances: List of AgentInstance objects from the monitor.
        forensic_files: Optional dict mapping agent_name -> list of file paths
                        accessed (from forensic session parsing).

    Returns:
        List of BoundaryViolation objects.
    """
    from riva.agents.base import AgentStatus

    violations: list[BoundaryViolation] = []

    for inst in instances:
        if inst.status != AgentStatus.RUNNING:
            continue

        # Network boundary checks
        network_data = inst.extra.get("network", [])
        if network_data and (policy.allowed_domains or policy.denied_domains):
            violations.extend(
                evaluate_network_boundaries(policy, inst.name, network_data)
            )

        # Process boundary checks
        tree_data = inst.extra.get("process_tree", {})
        child_count = tree_data.get("child_count", 0)
        children = tree_data.get("children", [])
        sandbox_data = inst.extra.get("sandbox", {})
        is_sandboxed = sandbox_data.get("is_sandboxed", False)

        # Check if running as root
        is_root = False
        try:
            import os

            import psutil

            if inst.pid:
                proc = psutil.Process(inst.pid)
                is_root = proc.uids().real == 0 if hasattr(os, "getuid") else False
        except Exception:
            pass

        violations.extend(
            evaluate_process_boundaries(
                policy, inst.name, child_count, children,
                is_root=is_root, is_sandboxed=is_sandboxed,
            )
        )

        # File boundary checks (from forensic data if available)
        if forensic_files and inst.name in forensic_files:
            violations.extend(
                evaluate_file_boundaries(policy, inst.name, forensic_files[inst.name])
            )

    return violations
