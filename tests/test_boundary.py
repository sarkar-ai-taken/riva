"""Tests for riva.core.boundary."""

from __future__ import annotations

import time

from riva.core.boundary import (
    BoundaryPolicy,
    evaluate_boundaries,
    evaluate_file_boundaries,
    evaluate_network_boundaries,
    evaluate_process_boundaries,
    load_boundary_policy,
)


class TestBoundaryPolicy:
    def test_load_from_workspace_config_none(self):
        assert load_boundary_policy(None) is None

    def test_load_from_workspace_config_no_boundary(self):
        class FakeConfig:
            metadata = {}

        assert load_boundary_policy(FakeConfig()) is None

    def test_load_from_workspace_config(self):
        class FakeConfig:
            metadata = {
                "boundary": {
                    "allowed_paths": ["/home/user/projects/**"],
                    "denied_paths": ["~/.ssh/**"],
                    "allowed_domains": ["api.anthropic.com"],
                    "denied_domains": ["evil.com"],
                    "max_child_processes": 10,
                    "deny_root": True,
                    "deny_unsandboxed": True,
                }
            }

        policy = load_boundary_policy(FakeConfig())
        assert policy is not None
        assert policy.allowed_paths == ["/home/user/projects/**"]
        assert policy.denied_paths == ["~/.ssh/**"]
        assert policy.allowed_domains == ["api.anthropic.com"]
        assert policy.denied_domains == ["evil.com"]
        assert policy.max_child_processes == 10
        assert policy.deny_root is True
        assert policy.deny_unsandboxed is True


class TestFileBoundaries:
    def test_denied_path_flagged(self):
        policy = BoundaryPolicy(denied_paths=["/etc/*", "~/.ssh/*"])
        violations = evaluate_file_boundaries(policy, "TestAgent", ["/etc/passwd"])
        assert len(violations) == 1
        assert violations[0].violation_type == "file_boundary"
        assert violations[0].severity == "high"
        assert "/etc/passwd" in violations[0].detail

    def test_allowed_path_outside_flagged(self):
        policy = BoundaryPolicy(allowed_paths=["/home/user/projects/**"])
        violations = evaluate_file_boundaries(policy, "TestAgent", ["/tmp/evil.sh"])
        assert len(violations) == 1
        assert violations[0].severity == "medium"

    def test_allowed_path_inside_ok(self):
        policy = BoundaryPolicy(allowed_paths=["/home/user/projects/*"])
        violations = evaluate_file_boundaries(policy, "TestAgent", ["/home/user/projects/foo.py"])
        assert len(violations) == 0

    def test_no_policy_no_violations(self):
        policy = BoundaryPolicy()
        violations = evaluate_file_boundaries(policy, "TestAgent", ["/anything"])
        assert len(violations) == 0

    def test_multiple_files(self):
        policy = BoundaryPolicy(denied_paths=["/etc/*", "/root/*"])
        violations = evaluate_file_boundaries(
            policy, "TestAgent", ["/etc/passwd", "/home/ok.txt", "/root/.bashrc"]
        )
        assert len(violations) == 2


class TestNetworkBoundaries:
    def test_denied_domain_flagged(self):
        policy = BoundaryPolicy(denied_domains=["evil.com", "*.malware.net"])
        connections = [{"hostname": "evil.com", "remote_addr": "1.2.3.4"}]
        violations = evaluate_network_boundaries(policy, "TestAgent", connections)
        assert len(violations) == 1
        assert violations[0].severity == "high"

    def test_allowed_domain_outside_flagged(self):
        policy = BoundaryPolicy(allowed_domains=["api.anthropic.com", "api.openai.com"])
        connections = [{"hostname": "unknown.io", "remote_addr": "5.6.7.8"}]
        violations = evaluate_network_boundaries(policy, "TestAgent", connections)
        assert len(violations) == 1
        assert violations[0].severity == "medium"

    def test_allowed_domain_inside_ok(self):
        policy = BoundaryPolicy(allowed_domains=["api.anthropic.com"])
        connections = [{"hostname": "api.anthropic.com", "remote_addr": "1.2.3.4"}]
        violations = evaluate_network_boundaries(policy, "TestAgent", connections)
        assert len(violations) == 0

    def test_deduplicates_domains(self):
        policy = BoundaryPolicy(denied_domains=["evil.com"])
        connections = [
            {"hostname": "evil.com", "remote_addr": "1.2.3.4"},
            {"hostname": "evil.com", "remote_addr": "1.2.3.5"},
        ]
        violations = evaluate_network_boundaries(policy, "TestAgent", connections)
        assert len(violations) == 1


class TestProcessBoundaries:
    def test_root_flagged(self):
        policy = BoundaryPolicy(deny_root=True)
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 0, [], is_root=True
        )
        assert len(violations) == 1
        assert violations[0].severity == "critical"
        assert violations[0].violation_type == "privilege"

    def test_unsandboxed_flagged(self):
        policy = BoundaryPolicy(deny_unsandboxed=True)
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 0, [], is_sandboxed=False
        )
        assert len(violations) == 1
        assert violations[0].violation_type == "privilege"

    def test_sandboxed_ok(self):
        policy = BoundaryPolicy(deny_unsandboxed=True)
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 0, [], is_sandboxed=True
        )
        assert len(violations) == 0

    def test_child_count_exceeded(self):
        policy = BoundaryPolicy(max_child_processes=5)
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 10, []
        )
        assert len(violations) == 1
        assert violations[0].violation_type == "process_boundary"
        assert "10" in violations[0].detail and "5" in violations[0].detail

    def test_child_count_within_limit(self):
        policy = BoundaryPolicy(max_child_processes=10)
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 5, []
        )
        assert len(violations) == 0

    def test_denied_process_name(self):
        policy = BoundaryPolicy(denied_process_names=["nc", "ncat", "curl"])
        children = [
            {"name": "node", "exe": "/usr/bin/node", "pid": 100},
            {"name": "nc", "exe": "/usr/bin/nc", "pid": 101},
        ]
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 2, children
        )
        assert len(violations) == 1
        assert "nc" in violations[0].detail

    def test_combined_violations(self):
        policy = BoundaryPolicy(
            deny_root=True,
            max_child_processes=2,
            denied_process_names=["nc"],
        )
        children = [
            {"name": "node", "exe": "/usr/bin/node", "pid": 100},
            {"name": "nc", "exe": "/usr/bin/nc", "pid": 101},
            {"name": "python", "exe": "/usr/bin/python", "pid": 102},
        ]
        violations = evaluate_process_boundaries(
            policy, "TestAgent", 3, children, is_root=True
        )
        # root + child count exceeded + denied process
        assert len(violations) == 3


class TestEvaluateBoundaries:
    def _make_instance(self, name="TestAgent", pid=123, network=None, tree=None, sandbox=None):
        from riva.agents.base import AgentInstance, AgentStatus

        inst = AgentInstance(
            name=name,
            status=AgentStatus.RUNNING,
            pid=pid,
            binary_path="/usr/bin/test",
            config_dir="~/.test",
            cpu_percent=5.0,
            memory_mb=100.0,
            uptime_seconds=60.0,
        )
        if network is not None:
            inst.extra["network"] = network
        if tree is not None:
            inst.extra["process_tree"] = tree
        if sandbox is not None:
            inst.extra["sandbox"] = sandbox
        return inst

    def test_network_violation(self):
        policy = BoundaryPolicy(denied_domains=["evil.com"])
        inst = self._make_instance(
            network=[{"hostname": "evil.com", "remote_addr": "1.2.3.4"}]
        )
        violations = evaluate_boundaries(policy, [inst])
        assert any(v.violation_type == "network_boundary" for v in violations)

    def test_no_violations(self):
        policy = BoundaryPolicy()
        inst = self._make_instance()
        violations = evaluate_boundaries(policy, [inst])
        assert len(violations) == 0

    def test_skips_non_running(self):
        from riva.agents.base import AgentInstance, AgentStatus

        policy = BoundaryPolicy(denied_domains=["evil.com"])
        inst = AgentInstance(
            name="Test",
            status=AgentStatus.INSTALLED,
            pid=None,
            binary_path="/usr/bin/test",
            config_dir="~/.test",
            cpu_percent=0.0,
            memory_mb=0.0,
            uptime_seconds=0.0,
        )
        inst.extra["network"] = [{"hostname": "evil.com"}]
        violations = evaluate_boundaries(policy, [inst])
        assert len(violations) == 0
