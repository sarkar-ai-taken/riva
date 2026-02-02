"""Tests for child process tracking and orphan detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from riva.core.children import (
    ChildProcessInfo,
    OrphanProcess,
    ProcessTree,
    ProcessTreeCollector,
)


def _make_mock_child(pid, ppid, name="child", cpu=1.0, mem_rss=1024*1024*10, status="running"):
    """Create a mock psutil child process."""
    child = MagicMock()
    child.pid = pid
    child.ppid.return_value = ppid
    child.name.return_value = name
    child.cpu_percent.return_value = cpu
    mem_info = MagicMock()
    mem_info.rss = mem_rss
    child.memory_info.return_value = mem_info
    child.create_time.return_value = 1000.0
    child.status.return_value = status
    child.cmdline.return_value = ["/usr/bin/" + name]
    child.exe.return_value = "/usr/bin/" + name
    child.oneshot.return_value.__enter__ = MagicMock(return_value=None)
    child.oneshot.return_value.__exit__ = MagicMock(return_value=False)
    return child


class TestChildProcessInfo:
    def test_fields(self):
        info = ChildProcessInfo(pid=100, ppid=50, name="test", cpu_percent=5.0, memory_mb=10.0)
        assert info.pid == 100
        assert info.ppid == 50
        assert info.cpu_percent == 5.0

    def test_defaults(self):
        info = ChildProcessInfo(pid=1, ppid=2)
        assert info.name == ""
        assert info.cmdline == ""
        assert info.exe == ""
        assert info.cpu_percent == 0.0
        assert info.memory_mb == 0.0


class TestProcessTree:
    def test_fields(self):
        tree = ProcessTree(parent_pid=100, agent_name="Test Agent")
        assert tree.parent_pid == 100
        assert tree.agent_name == "Test Agent"
        assert tree.children == []
        assert tree.tree_cpu_percent == 0.0
        assert tree.child_count == 0


class TestProcessTreeCollector:
    @patch("riva.core.children.psutil")
    def test_collect_tree_basic(self, mock_psutil):
        child1 = _make_mock_child(101, 100, "worker1", cpu=5.0, mem_rss=1024*1024*50)
        child2 = _make_mock_child(102, 100, "worker2", cpu=3.0, mem_rss=1024*1024*30)

        parent = MagicMock()
        parent.children.return_value = [child1, child2]
        mock_psutil.Process.return_value = parent

        collector = ProcessTreeCollector()
        tree = collector.collect_tree(100, "Test Agent")

        assert tree.parent_pid == 100
        assert tree.agent_name == "Test Agent"
        assert tree.child_count == 2
        assert len(tree.children) == 2
        assert tree.tree_cpu_percent == 8.0
        # memory: 50 + 30 = 80 MB
        assert abs(tree.tree_memory_mb - 80.0) < 0.1

    @patch("riva.core.children.psutil")
    def test_collect_tree_no_children(self, mock_psutil):
        parent = MagicMock()
        parent.children.return_value = []
        mock_psutil.Process.return_value = parent

        collector = ProcessTreeCollector()
        tree = collector.collect_tree(100, "Test Agent")

        assert tree.child_count == 0
        assert tree.children == []

    @patch("riva.core.children.psutil")
    def test_collect_tree_parent_not_found(self, mock_psutil):
        import psutil as real_psutil
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.Process.side_effect = real_psutil.NoSuchProcess(999)

        collector = ProcessTreeCollector()
        tree = collector.collect_tree(999, "Dead Agent")

        assert tree.child_count == 0
        assert tree.children == []

    @patch("riva.core.children.psutil")
    def test_collect_tree_child_access_denied(self, mock_psutil):
        import psutil as real_psutil
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.ZombieProcess = real_psutil.ZombieProcess

        # First child is accessible, second raises AccessDenied
        good_child = _make_mock_child(101, 100, "good", cpu=2.0)
        bad_child = MagicMock()
        bad_child.pid = 102
        bad_child.oneshot.return_value.__enter__ = MagicMock(
            side_effect=real_psutil.AccessDenied(102)
        )

        parent = MagicMock()
        parent.children.return_value = [good_child, bad_child]
        mock_psutil.Process.return_value = parent

        collector = ProcessTreeCollector()
        tree = collector.collect_tree(100, "Test")

        # Only the good child should appear
        assert tree.child_count == 1
        assert tree.children[0].name == "good"

    @patch("riva.core.children.psutil")
    def test_orphan_detection(self, mock_psutil):
        import psutil as real_psutil
        mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
        mock_psutil.AccessDenied = real_psutil.AccessDenied
        mock_psutil.ZombieProcess = real_psutil.ZombieProcess

        collector = ProcessTreeCollector()

        # Cycle 1: agent PID 100 has children 101, 102
        tree = ProcessTree(
            parent_pid=100,
            agent_name="Test Agent",
            children=[
                ChildProcessInfo(pid=101, ppid=100, name="child1"),
                ChildProcessInfo(pid=102, ppid=100, name="child2"),
            ],
            child_count=2,
        )
        collector.update_tracking([tree])

        # Cycle 2: agent PID 100 is dead, but children survive
        surviving_child = MagicMock()
        surviving_child.pid = 101
        surviving_child.ppid.return_value = 1
        surviving_child.name.return_value = "child1"
        surviving_child.cpu_percent.return_value = 1.0
        mem_info = MagicMock()
        mem_info.rss = 1024 * 1024 * 10
        surviving_child.memory_info.return_value = mem_info
        surviving_child.oneshot.return_value.__enter__ = MagicMock(return_value=None)
        surviving_child.oneshot.return_value.__exit__ = MagicMock(return_value=False)
        surviving_child.cmdline.return_value = ["/usr/bin/child1"]
        surviving_child.exe.return_value = "/usr/bin/child1"

        # child 102 is also dead
        def process_side_effect(pid):
            if pid == 101:
                return surviving_child
            raise real_psutil.NoSuchProcess(pid)

        mock_psutil.Process.side_effect = process_side_effect

        # Agent PID 100 is no longer in current set
        new_orphans = collector.detect_orphans({200})

        assert len(new_orphans) == 1
        assert new_orphans[0].pid == 101
        assert new_orphans[0].agent_name == "Test Agent"
        assert new_orphans[0].original_parent_pid == 100

    @patch("riva.core.children.psutil")
    def test_cleanup_orphans_removes_dead(self, mock_psutil):
        collector = ProcessTreeCollector()
        collector._orphans = [
            OrphanProcess(pid=101, original_parent_pid=100, agent_name="Test", detected_at=1000.0),
            OrphanProcess(pid=102, original_parent_pid=100, agent_name="Test", detected_at=1000.0),
        ]

        # PID 101 exists, PID 102 does not
        mock_psutil.pid_exists.side_effect = lambda pid: pid == 101

        collector.cleanup_orphans()

        assert len(collector.orphans) == 1
        assert collector.orphans[0].pid == 101

    def test_orphans_property_returns_copy(self):
        collector = ProcessTreeCollector()
        collector._orphans = [
            OrphanProcess(pid=101, original_parent_pid=100, agent_name="Test"),
        ]
        orphans = collector.orphans
        orphans.clear()
        # Original should be unchanged
        assert len(collector._orphans) == 1

    @patch("riva.core.children.psutil")
    def test_no_orphans_when_parent_alive(self, mock_psutil):
        collector = ProcessTreeCollector()

        tree = ProcessTree(
            parent_pid=100,
            agent_name="Test Agent",
            children=[ChildProcessInfo(pid=101, ppid=100)],
            child_count=1,
        )
        collector.update_tracking([tree])

        # Parent is still alive in current set
        new_orphans = collector.detect_orphans({100})
        assert len(new_orphans) == 0
