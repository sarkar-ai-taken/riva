"""Tests for riva.core.monitor."""

import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from riva.agents.base import AgentInstance, AgentStatus, SimpleAgentDetector
from riva.agents.registry import AgentRegistry
from riva.core.monitor import AgentHistory, ResourceMonitor, ResourceSnapshot


def _make_registry_with_detector(name="Test"):
    det = SimpleAgentDetector(
        name=name,
        binaries=["test"],
        config="/tmp/riva_nonexistent",
        api="api.test.dev",
    )
    reg = AgentRegistry()
    reg.register(det)
    return reg


class TestResourceSnapshot:
    def test_fields(self):
        snap = ResourceSnapshot(timestamp=1.0, cpu_percent=25.0, memory_mb=512.0)
        assert snap.cpu_percent == 25.0
        assert snap.memory_mb == 512.0


class TestAgentHistory:
    def test_empty_history(self):
        h = AgentHistory(agent_name="Test", pid=1)
        assert h.cpu_history == []
        assert h.memory_history == []

    def test_history_values(self):
        h = AgentHistory(agent_name="Test", pid=1)
        h.snapshots.append(ResourceSnapshot(1.0, 10.0, 100.0))
        h.snapshots.append(ResourceSnapshot(2.0, 20.0, 200.0))
        assert h.cpu_history == [10.0, 20.0]
        assert h.memory_history == [100.0, 200.0]

    def test_maxlen(self):
        h = AgentHistory(agent_name="Test", pid=1, snapshots=deque(maxlen=3))
        for i in range(5):
            h.snapshots.append(ResourceSnapshot(float(i), float(i), float(i)))
        assert len(h.snapshots) == 3
        assert h.cpu_history == [2.0, 3.0, 4.0]


class TestResourceMonitor:
    def test_scan_once(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg, interval=0.1)

        # Mock scanner to return a known instance
        fake_instance = AgentInstance(
            name="Test", status=AgentStatus.INSTALLED,
        )
        with patch.object(monitor._scanner, "scan", return_value=[fake_instance]):
            results = monitor.scan_once()

        assert len(results) == 1
        assert results[0].name == "Test"

    def test_history_populated_for_running(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg, interval=0.1)

        running = AgentInstance(
            name="Test", status=AgentStatus.RUNNING,
            pid=123, cpu_percent=15.0, memory_mb=256.0,
        )

        with patch.object(monitor._scanner, "scan", return_value=[running]), \
             patch.object(monitor._scanner, "refresh_instance", return_value=running):
            monitor.scan_once()

        histories = monitor.histories
        assert len(histories) == 1
        key = "Test:123"
        assert key in histories
        assert len(histories[key].snapshots) == 1
        assert histories[key].snapshots[0].cpu_percent == 15.0

    def test_no_history_for_installed_only(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg, interval=0.1)

        installed = AgentInstance(
            name="Test", status=AgentStatus.INSTALLED,
        )
        with patch.object(monitor._scanner, "scan", return_value=[installed]):
            monitor.scan_once()

        assert len(monitor.histories) == 0

    def test_start_stop(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg, interval=0.05)

        with patch.object(monitor._scanner, "scan", return_value=[]):
            monitor.start()
            assert monitor._thread is not None
            assert monitor._thread.is_alive()
            time.sleep(0.15)
            monitor.stop()
            assert monitor._thread is None

    def test_instances_property_thread_safe(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg)
        # Should return empty list without error
        assert monitor.instances == []

    def test_history_key_with_pid(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg)
        inst = AgentInstance(name="Agent", status=AgentStatus.RUNNING, pid=42)
        assert monitor._history_key(inst) == "Agent:42"

    def test_history_key_without_pid(self):
        reg = _make_registry_with_detector()
        monitor = ResourceMonitor(registry=reg)
        inst = AgentInstance(name="Agent", status=AgentStatus.INSTALLED)
        assert monitor._history_key(inst) == "Agent"
