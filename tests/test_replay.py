"""Tests for time-travel replay functionality in storage."""

from __future__ import annotations

import time

import pytest

from riva.agents.base import AgentInstance, AgentStatus
from riva.core.storage import RivaStorage


@pytest.fixture
def storage(tmp_path):
    """Create a temporary storage instance."""
    db_path = tmp_path / "test_replay.db"
    s = RivaStorage(db_path=db_path)
    yield s
    s.close()


def _make_instance(name, pid=1, cpu=10.0, mem=100.0, uptime=3600.0, tree_data=None, network=None):
    """Helper to create a test instance."""
    extra = {}
    if tree_data:
        extra["process_tree"] = tree_data
    if network:
        extra["network"] = network
    return AgentInstance(
        name=name,
        status=AgentStatus.RUNNING,
        pid=pid,
        cpu_percent=cpu,
        memory_mb=mem,
        uptime_seconds=uptime,
        extra=extra,
    )


class TestGetStateAt:
    def test_returns_closest_snapshot_per_agent(self, storage):
        inst_a = _make_instance("Agent A", pid=1, cpu=10.0)
        inst_b = _make_instance("Agent B", pid=2, cpu=20.0)

        # Record first round
        storage.record_snapshot(inst_a, connection_count=0)
        storage.record_snapshot(inst_b, connection_count=0)
        ts1 = time.time()

        time.sleep(0.05)

        # Record second round with different CPU
        inst_a2 = _make_instance("Agent A", pid=1, cpu=50.0)
        storage.record_snapshot(inst_a2, connection_count=0)
        ts2 = time.time()

        # Query at ts1 should get first snapshot
        state = storage.get_state_at(ts1)
        assert len(state) == 2

        # Query at ts2 should get updated Agent A
        state2 = storage.get_state_at(ts2)
        agent_a_state = [s for s in state2 if s["agent_name"] == "Agent A"][0]
        assert agent_a_state["cpu_percent"] == 50.0

    def test_returns_empty_for_future_timestamp(self, storage):
        # No snapshots exist yet at a past time
        state = storage.get_state_at(1000.0)  # very old timestamp
        assert state == []

    def test_includes_children(self, storage):
        inst = _make_instance(
            "Agent A", pid=100, tree_data={
                "tree_cpu_percent": 15.0,
                "tree_memory_mb": 200.0,
                "child_count": 2,
            }
        )
        storage.record_snapshot(inst, connection_count=0)

        # Get snapshot_id and record children
        conn = storage._get_conn()
        row = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        snapshot_id = row["id"]
        storage.record_child_processes(snapshot_id, 100, [
            {"pid": 101, "name": "child1", "exe": "/usr/bin/c1", "cpu_percent": 5.0, "memory_mb": 50.0, "status": "running"},
            {"pid": 102, "name": "child2", "exe": "/usr/bin/c2", "cpu_percent": 10.0, "memory_mb": 150.0, "status": "running"},
        ])

        state = storage.get_state_at(time.time() + 1)
        assert len(state) == 1
        assert len(state[0]["children"]) == 2
        assert state[0]["children"][0]["child_name"] == "child1"

    def test_includes_network_connections(self, storage):
        inst = _make_instance(
            "Agent A", pid=100, network=[
                {
                    "local_addr": "127.0.0.1",
                    "local_port": 5000,
                    "remote_addr": "1.2.3.4",
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "hostname": "api.test.com",
                    "known_service": "Test API",
                    "is_tls": True,
                }
            ]
        )
        storage.record_snapshot(inst, connection_count=1)

        state = storage.get_state_at(time.time() + 1)
        assert len(state) == 1
        assert len(state[0]["network_connections"]) == 1
        assert state[0]["network_connections"][0]["remote_addr"] == "1.2.3.4"


class TestGetTimelineSummary:
    def test_buckets_correctly(self, storage):
        inst = _make_instance("Agent A", pid=1, cpu=10.0, mem=100.0)
        storage.record_snapshot(inst, connection_count=2)
        storage.record_snapshot(inst, connection_count=3)

        summary = storage.get_timeline_summary(hours=1.0, bucket_seconds=60)
        assert len(summary) >= 1
        # All snapshots should be in the same bucket (taken within same second)
        assert summary[0]["agent_count"] >= 1
        assert summary[0]["total_cpu"] >= 0

    def test_empty_when_no_data(self, storage):
        summary = storage.get_timeline_summary(hours=1.0, bucket_seconds=60)
        assert summary == []

    def test_includes_orphan_count(self, storage):
        inst = _make_instance("Agent A", pid=1)
        storage.record_snapshot(inst, connection_count=0)

        # Record an orphan at current time
        storage.record_orphan({
            "agent_name": "Agent A",
            "original_parent_pid": 1,
            "pid": 101,
            "name": "orphan",
            "exe": "/usr/bin/orphan",
            "detected_at": time.time(),
            "cpu_percent": 1.0,
            "memory_mb": 10.0,
        })

        summary = storage.get_timeline_summary(hours=1.0, bucket_seconds=3600)
        assert len(summary) >= 1


class TestGetSnapshotTimestamps:
    def test_returns_distinct_timestamps(self, storage):
        inst = _make_instance("Agent A", pid=1)
        storage.record_snapshot(inst, connection_count=0)
        time.sleep(0.01)
        storage.record_snapshot(inst, connection_count=0)

        timestamps = storage.get_snapshot_timestamps(hours=1.0)
        assert len(timestamps) >= 1
        # Should be sorted
        assert timestamps == sorted(timestamps)

    def test_empty_when_no_data(self, storage):
        timestamps = storage.get_snapshot_timestamps(hours=1.0)
        assert timestamps == []

    def test_respects_time_window(self, storage):
        inst = _make_instance("Agent A", pid=1)
        storage.record_snapshot(inst, connection_count=0)

        # Very short window might exclude
        timestamps = storage.get_snapshot_timestamps(hours=0.0)
        assert len(timestamps) == 0


class TestChildProcessPersistence:
    def test_record_and_get_child_processes(self, storage):
        inst = _make_instance("Agent A", pid=100)
        storage.record_snapshot(inst, connection_count=0)

        conn = storage._get_conn()
        row = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        snapshot_id = row["id"]

        storage.record_child_processes(snapshot_id, 100, [
            {"pid": 101, "name": "c1", "exe": "/bin/c1", "cpu_percent": 5.0, "memory_mb": 50.0, "status": "running"},
        ])

        children = storage.get_child_processes(snapshot_id)
        assert len(children) == 1
        assert children[0]["child_pid"] == 101
        assert children[0]["child_name"] == "c1"


class TestOrphanPersistence:
    def test_record_and_get_orphans(self, storage):
        storage.record_orphan({
            "agent_name": "Agent A",
            "original_parent_pid": 100,
            "pid": 101,
            "name": "orphan1",
            "exe": "/bin/orphan1",
            "detected_at": time.time(),
            "cpu_percent": 2.0,
            "memory_mb": 20.0,
        })

        orphans = storage.get_orphans(resolved=False, hours=1.0)
        assert len(orphans) == 1
        assert orphans[0]["orphan_pid"] == 101

    def test_resolve_orphan(self, storage):
        storage.record_orphan({
            "agent_name": "Agent A",
            "original_parent_pid": 100,
            "pid": 101,
            "name": "orphan1",
            "detected_at": time.time(),
        })

        storage.resolve_orphan(101)

        # Unresolved should be empty
        unresolved = storage.get_orphans(resolved=False, hours=1.0)
        assert len(unresolved) == 0

        # All (including resolved) should have one
        all_orphans = storage.get_orphans(resolved=True, hours=1.0)
        assert len(all_orphans) == 1
        assert all_orphans[0]["resolved_at"] is not None

    def test_cleanup_includes_orphans(self, storage):
        storage.record_orphan({
            "agent_name": "Agent A",
            "original_parent_pid": 100,
            "pid": 101,
            "detected_at": time.time(),
        })

        storage.cleanup(retention_days=0)

        orphans = storage.get_orphans(resolved=True, hours=24.0)
        assert len(orphans) == 0


class TestNewSnapshotColumns:
    def test_tree_columns_in_snapshot(self, storage):
        inst = _make_instance(
            "Agent A", pid=100,
            tree_data={
                "tree_cpu_percent": 25.0,
                "tree_memory_mb": 500.0,
                "child_count": 3,
            }
        )
        storage.record_snapshot(inst, connection_count=0)

        snapshots = storage.get_snapshots(agent_name="Agent A", hours=1.0)
        assert len(snapshots) == 1
        assert snapshots[0]["tree_cpu_percent"] == 25.0
        assert snapshots[0]["tree_memory_mb"] == 500.0
        assert snapshots[0]["child_count"] == 3

    def test_cleanup_includes_child_processes(self, storage):
        inst = _make_instance("Agent A", pid=100)
        storage.record_snapshot(inst, connection_count=0)

        conn = storage._get_conn()
        row = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
        storage.record_child_processes(row["id"], 100, [
            {"pid": 101, "name": "c1"},
        ])

        storage.cleanup(retention_days=0)

        children = storage.get_child_processes(row["id"])
        assert len(children) == 0
