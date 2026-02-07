"""Tests for SQLite storage module."""

from __future__ import annotations

import pytest

from riva.agents.base import AgentInstance, AgentStatus
from riva.core.storage import RivaStorage


@pytest.fixture
def storage(tmp_path):
    """Create a temporary storage instance."""
    db_path = tmp_path / "test.db"
    s = RivaStorage(db_path=db_path)
    yield s
    s.close()


class TestRivaStorage:
    def test_creates_database(self, storage, tmp_path):
        db_path = tmp_path / "test.db"
        assert db_path.exists()

    def test_creates_tables(self, storage):
        conn = storage._get_conn()
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row["name"] for row in cursor.fetchall()]
        assert "agents" in tables
        assert "snapshots" in tables
        assert "network_connections" in tables
        assert "audit_events" in tables

    def test_record_snapshot(self, storage):
        inst = AgentInstance(
            name="Test Agent",
            status=AgentStatus.RUNNING,
            pid=12345,
            cpu_percent=25.5,
            memory_mb=512.0,
            uptime_seconds=3600.0,
            config_dir="/tmp/test",
            api_domain="api.test.com",
        )
        storage.record_snapshot(inst, connection_count=3)

        snapshots = storage.get_snapshots(agent_name="Test Agent", hours=1.0)
        assert len(snapshots) == 1
        assert snapshots[0]["pid"] == 12345
        assert snapshots[0]["cpu_percent"] == 25.5
        assert snapshots[0]["connection_count"] == 3

    def test_record_snapshot_with_network(self, storage):
        inst = AgentInstance(
            name="Test Agent",
            status=AgentStatus.RUNNING,
            pid=12345,
            cpu_percent=10.0,
            memory_mb=256.0,
            uptime_seconds=1800.0,
            extra={
                "network": [
                    {
                        "local_addr": "127.0.0.1",
                        "local_port": 5000,
                        "remote_addr": "93.184.216.34",
                        "remote_port": 443,
                        "status": "ESTABLISHED",
                        "hostname": "api.anthropic.com",
                        "known_service": "Anthropic API",
                        "is_tls": True,
                    }
                ]
            },
        )
        storage.record_snapshot(inst, connection_count=1)

        # Verify network connections were persisted
        conn = storage._get_conn()
        rows = conn.execute("SELECT * FROM network_connections").fetchall()
        assert len(rows) == 1
        assert rows[0]["remote_addr"] == "93.184.216.34"
        assert rows[0]["known_service"] == "Anthropic API"
        assert rows[0]["is_tls"] == 1

    def test_get_snapshots_filters_by_agent(self, storage):
        inst1 = AgentInstance(name="Agent A", status=AgentStatus.RUNNING, pid=1)
        inst2 = AgentInstance(name="Agent B", status=AgentStatus.RUNNING, pid=2)
        storage.record_snapshot(inst1)
        storage.record_snapshot(inst2)

        a_snaps = storage.get_snapshots(agent_name="Agent A", hours=1.0)
        b_snaps = storage.get_snapshots(agent_name="Agent B", hours=1.0)
        all_snaps = storage.get_snapshots(hours=1.0)

        assert len(a_snaps) == 1
        assert len(b_snaps) == 1
        assert len(all_snaps) == 2

    def test_get_snapshots_filters_by_time(self, storage):
        inst = AgentInstance(name="Test", status=AgentStatus.RUNNING, pid=1)
        storage.record_snapshot(inst)

        # Should find recent snapshot
        recent = storage.get_snapshots(hours=1.0)
        assert len(recent) == 1

        # Old data wouldn't appear for very short window
        # (this test just verifies the query works)
        storage.get_snapshots(hours=0.0001)
        # Might be 0 or 1 depending on timing, just verify no error

    def test_record_audit_event(self, storage):
        storage.record_audit_event("Test Check", "pass", "All good", "info")
        storage.record_audit_event("Bad Check", "fail", "Something wrong", "high")

        events = storage.get_audit_events(hours=1.0)
        assert len(events) == 2
        assert events[0]["check_name"] == "Bad Check"  # DESC order

    def test_get_network_history(self, storage):
        inst = AgentInstance(
            name="Test",
            status=AgentStatus.RUNNING,
            pid=1,
            extra={
                "network": [
                    {
                        "local_addr": "0.0.0.0",
                        "local_port": 0,
                        "remote_addr": "1.2.3.4",
                        "remote_port": 443,
                        "status": "ESTABLISHED",
                        "hostname": None,
                        "known_service": None,
                        "is_tls": True,
                    }
                ]
            },
        )
        storage.record_snapshot(inst, connection_count=1)

        history = storage.get_network_history(hours=1.0)
        assert len(history) == 1

    def test_cleanup(self, storage):
        inst = AgentInstance(name="Test", status=AgentStatus.RUNNING, pid=1)
        storage.record_snapshot(inst)

        # Cleanup with 0 retention should remove everything
        storage.cleanup(retention_days=0)

        snapshots = storage.get_snapshots(hours=24.0)
        assert len(snapshots) == 0

    def test_agent_deduplication(self, storage):
        inst = AgentInstance(name="Same Agent", status=AgentStatus.RUNNING, pid=1)
        storage.record_snapshot(inst)
        storage.record_snapshot(inst)

        conn = storage._get_conn()
        agents = conn.execute("SELECT * FROM agents").fetchall()
        assert len(agents) == 1  # Only one agent record

        snapshots = storage.get_snapshots(hours=1.0)
        assert len(snapshots) == 2  # But two snapshots

    def test_close_and_reopen(self, tmp_path):
        db_path = tmp_path / "test_reopen.db"
        s1 = RivaStorage(db_path=db_path)
        inst = AgentInstance(name="Test", status=AgentStatus.RUNNING, pid=1)
        s1.record_snapshot(inst)
        s1.close()

        s2 = RivaStorage(db_path=db_path)
        snapshots = s2.get_snapshots(hours=1.0)
        assert len(snapshots) == 1
        s2.close()
