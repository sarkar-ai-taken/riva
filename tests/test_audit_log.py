"""Tests for riva.core.audit_log."""

from __future__ import annotations

import json
from pathlib import Path

from riva.core.audit_log import AuditLog


class TestAuditLogAppend:
    def test_append_creates_file(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        entry = log.append("test_event", "Something happened", severity="info")

        assert entry.event_type == "test_event"
        assert entry.detail == "Something happened"
        assert entry.severity == "info"
        assert entry.entry_hash != ""
        assert entry.prev_hash == ""  # First entry has no predecessor
        assert log.log_file.exists()

    def test_append_chains_hashes(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        e1 = log.append("event1", "First")
        e2 = log.append("event2", "Second")
        e3 = log.append("event3", "Third")

        assert e2.prev_hash == e1.entry_hash
        assert e3.prev_hash == e2.entry_hash
        assert e1.entry_hash != e2.entry_hash != e3.entry_hash

    def test_append_with_metadata(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        entry = log.append(
            "boundary_violation",
            "Access denied",
            severity="high",
            agent_name="Claude Code",
            metadata={"violation_type": "file_boundary", "path": "/etc/passwd"},
        )
        assert entry.agent_name == "Claude Code"
        assert entry.metadata["violation_type"] == "file_boundary"

    def test_entry_count(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        assert log.entry_count == 0
        log.append("e1", "first")
        log.append("e2", "second")
        assert log.entry_count == 2


class TestAuditLogIntegrity:
    def test_verify_empty_log(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        valid, count, error = log.verify_integrity()
        assert valid is True
        assert count == 0

    def test_verify_valid_chain(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first")
        log.append("e2", "second")
        log.append("e3", "third")

        valid, count, error = log.verify_integrity()
        assert valid is True
        assert count == 3
        assert error == ""

    def test_verify_detects_tamper(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first")
        log.append("e2", "second")

        # Tamper with the log file
        lines = log.log_file.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["detail"] = "TAMPERED"
        lines[0] = json.dumps(entry)
        log.log_file.write_text("\n".join(lines) + "\n")

        valid, count, error = log.verify_integrity()
        assert valid is False
        assert "tampered" in error.lower() or "mismatch" in error.lower()

    def test_verify_detects_chain_break(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first")
        log.append("e2", "second")

        # Break the chain by changing prev_hash of second entry
        lines = log.log_file.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["prev_hash"] = "00000000deadbeef"
        lines[1] = json.dumps(entry)
        log.log_file.write_text("\n".join(lines) + "\n")

        valid, count, error = log.verify_integrity()
        assert valid is False
        assert "chain break" in error.lower()

    def test_verify_detects_invalid_json(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first")

        # Corrupt the file
        with open(log.log_file, "a") as fh:
            fh.write("{invalid json\n")

        valid, count, error = log.verify_integrity()
        assert valid is False
        assert "invalid JSON" in error


class TestAuditLogPersistence:
    def test_resumes_chain_after_reopen(self, tmp_path):
        log1 = AuditLog(log_dir=tmp_path)
        e1 = log1.append("e1", "first")
        e2 = log1.append("e2", "second")

        # Re-open the log (simulates process restart)
        log2 = AuditLog(log_dir=tmp_path)
        e3 = log2.append("e3", "third")

        # Chain should be continuous
        assert e3.prev_hash == e2.entry_hash

        # Full chain should verify
        valid, count, error = log2.verify_integrity()
        assert valid is True
        assert count == 3


class TestAuditLogReadEntries:
    def test_read_all(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first")
        log.append("e2", "second")
        log.append("e3", "third")

        entries = log.read_entries()
        assert len(entries) == 3

    def test_read_by_event_type(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("scan", "scan done")
        log.append("boundary_violation", "bad access")
        log.append("scan", "another scan")

        entries = log.read_entries(event_type="boundary_violation")
        assert len(entries) == 1
        assert entries[0]["event_type"] == "boundary_violation"

    def test_read_empty(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        assert log.read_entries() == []


class TestAuditLogExport:
    def test_export_jsonl(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("e1", "first", severity="info")
        log.append("e2", "second", severity="high")

        output = tmp_path / "export.jsonl"
        count = log.export_jsonl(output, hours=24.0)

        assert count == 2
        assert output.exists()
        lines = output.read_text().strip().splitlines()
        assert len(lines) == 2
        entry = json.loads(lines[0])
        assert "event_type" in entry

    def test_export_cef(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("boundary_violation", "Denied path access", severity="high", agent_name="Claude Code")

        output = tmp_path / "export.cef"
        count = log.export_cef(output, hours=24.0)

        assert count == 1
        assert output.exists()
        content = output.read_text().strip()
        assert content.startswith("CEF:0|Riva|AgentMonitor|1.0|")
        assert "boundary_violation" in content
        assert "Denied path access" in content
        assert "8" in content  # high severity = 8

    def test_export_cef_escapes_pipes(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        log.append("test", "detail|with|pipes", severity="info")

        output = tmp_path / "export.cef"
        log.export_cef(output, hours=24.0)

        content = output.read_text()
        assert "detail\\|with\\|pipes" in content

    def test_export_empty(self, tmp_path):
        log = AuditLog(log_dir=tmp_path)
        output = tmp_path / "export.jsonl"
        count = log.export_jsonl(output, hours=24.0)
        assert count == 0
