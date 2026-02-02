"""Tests for riva.utils.jsonl."""

import json
import os
import time

import pytest

from riva.utils.jsonl import find_recent_sessions, stream_jsonl


class TestStreamJsonl:
    def test_valid_data(self, tmp_path):
        f = tmp_path / "data.jsonl"
        lines = [
            json.dumps({"a": 1}),
            json.dumps({"b": 2}),
            json.dumps({"c": 3}),
        ]
        f.write_text("\n".join(lines) + "\n")

        result = list(stream_jsonl(f))
        assert len(result) == 3
        assert result[0] == {"a": 1}
        assert result[2] == {"c": 3}

    def test_malformed_lines_skipped(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text(
            '{"ok": true}\n'
            "NOT JSON\n"
            '{"also": "ok"}\n'
            "[1, 2, 3]\n"  # array, not dict — skipped
        )

        result = list(stream_jsonl(f))
        assert len(result) == 2
        assert result[0] == {"ok": True}
        assert result[1] == {"also": "ok"}

    def test_max_lines_cap(self, tmp_path):
        f = tmp_path / "data.jsonl"
        lines = [json.dumps({"i": i}) for i in range(100)]
        f.write_text("\n".join(lines) + "\n")

        result = list(stream_jsonl(f, max_lines=5))
        assert len(result) == 5
        assert result[0] == {"i": 0}
        assert result[4] == {"i": 4}

    def test_missing_file(self, tmp_path):
        result = list(stream_jsonl(tmp_path / "nope.jsonl"))
        assert result == []

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        result = list(stream_jsonl(f))
        assert result == []

    def test_blank_lines_skipped(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text('\n\n{"x": 1}\n\n{"y": 2}\n\n')
        result = list(stream_jsonl(f))
        assert len(result) == 2


class TestFindRecentSessions:
    def test_finds_files_sorted_by_mtime(self, tmp_path):
        # Create files with different mtimes
        files = []
        for i in range(5):
            d = tmp_path / f"session_{i}"
            d.mkdir()
            f = d / "log.jsonl"
            f.write_text('{"i": %d}\n' % i)
            files.append(f)
            # Ensure distinct mtimes
            os.utime(f, (1000 + i, 1000 + i))

        result = find_recent_sessions(tmp_path, "**/*.jsonl", limit=3)
        assert len(result) == 3
        # Newest first (highest mtime = session_4)
        assert result[0].name == "log.jsonl"
        assert "session_4" in str(result[0])

    def test_respects_limit(self, tmp_path):
        for i in range(10):
            f = tmp_path / f"s{i}.jsonl"
            f.write_text("{}\n")
        result = find_recent_sessions(tmp_path, "*.jsonl", limit=3)
        assert len(result) == 3

    def test_missing_dir(self):
        result = find_recent_sessions("/tmp/riva_nonexistent_dir_12345")
        assert result == []

    def test_empty_dir(self, tmp_path):
        result = find_recent_sessions(tmp_path, "**/*.jsonl")
        assert result == []
