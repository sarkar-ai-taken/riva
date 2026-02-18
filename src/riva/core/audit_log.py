"""Tamper-evident, append-only audit log for compliance reporting.

Produces a JSONL file where each entry includes an HMAC-chained hash
of the previous entry, making unauthorized modifications detectable.

Supports export to CEF (Common Event Format) for SIEM integration.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_LOG_DIR = Path.home() / ".config" / "riva"
_HMAC_KEY = b"riva-audit-log-integrity"  # Not a secret — detects accidental tampering


@dataclass
class AuditLogEntry:
    """A single audit log record."""

    timestamp: str  # ISO 8601
    event_id: str
    event_type: str  # scan, audit_finding, boundary_violation, agent_lifecycle
    agent_name: str | None
    detail: str
    severity: str  # info, low, medium, high, critical
    metadata: dict = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""


class AuditLog:
    """Append-only, tamper-evident JSONL audit log.

    Each entry includes an HMAC hash chained from the previous entry,
    enabling integrity verification of the full log.
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or _DEFAULT_LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._log_file = self._log_dir / "audit.jsonl"
        self._prev_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        """Read the hash from the last entry in the log file."""
        if not self._log_file.exists():
            return ""
        try:
            last_line = ""
            with open(self._log_file) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last_line = line
            if last_line:
                entry = json.loads(last_line)
                return entry.get("entry_hash", "")
        except Exception:
            pass
        return ""

    @staticmethod
    def _compute_hash(entry_data: dict, prev_hash: str) -> str:
        """Compute HMAC-SHA256 for an entry chained to the previous hash."""
        canonical = json.dumps(
            {
                "timestamp": entry_data["timestamp"],
                "event_id": entry_data["event_id"],
                "event_type": entry_data["event_type"],
                "agent_name": entry_data["agent_name"],
                "detail": entry_data["detail"],
                "severity": entry_data["severity"],
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        )
        return hmac.new(_HMAC_KEY, canonical.encode(), hashlib.sha256).hexdigest()

    def append(
        self,
        event_type: str,
        detail: str,
        severity: str = "info",
        agent_name: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLogEntry:
        """Append a new entry to the audit log.

        Returns the created entry.
        """
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())

        entry_data = {
            "timestamp": now,
            "event_id": event_id,
            "event_type": event_type,
            "agent_name": agent_name,
            "detail": detail,
            "severity": severity,
            "metadata": metadata or {},
            "prev_hash": self._prev_hash,
        }

        entry_hash = self._compute_hash(entry_data, self._prev_hash)
        entry_data["entry_hash"] = entry_hash

        with open(self._log_file, "a") as fh:
            fh.write(json.dumps(entry_data, default=str) + "\n")

        self._prev_hash = entry_hash

        return AuditLogEntry(**entry_data)

    def verify_integrity(self) -> tuple[bool, int, str]:
        """Verify the HMAC chain of the entire audit log.

        Returns:
            (is_valid, entries_checked, error_message)
        """
        if not self._log_file.exists():
            return True, 0, ""

        prev_hash = ""
        count = 0

        try:
            with open(self._log_file) as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return False, count, f"Line {line_num}: invalid JSON"

                    stored_hash = entry.get("entry_hash", "")
                    stored_prev = entry.get("prev_hash", "")

                    if stored_prev != prev_hash:
                        return False, count, (
                            f"Line {line_num}: chain break — "
                            f"expected prev_hash={prev_hash[:16]}..., "
                            f"got {stored_prev[:16]}..."
                        )

                    computed = self._compute_hash(entry, prev_hash)
                    if computed != stored_hash:
                        return False, count, (
                            f"Line {line_num}: hash mismatch — entry may have been tampered"
                        )

                    prev_hash = stored_hash
                    count += 1

        except Exception as exc:
            return False, count, f"Read error: {exc}"

        return True, count, ""

    def read_entries(self, hours: float | None = None, event_type: str | None = None) -> list[dict]:
        """Read entries from the audit log, optionally filtered.

        Args:
            hours: Only return entries from the last N hours.
            event_type: Only return entries of this type.

        Returns:
            List of entry dicts, most recent last.
        """
        if not self._log_file.exists():
            return []

        cutoff = None
        if hours is not None:
            cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)

        entries: list[dict] = []
        with open(self._log_file) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event_type and entry.get("event_type") != event_type:
                    continue

                if cutoff:
                    try:
                        ts = datetime.fromisoformat(entry["timestamp"]).timestamp()
                        if ts < cutoff:
                            continue
                    except (KeyError, ValueError):
                        continue

                entries.append(entry)

        return entries

    def export_jsonl(self, output_path: Path, hours: float = 24.0) -> int:
        """Export filtered entries to a JSONL file.

        Returns the number of entries exported.
        """
        entries = self.read_entries(hours=hours)
        with open(output_path, "w") as fh:
            for entry in entries:
                fh.write(json.dumps(entry, default=str) + "\n")
        return len(entries)

    def export_cef(self, output_path: Path, hours: float = 24.0) -> int:
        """Export entries in CEF (Common Event Format) for SIEM integration.

        CEF format:
            CEF:0|Riva|AgentMonitor|1.0|<event_type>|<detail>|<severity_num>|...

        Returns the number of entries exported.
        """
        severity_map = {
            "info": 1,
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10,
        }

        entries = self.read_entries(hours=hours)
        with open(output_path, "w") as fh:
            for entry in entries:
                sev_num = severity_map.get(entry.get("severity", "info"), 1)
                # Escape pipes and backslashes in CEF fields
                detail = entry.get("detail", "").replace("\\", "\\\\").replace("|", "\\|")
                agent = entry.get("agent_name") or "none"
                event_type = entry.get("event_type", "unknown")
                timestamp = entry.get("timestamp", "")
                event_id = entry.get("event_id", "")

                extensions = (
                    f"rt={timestamp} "
                    f"dvchost=localhost "
                    f"cs1={agent} cs1Label=agentName "
                    f"externalId={event_id}"
                )

                cef_line = (
                    f"CEF:0|Riva|AgentMonitor|1.0|{event_type}|{detail}|{sev_num}|{extensions}"
                )
                fh.write(cef_line + "\n")

        return len(entries)

    @property
    def log_file(self) -> Path:
        """Return the path to the audit log file."""
        return self._log_file

    @property
    def entry_count(self) -> int:
        """Return the number of entries in the log."""
        if not self._log_file.exists():
            return 0
        count = 0
        with open(self._log_file) as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count
