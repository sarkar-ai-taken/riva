"""SQLite data persistence for Riva."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path


_DEFAULT_DB_PATH = Path.home() / ".config" / "riva" / "riva.db"
_DEFAULT_RETENTION_DAYS = 7


class RivaStorage:
    """SQLite-backed storage for agent snapshots, network connections, and audit events.

    Uses WAL mode for concurrent read/write access from the monitor thread
    and web server.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self._db_path),
                timeout=5.0,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                config_dir TEXT,
                api_domain TEXT
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                timestamp REAL NOT NULL,
                pid INTEGER,
                cpu_percent REAL,
                memory_mb REAL,
                uptime_seconds REAL,
                connection_count INTEGER DEFAULT 0,
                status TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            );

            CREATE INDEX IF NOT EXISTS idx_snapshots_agent_ts
                ON snapshots(agent_id, timestamp);

            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_port INTEGER,
                status TEXT,
                hostname TEXT,
                known_service TEXT,
                is_tls INTEGER DEFAULT 0,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT,
                severity TEXT DEFAULT 'info'
            );

            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_events(timestamp);
        """)
        conn.commit()

    def _get_or_create_agent(self, name: str, config_dir: str | None = None, api_domain: str | None = None) -> int:
        """Get or create an agent record, returning the agent id."""
        conn = self._get_conn()
        now = time.time()

        row = conn.execute("SELECT id FROM agents WHERE name = ?", (name,)).fetchone()
        if row:
            conn.execute(
                "UPDATE agents SET last_seen = ?, config_dir = COALESCE(?, config_dir), api_domain = COALESCE(?, api_domain) WHERE id = ?",
                (now, config_dir, api_domain, row["id"]),
            )
            conn.commit()
            return row["id"]

        cursor = conn.execute(
            "INSERT INTO agents (name, first_seen, last_seen, config_dir, api_domain) VALUES (?, ?, ?, ?, ?)",
            (name, now, now, config_dir, api_domain),
        )
        conn.commit()
        return cursor.lastrowid

    def record_snapshot(self, instance, connection_count: int = 0) -> None:
        """Record a resource snapshot for an agent instance."""
        conn = self._get_conn()
        agent_id = self._get_or_create_agent(
            instance.name,
            config_dir=instance.config_dir,
            api_domain=instance.api_domain,
        )

        cursor = conn.execute(
            """INSERT INTO snapshots (agent_id, timestamp, pid, cpu_percent, memory_mb, uptime_seconds, connection_count, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                agent_id,
                time.time(),
                instance.pid,
                instance.cpu_percent,
                instance.memory_mb,
                instance.uptime_seconds,
                connection_count,
                instance.status.value,
            ),
        )
        snapshot_id = cursor.lastrowid

        # Record network connections if available
        network_data = instance.extra.get("network", [])
        if network_data:
            for nc in network_data:
                conn.execute(
                    """INSERT INTO network_connections
                       (snapshot_id, local_addr, local_port, remote_addr, remote_port, status, hostname, known_service, is_tls)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        snapshot_id,
                        nc.get("local_addr", ""),
                        nc.get("local_port", 0),
                        nc.get("remote_addr", ""),
                        nc.get("remote_port", 0),
                        nc.get("status", ""),
                        nc.get("hostname"),
                        nc.get("known_service"),
                        1 if nc.get("is_tls") else 0,
                    ),
                )

        conn.commit()

    def record_audit_event(self, check_name: str, status: str, detail: str, severity: str = "info") -> None:
        """Record an audit event."""
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO audit_events (timestamp, check_name, status, detail, severity) VALUES (?, ?, ?, ?, ?)",
            (time.time(), check_name, status, detail, severity),
        )
        conn.commit()

    def get_snapshots(self, agent_name: str | None = None, hours: float = 1.0) -> list[dict]:
        """Retrieve historical snapshots."""
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)

        if agent_name:
            rows = conn.execute(
                """SELECT s.*, a.name as agent_name FROM snapshots s
                   JOIN agents a ON s.agent_id = a.id
                   WHERE a.name = ? AND s.timestamp > ?
                   ORDER BY s.timestamp DESC""",
                (agent_name, cutoff),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT s.*, a.name as agent_name FROM snapshots s
                   JOIN agents a ON s.agent_id = a.id
                   WHERE s.timestamp > ?
                   ORDER BY s.timestamp DESC""",
                (cutoff,),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_network_history(self, hours: float = 1.0) -> list[dict]:
        """Retrieve historical network connections."""
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)

        rows = conn.execute(
            """SELECT nc.*, s.timestamp, a.name as agent_name
               FROM network_connections nc
               JOIN snapshots s ON nc.snapshot_id = s.id
               JOIN agents a ON s.agent_id = a.id
               WHERE s.timestamp > ?
               ORDER BY s.timestamp DESC
               LIMIT 1000""",
            (cutoff,),
        ).fetchall()

        return [dict(row) for row in rows]

    def get_audit_events(self, hours: float = 24.0) -> list[dict]:
        """Retrieve historical audit events."""
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)

        rows = conn.execute(
            "SELECT * FROM audit_events WHERE timestamp > ? ORDER BY timestamp DESC",
            (cutoff,),
        ).fetchall()

        return [dict(row) for row in rows]

    def cleanup(self, retention_days: int = _DEFAULT_RETENTION_DAYS) -> None:
        """Remove data older than retention_days."""
        conn = self._get_conn()
        cutoff = time.time() - (retention_days * 86400)

        # Delete old network connections (via snapshots)
        conn.execute(
            """DELETE FROM network_connections WHERE snapshot_id IN
               (SELECT id FROM snapshots WHERE timestamp < ?)""",
            (cutoff,),
        )
        conn.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
