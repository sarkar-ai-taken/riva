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

            CREATE TABLE IF NOT EXISTS child_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                parent_pid INTEGER NOT NULL,
                child_pid INTEGER NOT NULL,
                child_name TEXT,
                child_exe TEXT,
                cpu_percent REAL DEFAULT 0.0,
                memory_mb REAL DEFAULT 0.0,
                status TEXT,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
            );

            CREATE TABLE IF NOT EXISTS orphan_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                original_parent_pid INTEGER NOT NULL,
                orphan_pid INTEGER NOT NULL,
                orphan_name TEXT,
                orphan_exe TEXT,
                detected_at REAL NOT NULL,
                resolved_at REAL,
                cpu_percent REAL DEFAULT 0.0,
                memory_mb REAL DEFAULT 0.0
            );
        """)
        conn.commit()

        # Safe ALTER TABLE for new columns on snapshots
        self._safe_add_column(conn, "snapshots", "tree_cpu_percent", "REAL DEFAULT 0.0")
        self._safe_add_column(conn, "snapshots", "tree_memory_mb", "REAL DEFAULT 0.0")
        self._safe_add_column(conn, "snapshots", "child_count", "INTEGER DEFAULT 0")
        self._safe_add_column(conn, "snapshots", "parent_pid", "INTEGER")
        self._safe_add_column(conn, "snapshots", "parent_name", "TEXT")
        self._safe_add_column(conn, "snapshots", "launched_by", "TEXT")

    @staticmethod
    def _safe_add_column(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
        """Add a column to a table if it doesn't already exist."""
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists

    def _get_or_create_agent(self, name: str, config_dir: str | None = None, api_domain: str | None = None) -> int:
        """Get or create an agent record, returning the agent id."""
        conn = self._get_conn()
        now = time.time()

        row = conn.execute("SELECT id FROM agents WHERE name = ?", (name,)).fetchone()
        if row:
            conn.execute(
                "UPDATE agents SET last_seen = ?, config_dir = COALESCE(?, config_dir), "
                "api_domain = COALESCE(?, api_domain) WHERE id = ?",
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

        tree_data = instance.extra.get("process_tree", {})
        cursor = conn.execute(
            """INSERT INTO snapshots
               (agent_id, timestamp, pid, cpu_percent, memory_mb, uptime_seconds,
                connection_count, status, tree_cpu_percent, tree_memory_mb,
                child_count, parent_pid, parent_name, launched_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                agent_id,
                time.time(),
                instance.pid,
                instance.cpu_percent,
                instance.memory_mb,
                instance.uptime_seconds,
                connection_count,
                instance.status.value,
                tree_data.get("tree_cpu_percent", 0.0),
                tree_data.get("tree_memory_mb", 0.0),
                tree_data.get("child_count", 0),
                getattr(instance, "parent_pid", None),
                getattr(instance, "parent_name", None),
                getattr(instance, "launched_by", None),
            ),
        )
        snapshot_id = cursor.lastrowid

        # Record network connections if available
        network_data = instance.extra.get("network", [])
        if network_data:
            for nc in network_data:
                conn.execute(
                    """INSERT INTO network_connections
                       (snapshot_id, local_addr, local_port, remote_addr,
                        remote_port, status, hostname, known_service, is_tls)
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

    def record_child_processes(self, snapshot_id: int, parent_pid: int, children: list[dict]) -> None:
        """Record child processes for a snapshot."""
        conn = self._get_conn()
        for child in children:
            conn.execute(
                """INSERT INTO child_processes
                   (snapshot_id, parent_pid, child_pid, child_name, child_exe, cpu_percent, memory_mb, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    snapshot_id,
                    parent_pid,
                    child.get("pid", 0),
                    child.get("name", ""),
                    child.get("exe", ""),
                    child.get("cpu_percent", 0.0),
                    child.get("memory_mb", 0.0),
                    child.get("status", ""),
                ),
            )
        conn.commit()

    def record_orphan(self, orphan: dict) -> None:
        """Record a detected orphan process."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO orphan_processes
               (agent_name, original_parent_pid, orphan_pid, orphan_name,
                orphan_exe, detected_at, cpu_percent, memory_mb)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                orphan.get("agent_name", ""),
                orphan.get("original_parent_pid", 0),
                orphan.get("pid", 0),
                orphan.get("name", ""),
                orphan.get("exe", ""),
                orphan.get("detected_at", time.time()),
                orphan.get("cpu_percent", 0.0),
                orphan.get("memory_mb", 0.0),
            ),
        )
        conn.commit()

    def resolve_orphan(self, orphan_pid: int) -> None:
        """Mark an orphan process as resolved."""
        conn = self._get_conn()
        conn.execute(
            "UPDATE orphan_processes SET resolved_at = ? WHERE orphan_pid = ? AND resolved_at IS NULL",
            (time.time(), orphan_pid),
        )
        conn.commit()

    def get_orphans(self, resolved: bool = False, hours: float = 24.0) -> list[dict]:
        """Retrieve orphan processes from storage."""
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)
        if resolved:
            rows = conn.execute(
                "SELECT * FROM orphan_processes WHERE detected_at > ? ORDER BY detected_at DESC",
                (cutoff,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM orphan_processes WHERE resolved_at IS NULL "
                "AND detected_at > ? ORDER BY detected_at DESC",
                (cutoff,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_child_processes(self, snapshot_id: int) -> list[dict]:
        """Retrieve child processes for a given snapshot."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM child_processes WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_snapshot_at(self, timestamp: float) -> list[dict]:
        """Get the closest snapshot per agent at or before the given timestamp."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT s.*, a.name as agent_name
               FROM snapshots s
               JOIN agents a ON s.agent_id = a.id
               WHERE s.id IN (
                   SELECT s2.id FROM snapshots s2
                   WHERE s2.agent_id = s.agent_id AND s2.timestamp <= ?
                   ORDER BY s2.timestamp DESC LIMIT 1
               )
               ORDER BY a.name""",
            (timestamp,),
        ).fetchall()
        return [dict(row) for row in rows]

    # --- Replay query methods ---

    def get_snapshot_timestamps(self, hours: float = 24.0) -> list[float]:
        """Return distinct snapshot timestamps within window (for timeline tick marks)."""
        conn = self._get_conn()
        cutoff = time.time() - (hours * 3600)
        rows = conn.execute(
            "SELECT DISTINCT timestamp FROM snapshots WHERE timestamp > ? ORDER BY timestamp",
            (cutoff,),
        ).fetchall()
        return [row["timestamp"] for row in rows]

    def get_state_at(self, timestamp: float) -> list[dict]:
        """Reconstruct agent states at a specific timestamp.

        For each agent, find the closest snapshot <= timestamp.
        Returns list of dicts with agent state including children and network data.
        """
        conn = self._get_conn()

        # Get closest snapshot per agent at or before the timestamp
        rows = conn.execute(
            """SELECT s.*, a.name as agent_name
               FROM snapshots s
               JOIN agents a ON s.agent_id = a.id
               INNER JOIN (
                   SELECT agent_id, MAX(timestamp) as max_ts
                   FROM snapshots
                   WHERE timestamp <= ?
                   GROUP BY agent_id
               ) latest ON s.agent_id = latest.agent_id AND s.timestamp = latest.max_ts""",
            (timestamp,),
        ).fetchall()

        results = []
        for row in rows:
            entry = dict(row)
            snapshot_id = entry["id"]

            # Attach children
            children = conn.execute(
                "SELECT * FROM child_processes WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchall()
            entry["children"] = [dict(c) for c in children]

            # Attach network connections
            connections = conn.execute(
                "SELECT * FROM network_connections WHERE snapshot_id = ?",
                (snapshot_id,),
            ).fetchall()
            entry["network_connections"] = [dict(c) for c in connections]

            results.append(entry)

        return results

    def get_timeline_summary(self, hours: float = 1.0, bucket_seconds: int = 60) -> list[dict]:
        """Aggregate snapshots into time buckets for the timeline bar.

        Returns list of: {timestamp, agent_count, total_cpu, total_memory,
        total_connections, orphan_count_at_time}
        """
        conn = self._get_conn()
        now = time.time()
        cutoff = now - (hours * 3600)

        # Bucket snapshots
        rows = conn.execute(
            """SELECT
                   CAST((timestamp / ?) AS INTEGER) * ? as bucket_ts,
                   COUNT(DISTINCT agent_id) as agent_count,
                   AVG(cpu_percent) as total_cpu,
                   AVG(memory_mb) as total_memory,
                   SUM(connection_count) as total_connections,
                   SUM(child_count) as total_children
               FROM snapshots
               WHERE timestamp > ?
               GROUP BY bucket_ts
               ORDER BY bucket_ts""",
            (bucket_seconds, bucket_seconds, cutoff),
        ).fetchall()

        results = []
        for row in rows:
            bucket_ts = row["bucket_ts"]
            # Count orphans active at this time
            orphan_count = conn.execute(
                """SELECT COUNT(*) as cnt FROM orphan_processes
                   WHERE detected_at <= ? AND (resolved_at IS NULL OR resolved_at > ?)""",
                (bucket_ts + bucket_seconds, bucket_ts),
            ).fetchone()["cnt"]

            results.append(
                {
                    "timestamp": bucket_ts,
                    "agent_count": row["agent_count"],
                    "total_cpu": round(row["total_cpu"] or 0, 2),
                    "total_memory": round(row["total_memory"] or 0, 2),
                    "total_connections": row["total_connections"] or 0,
                    "total_children": row["total_children"] or 0,
                    "orphan_count": orphan_count,
                }
            )

        return results

    def cleanup(self, retention_days: int = _DEFAULT_RETENTION_DAYS) -> None:
        """Remove data older than retention_days."""
        conn = self._get_conn()
        cutoff = time.time() - (retention_days * 86400)

        # Delete old child processes (via snapshots)
        conn.execute(
            """DELETE FROM child_processes WHERE snapshot_id IN
               (SELECT id FROM snapshots WHERE timestamp < ?)""",
            (cutoff,),
        )
        # Delete old network connections (via snapshots)
        conn.execute(
            """DELETE FROM network_connections WHERE snapshot_id IN
               (SELECT id FROM snapshots WHERE timestamp < ?)""",
            (cutoff,),
        )
        conn.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
        conn.execute("DELETE FROM orphan_processes WHERE detected_at < ?", (cutoff,))
        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
