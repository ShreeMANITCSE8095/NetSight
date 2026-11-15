"""SQLite persistent storage for NetSight per-minute aggregated history."""

import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import contextmanager
import datetime
import logging

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode and busy timeout for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS history_minute (
                    minute_ts INTEGER PRIMARY KEY,
                    total_bytes INTEGER NOT NULL,
                    total_packets INTEGER NOT NULL,
                    bps REAL NOT NULL,
                    pps REAL NOT NULL,
                    active_flows INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS history_app (
                    minute_ts INTEGER NOT NULL,
                    app TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    packets INTEGER NOT NULL,
                    PRIMARY KEY (minute_ts, app)
                );

                CREATE TABLE IF NOT EXISTS history_domain (
                    minute_ts INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    app TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    packets INTEGER NOT NULL,
                    PRIMARY KEY (minute_ts, domain)
                );

                CREATE INDEX IF NOT EXISTS idx_history_minute_ts ON history_minute (minute_ts);
                CREATE INDEX IF NOT EXISTS idx_history_app_ts ON history_app (minute_ts);
                CREATE INDEX IF NOT EXISTS idx_history_domain_ts ON history_domain (minute_ts);
                """
            )
        logger.info(f"Initialized SQLite database at {self.db_path}")

    def record_minute_rollup(
        self,
        minute_ts: int,
        total_bytes: int,
        total_packets: int,
        bps: float,
        pps: float,
        active_flows: int,
        app_data: Dict[str, Dict[str, int]],
        domain_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        """Record a 1-minute aggregation window atomically."""
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO history_minute (minute_ts, total_bytes, total_packets, bps, pps, active_flows)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (minute_ts, total_bytes, total_packets, bps, pps, active_flows),
                )

                for app, counts in app_data.items():
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO history_app (minute_ts, app, bytes, packets)
                        VALUES (?, ?, ?, ?);
                        """,
                        (minute_ts, app, counts.get("bytes", 0), counts.get("packets", 0)),
                    )

                if domain_data:
                    for domain, data in domain_data.items():
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO history_domain (minute_ts, domain, app, bytes, packets)
                            VALUES (?, ?, ?, ?, ?);
                            """,
                            (
                                minute_ts,
                                domain,
                                data.get("app", "Unlabeled"),
                                data.get("bytes", 0),
                                data.get("packets", 0),
                            ),
                        )
        except Exception as e:
            logger.error(f"Failed to record minute rollup: {e}")

    def get_history(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Retrieve the last N minutes of rollups with application breakdown."""
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        start_ts = now_ts - (minutes * 60)

        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT minute_ts, total_bytes, total_packets, bps, pps, active_flows
                FROM history_minute
                WHERE minute_ts >= ?
                ORDER BY minute_ts ASC;
                """,
                (start_ts,),
            )
            rows = cursor.fetchall()

            # Retrieve app breakdowns
            app_cursor = conn.execute(
                """
                SELECT minute_ts, app, bytes, packets
                FROM history_app
                WHERE minute_ts >= ?
                ORDER BY minute_ts ASC;
                """,
                (start_ts,),
            )
            app_rows = app_cursor.fetchall()

        app_map: Dict[int, Dict[str, int]] = {}
        for r in app_rows:
            ts = r["minute_ts"]
            if ts not in app_map:
                app_map[ts] = {}
            app_map[ts][r["app"]] = r["bytes"]

        history = []
        for r in rows:
            ts = r["minute_ts"]
            history.append(
                {
                    "minute": ts,
                    "timestamp_iso": datetime.datetime.fromtimestamp(
                        ts, tz=datetime.timezone.utc
                    ).isoformat(),
                    "bps": round(r["bps"], 1),
                    "pps": round(r["pps"], 1),
                    "total_bytes": r["total_bytes"],
                    "total_packets": r["total_packets"],
                    "active_flows": r["active_flows"],
                    "app_breakdown": app_map.get(ts, {}),
                }
            )
        return history

    def get_aggregated_apps(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Retrieve aggregated app totals over the last N minutes."""
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        start_ts = now_ts - (minutes * 60)

        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT app, SUM(bytes) as total_bytes, SUM(packets) as total_packets
                FROM history_app
                WHERE minute_ts >= ?
                GROUP BY app
                ORDER BY total_bytes DESC;
                """,
                (start_ts,),
            )
            rows = cursor.fetchall()

        total_bytes = sum(r["total_bytes"] for r in rows)
        result = []
        for r in rows:
            b = r["total_bytes"]
            pct = (b * 100.0 / total_bytes) if total_bytes > 0 else 0.0
            result.append(
                {
                    "app": r["app"],
                    "bytes": b,
                    "packets": r["total_packets"],
                    "flows": 0,
                    "share_percent": round(pct, 1),
                }
            )
        return result

    def get_aggregated_domains(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Retrieve aggregated domain totals over the last N minutes."""
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        start_ts = now_ts - (minutes * 60)

        with self._get_conn() as conn:
            cursor = conn.execute(
                """
                SELECT domain, app, SUM(bytes) as total_bytes, SUM(packets) as total_packets
                FROM history_domain
                WHERE minute_ts >= ?
                GROUP BY domain
                ORDER BY total_bytes DESC;
                """,
                (start_ts,),
            )
            rows = cursor.fetchall()

        total_bytes = sum(r["total_bytes"] for r in rows)
        result = []
        for r in rows:
            b = r["total_bytes"]
            pct = (b * 100.0 / total_bytes) if total_bytes > 0 else 0.0
            result.append(
                {
                    "domain": r["domain"],
                    "app": r["app"],
                    "bytes": b,
                    "packets": r["total_packets"],
                    "flows": 0,
                    "share_percent": round(pct, 1),
                }
            )
        return result

    def prune_history(self, retention_days: int = 7) -> int:
        """Delete historical rollups older than retention_days to prevent unbounded DB growth (SEC-13)."""
        cutoff_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - (retention_days * 86400)
        deleted_count = 0
        try:
            with self._get_conn() as conn:
                cur1 = conn.execute("DELETE FROM history_minute WHERE minute_ts < ?;", (cutoff_ts,))
                cur2 = conn.execute("DELETE FROM history_app WHERE minute_ts < ?;", (cutoff_ts,))
                cur3 = conn.execute("DELETE FROM history_domain WHERE minute_ts < ?;", (cutoff_ts,))
                deleted_count = (cur1.rowcount or 0) + (cur2.rowcount or 0) + (cur3.rowcount or 0)
            if deleted_count > 0:
                logger.info(f"Pruned {deleted_count} historical records older than {retention_days} days")
        except Exception as e:
            logger.error(f"Failed to prune historical records: {e}")
        return deleted_count
