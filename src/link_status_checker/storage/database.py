from __future__ import annotations

import json
import sqlite3
import statistics
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AnalyticsSummary:
    total_checks: int = 0
    healthy: int = 0
    degraded: int = 0
    unhealthy: int = 0
    maintenance: int = 0
    unknown: int = 0
    uptime_percent: float | None = None
    average_latency_ms: float | None = None
    minimum_latency_ms: int | None = None
    maximum_latency_ms: int | None = None
    median_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    incident_count: int = 0
    open_incidents: int = 0
    longest_outage_seconds: int = 0


def percentile(values: Iterable[int], percentage: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * percentage
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


class MonitoringStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.path, timeout=10)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                );
                INSERT INTO schema_version(version)
                SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);

                CREATE TABLE IF NOT EXISTS websites (
                    id INTEGER PRIMARY KEY,
                    url TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    environment TEXT NOT NULL DEFAULT 'production',
                    customer TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    maintenance INTEGER NOT NULL DEFAULT 0,
                    maintenance_reason TEXT NOT NULL DEFAULT '',
                    settings_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY,
                    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    http_code INTEGER,
                    response_time_ms INTEGER,
                    dns_status TEXT NOT NULL,
                    ssl_status TEXT NOT NULL,
                    ssl_expiry TEXT,
                    problem_code TEXT,
                    technical_error TEXT,
                    included_in_uptime INTEGER NOT NULL,
                    available INTEGER,
                    FOREIGN KEY(website_id) REFERENCES websites(id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY,
                    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                    started_at TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    recovered_at TEXT,
                    reason TEXT NOT NULL,
                    last_problem_code TEXT,
                    failed_checks INTEGER NOT NULL DEFAULT 0,
                    open INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS certificate_snapshots (
                    id INTEGER PRIMARY KEY,
                    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
                    checked_at TEXT NOT NULL,
                    ssl_status TEXT NOT NULL,
                    expiry_date TEXT,
                    issuer TEXT,
                    subject TEXT
                );

                CREATE INDEX IF NOT EXISTS ix_checks_website_time
                    ON check_results(website_id, checked_at DESC);
                CREATE INDEX IF NOT EXISTS ix_checks_status_time
                    ON check_results(status, checked_at DESC);
                CREATE INDEX IF NOT EXISTS ix_incidents_open
                    ON incidents(open, website_id);
                """
            )

    def upsert_website(
        self,
        url: str,
        name: str,
        *,
        environment: str = "production",
        customer: str = "",
        tags: Iterable[str] = (),
        maintenance: bool = False,
        maintenance_reason: str = "",
        settings: dict[str, Any] | None = None,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO websites(
                    url, name, environment, customer, tags_json, maintenance,
                    maintenance_reason, settings_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name=excluded.name,
                    environment=excluded.environment,
                    customer=excluded.customer,
                    tags_json=excluded.tags_json,
                    maintenance=excluded.maintenance,
                    maintenance_reason=excluded.maintenance_reason,
                    settings_json=excluded.settings_json,
                    updated_at=excluded.updated_at
                """,
                (
                    url,
                    name,
                    environment,
                    customer,
                    json.dumps(sorted(set(tags))),
                    int(maintenance),
                    maintenance_reason,
                    json.dumps(settings or {}, sort_keys=True),
                    now,
                    now,
                ),
            )
            row = connection.execute("SELECT id FROM websites WHERE url = ?", (url,)).fetchone()
            return int(row["id"])

    def upsert_websites(self, websites: Iterable[tuple[str, str]]) -> dict[str, int]:
        now = datetime.now(timezone.utc).isoformat()
        normalized = list(websites)
        if not normalized:
            return {}
        with self.connect() as connection:
            connection.executemany(
                """
                INSERT INTO websites(url, name, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name=excluded.name,
                    updated_at=excluded.updated_at
                """,
                [(url, name, now, now) for url, name in normalized],
            )
            rows = connection.execute("SELECT id, url FROM websites").fetchall()
        requested = {url for url, _name in normalized}
        return {str(row["url"]): int(row["id"]) for row in rows if row["url"] in requested}

    def add_check(
        self,
        website_id: int,
        *,
        checked_at: str,
        status: str,
        reason: str,
        http_code: int | None,
        response_time_ms: int | None,
        dns_status: str,
        ssl_status: str,
        ssl_expiry: str,
        problem_code: str,
        technical_error: str,
        included_in_uptime: bool,
        available: bool | None,
        issuer: str = "",
        subject: str = "",
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO check_results(
                    website_id, checked_at, status, reason, http_code,
                    response_time_ms, dns_status, ssl_status, ssl_expiry,
                    problem_code, technical_error, included_in_uptime, available
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    website_id,
                    checked_at,
                    status,
                    reason,
                    http_code,
                    response_time_ms,
                    dns_status,
                    ssl_status,
                    ssl_expiry or None,
                    problem_code or None,
                    technical_error or None,
                    int(included_in_uptime),
                    None if available is None else int(available),
                ),
            )
            previous = connection.execute(
                """
                SELECT ssl_status, expiry_date, issuer, subject
                FROM certificate_snapshots
                WHERE website_id = ?
                ORDER BY checked_at DESC LIMIT 1
                """,
                (website_id,),
            ).fetchone()
            snapshot = (ssl_status, ssl_expiry or None, issuer or None, subject or None)
            if previous is None or tuple(previous) != snapshot:
                connection.execute(
                    """
                    INSERT INTO certificate_snapshots(
                        website_id, checked_at, ssl_status, expiry_date, issuer, subject
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (website_id, checked_at, *snapshot),
                )

    def list_websites(self, limit: int = 2000) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM websites ORDER BY name COLLATE NOCASE LIMIT ?",
                (max(1, min(limit, 10000)),),
            ).fetchall()

    def open_incident_website_ids(self) -> set[int]:
        rows = self.connect().execute("SELECT DISTINCT website_id FROM incidents WHERE open = 1").fetchall()
        return {int(row["website_id"]) for row in rows}

    def delete_website(self, url: str) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM websites WHERE url = ?", (url,))

    def set_maintenance(self, url: str, enabled: bool, reason: str = "") -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE websites
                SET maintenance = ?, maintenance_reason = ?, updated_at = ?
                WHERE url = ?
                """,
                (int(enabled), reason, datetime.now(timezone.utc).isoformat(), url),
            )

    def recent_latencies(self, website_id: int, limit: int = 60) -> list[int]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT response_time_ms FROM check_results
                WHERE website_id = ? AND response_time_ms IS NOT NULL
                ORDER BY checked_at DESC LIMIT ?
                """,
                (website_id, max(1, min(limit, 500))),
            ).fetchall()
        return [int(row["response_time_ms"]) for row in reversed(rows)]

    def update_incident(
        self,
        website_id: int,
        status: str,
        reason: str,
        problem_code: str,
        failure_threshold: int,
        recovery_threshold: int,
    ) -> None:
        with self.connect() as connection:
            recent = connection.execute(
                """
                SELECT status, checked_at FROM check_results
                WHERE website_id = ? ORDER BY checked_at DESC
                LIMIT ?
                """,
                (website_id, max(failure_threshold, recovery_threshold)),
            ).fetchall()
            open_row = connection.execute(
                "SELECT id FROM incidents WHERE website_id = ? AND open = 1",
                (website_id,),
            ).fetchone()
            failed = [row for row in recent[:failure_threshold] if row["status"] == "UNHEALTHY"]
            recovered = [row for row in recent[:recovery_threshold] if row["status"] == "HEALTHY"]
            now = datetime.now(timezone.utc).isoformat()
            if not open_row and len(failed) >= failure_threshold:
                connection.execute(
                    """
                    INSERT INTO incidents(
                        website_id, started_at, detected_at, reason,
                        last_problem_code, failed_checks, open
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                    """,
                    (website_id, failed[-1]["checked_at"], now, reason, problem_code, len(failed)),
                )
            elif open_row and len(recovered) >= recovery_threshold:
                connection.execute(
                    "UPDATE incidents SET recovered_at = ?, open = 0 WHERE id = ?",
                    (now, int(open_row["id"])),
                )
            elif open_row and status == "UNHEALTHY":
                connection.execute(
                    """
                    UPDATE incidents
                    SET failed_checks = failed_checks + 1,
                        reason = ?, last_problem_code = ?
                    WHERE id = ?
                    """,
                    (reason, problem_code, int(open_row["id"])),
                )

    def analytics(self, since: datetime | None = None, website_id: int | None = None) -> AnalyticsSummary:
        since = since or datetime.now(timezone.utc) - timedelta(days=1)
        clauses = ["checked_at >= ?"]
        params: list[Any] = [since.isoformat()]
        if website_id is not None:
            clauses.append("website_id = ?")
            params.append(website_id)
        where = " AND ".join(clauses)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT status, response_time_ms, included_in_uptime, available
                FROM check_results WHERE {where}
                """,
                params,
            ).fetchall()
            incident_row = connection.execute(
                f"""
                SELECT COUNT(*) AS total, COALESCE(SUM(open), 0) AS open_count
                FROM incidents
                WHERE started_at >= ? {"AND website_id = ?" if website_id is not None else ""}
                """,
                params,
            ).fetchone()
            duration_rows = connection.execute(
                f"""
                SELECT started_at, COALESCE(recovered_at, ?) AS ended_at
                FROM incidents WHERE started_at >= ?
                {"AND website_id = ?" if website_id is not None else ""}
                """,
                [datetime.now(timezone.utc).isoformat(), *params],
            ).fetchall()

        counts = dict.fromkeys(("HEALTHY", "DEGRADED", "UNHEALTHY", "MAINTENANCE", "UNKNOWN"), 0)
        latencies: list[int] = []
        available = unavailable = 0
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            if row["response_time_ms"] is not None:
                latencies.append(int(row["response_time_ms"]))
            if row["included_in_uptime"]:
                if row["available"]:
                    available += 1
                else:
                    unavailable += 1
        denominator = available + unavailable
        uptime = available / denominator * 100 if denominator else None
        durations = []
        for row in duration_rows:
            started = datetime.fromisoformat(row["started_at"])
            ended = datetime.fromisoformat(row["ended_at"])
            durations.append(max(0, int((ended - started).total_seconds())))
        return AnalyticsSummary(
            total_checks=len(rows),
            healthy=counts["HEALTHY"],
            degraded=counts["DEGRADED"],
            unhealthy=counts["UNHEALTHY"],
            maintenance=counts["MAINTENANCE"],
            unknown=counts["UNKNOWN"],
            uptime_percent=uptime,
            average_latency_ms=statistics.fmean(latencies) if latencies else None,
            minimum_latency_ms=min(latencies) if latencies else None,
            maximum_latency_ms=max(latencies) if latencies else None,
            median_latency_ms=statistics.median(latencies) if latencies else None,
            p95_latency_ms=percentile(latencies, 0.95),
            incident_count=int(incident_row["total"]),
            open_incidents=int(incident_row["open_count"]),
            longest_outage_seconds=max(durations, default=0),
        )
