from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.link_status_checker.storage.database import MonitoringStore, percentile


def add_check(store, website_id, status, checked_at, latency=100, available=True, included=True):
    store.add_check(
        website_id,
        checked_at=checked_at,
        status=status,
        reason=status,
        http_code=200 if available else 500,
        response_time_ms=latency,
        dns_status="RESOLVED",
        ssl_status="SSL VALID",
        ssl_expiry="2027-01-01",
        problem_code="",
        technical_error="",
        included_in_uptime=included,
        available=available if included else None,
    )


def test_schema_initializes_and_websites_are_persistent(tmp_path):
    path = tmp_path / "monitoring.db"
    store = MonitoringStore(path)
    website_id = store.upsert_website("https://example.com/", "example.com", tags=["public", "production"])
    second = MonitoringStore(path)
    rows = second.list_websites()
    assert rows[0]["id"] == website_id
    assert rows[0]["url"] == "https://example.com/"


def test_uptime_and_latency_exclude_maintenance_and_unknown(tmp_path):
    store = MonitoringStore(tmp_path / "monitoring.db")
    website_id = store.upsert_website("https://example.com/", "example.com")
    now = datetime.now(timezone.utc)
    add_check(store, website_id, "HEALTHY", now.isoformat(), 100, True)
    add_check(store, website_id, "DEGRADED", (now + timedelta(seconds=1)).isoformat(), 300, True)
    add_check(store, website_id, "UNHEALTHY", (now + timedelta(seconds=2)).isoformat(), 500, False)
    add_check(store, website_id, "MAINTENANCE", (now + timedelta(seconds=3)).isoformat(), 900, None, False)
    add_check(store, website_id, "UNKNOWN", (now + timedelta(seconds=4)).isoformat(), None, None, False)

    summary = store.analytics(now - timedelta(minutes=1))
    assert summary.total_checks == 5
    assert summary.uptime_percent == pytest.approx(200 / 3)
    assert summary.average_latency_ms == 450
    assert summary.median_latency_ms == 400
    assert summary.p95_latency_ms == pytest.approx(840)


def test_incident_opens_once_and_recovers_after_threshold(tmp_path):
    store = MonitoringStore(tmp_path / "monitoring.db")
    website_id = store.upsert_website("https://example.com/", "example.com")
    now = datetime.now(timezone.utc)
    for index in range(3):
        add_check(
            store,
            website_id,
            "UNHEALTHY",
            (now + timedelta(seconds=index)).isoformat(),
            available=False,
        )
        store.update_incident(website_id, "UNHEALTHY", "HTTP 500", "http_error", 3, 2)
    summary = store.analytics(now - timedelta(minutes=1))
    assert summary.incident_count == 1
    assert summary.open_incidents == 1

    for index in range(2):
        add_check(store, website_id, "HEALTHY", (now + timedelta(seconds=10 + index)).isoformat())
        store.update_incident(website_id, "HEALTHY", "Recovered", "", 3, 2)
    recovered = store.analytics(now - timedelta(minutes=1))
    assert recovered.incident_count == 1
    assert recovered.open_incidents == 0


def test_percentile_uses_linear_interpolation():
    assert percentile([], 0.95) is None
    assert percentile([200], 0.95) == 200
    assert percentile([100, 200, 300, 400, 500], 0.95) == 480


def test_analytics_accepts_legacy_naive_incident_timestamps(tmp_path):
    store = MonitoringStore(tmp_path / "monitoring.db")
    website_id = store.upsert_website("https://legacy.example.com/", "Legacy")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    legacy_start = now.replace(tzinfo=None).isoformat()
    utc_end = (now + timedelta(seconds=75)).isoformat()
    with store.connect() as connection:
        connection.execute(
            """
            INSERT INTO incidents(
                website_id, started_at, detected_at, recovered_at, reason,
                last_problem_code, failed_checks, open
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                website_id,
                legacy_start,
                legacy_start,
                utc_end,
                "Legacy incident",
                "legacy",
                3,
            ),
        )

    summary = store.analytics(now - timedelta(minutes=1))

    assert summary.incident_count == 1
    assert summary.longest_outage_seconds == 75
