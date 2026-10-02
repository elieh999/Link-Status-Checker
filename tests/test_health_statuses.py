from __future__ import annotations

import pytest

from src.link_status_checker.domain.statuses import (
    HealthFacts,
    HealthRules,
    HealthStatus,
    classify_health,
)


def facts(**changes) -> HealthFacts:
    values = {
        "reliable": True,
        "dns_ok": True,
        "connection_ok": True,
        "http_code": 200,
        "latency_ms": 120,
        "ssl_status": "SSL VALID",
        "consecutive_failures": 0,
        "content_ok": True,
    }
    values.update(changes)
    return HealthFacts(**values)


def test_healthy_requires_all_default_rules_to_pass():
    decision = classify_health(facts())
    assert decision.status is HealthStatus.HEALTHY
    assert decision.available is True
    assert decision.included_in_uptime is True


@pytest.mark.parametrize("code", [200, 204, 301, 399])
def test_default_http_range_is_healthy(code):
    assert classify_health(facts(http_code=code)).status is HealthStatus.HEALTHY


def test_http_500_is_never_healthy():
    assert classify_health(facts(http_code=500, consecutive_failures=1)).status is HealthStatus.DEGRADED
    assert classify_health(facts(http_code=500, consecutive_failures=3)).status is HealthStatus.UNHEALTHY


def test_slow_and_critical_latency_have_distinct_statuses():
    assert classify_health(facts(latency_ms=1500)).status is HealthStatus.DEGRADED
    assert classify_health(facts(latency_ms=3500)).status is HealthStatus.UNHEALTHY


@pytest.mark.parametrize(
    "ssl_status",
    ["SSL EXPIRED", "SSL NOT YET VALID", "SSL HOSTNAME MISMATCH", "SSL UNTRUSTED", "SSL ERROR"],
)
def test_confirmed_ssl_security_failures_are_unhealthy_immediately(ssl_status):
    decision = classify_health(facts(ssl_status=ssl_status))
    assert decision.status is HealthStatus.UNHEALTHY
    assert decision.available is False


def test_ssl_expiry_warning_is_degraded_but_available():
    decision = classify_health(facts(ssl_status="SSL EXPIRES SOON"))
    assert decision.status is HealthStatus.DEGRADED
    assert decision.available is True


def test_maintenance_and_unknown_are_excluded_from_uptime():
    maintenance = classify_health(facts(), HealthRules(maintenance=True, maintenance_reason="Planned work"))
    unknown = classify_health(facts(reliable=False))
    assert maintenance.status is HealthStatus.MAINTENANCE
    assert unknown.status is HealthStatus.UNKNOWN
    assert maintenance.included_in_uptime is False
    assert unknown.included_in_uptime is False
