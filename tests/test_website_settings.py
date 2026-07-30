from __future__ import annotations

from dataclasses import asdict

from conftest import make_result

import main


def test_saved_website_settings_are_restored(window):
    rules = main.HealthRules(
        accepted_status_min=201,
        accepted_status_max=204,
        warning_latency_ms=750,
        critical_latency_ms=1800,
        failure_threshold=2,
        recovery_threshold=3,
        ssl_warning_days=45,
        required_text="ready",
        timeout_seconds=12,
        maintenance=True,
        maintenance_reason="Planned deployment",
    )
    url = "https://status.example.com/"
    window.store.upsert_website(
        url,
        "Status API",
        environment="staging",
        customer="Operations",
        tags=("api", "priority"),
        maintenance=True,
        maintenance_reason=rules.maintenance_reason,
        settings={
            **asdict(rules),
            "iis_related": True,
            "monitoring_enabled": False,
        },
    )

    window._load_saved_websites()
    restored = window.targets[url]

    assert restored.environment == "staging"
    assert restored.customer == "Operations"
    assert restored.tags == ("api", "priority")
    assert restored.iis_related is True
    assert restored.monitoring_enabled is False
    assert restored.health_rules == rules
    assert url in window.maintenance_urls


def test_check_all_skips_websites_with_monitoring_disabled(window, monkeypatch):
    enabled = main.LinkTarget("Enabled", "enabled.test", "https://enabled.test/")
    disabled = main.LinkTarget(
        "Disabled",
        "disabled.test",
        "https://disabled.test/",
        monitoring_enabled=False,
    )
    window.targets = {
        enabled.normalized_url: enabled,
        disabled.normalized_url: disabled,
    }
    started = []
    monkeypatch.setattr(window.thread_pool, "start", started.append)

    window.check_all()

    assert window.pending_checks == 1
    assert len(started) == 1
    assert started[0].target == enabled


def test_website_filters_work_together_and_reset(window):
    production = main.LinkTarget(
        "Production API",
        "prod.test",
        "https://prod.test/",
        environment="production",
        tags=("customer-a",),
    )
    staging = main.LinkTarget(
        "Staging API",
        "staging.test",
        "https://staging.test/",
        environment="staging",
        iis_related=True,
    )
    window.targets = {
        production.normalized_url: production,
        staging.normalized_url: staging,
    }
    window.latest_results = {
        production.normalized_url: make_result(
            normalized_url=production.normalized_url,
            name=production.name,
            health_status=main.HealthStatus.HEALTHY.value,
            response_time_ms="120",
        ),
        staging.normalized_url: make_result(
            normalized_url=staging.normalized_url,
            name=staging.name,
            health_status=main.HealthStatus.DEGRADED.value,
            response_time_ms="1400",
        ),
    }

    window.environment_filter.setCurrentText("Staging")
    window.status_filter.setCurrentText("Degraded")
    window.condition_filter.setCurrentText("IIS related")

    assert window._filtered_target_keys() == [staging.normalized_url]

    window.reset_website_filters()
    assert window._filtered_target_keys() == [
        production.normalized_url,
        staging.normalized_url,
    ]
