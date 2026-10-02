from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class HealthStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    MAINTENANCE = "MAINTENANCE"
    UNKNOWN = "UNKNOWN"


STATUS_LABELS = {
    HealthStatus.HEALTHY: ("OK", "Healthy", "All configured checks passed."),
    HealthStatus.DEGRADED: ("!", "Degraded", "The website is reachable but needs attention."),
    HealthStatus.UNHEALTHY: ("X", "Unhealthy", "A required website check failed."),
    HealthStatus.MAINTENANCE: ("||", "Maintenance", "Monitoring is excluded from uptime."),
    HealthStatus.UNKNOWN: ("?", "Unknown", "No reliable completed check is available."),
}


@dataclass(frozen=True)
class HealthRules:
    accepted_status_min: int = 200
    accepted_status_max: int = 399
    warning_latency_ms: int = 1000
    critical_latency_ms: int = 3000
    failure_threshold: int = 3
    recovery_threshold: int = 2
    ssl_warning_days: int = 30
    require_valid_ssl: bool = True
    required_text: str = ""
    forbidden_text: str = ""
    timeout_seconds: int | None = None
    maintenance: bool = False
    maintenance_reason: str = ""


@dataclass(frozen=True)
class HealthFacts:
    reliable: bool
    dns_ok: bool
    connection_ok: bool
    http_code: int | None
    latency_ms: int | None
    ssl_status: str
    consecutive_failures: int = 0
    content_ok: bool = True


@dataclass(frozen=True)
class HealthDecision:
    status: HealthStatus
    reason: str
    included_in_uptime: bool
    available: bool | None


def classify_health(facts: HealthFacts, rules: HealthRules | None = None) -> HealthDecision:
    rules = rules or HealthRules()
    if rules.maintenance:
        reason = rules.maintenance_reason or "Maintenance mode is enabled."
        return HealthDecision(HealthStatus.MAINTENANCE, reason, False, None)
    if not facts.reliable:
        return HealthDecision(HealthStatus.UNKNOWN, "The check did not produce a reliable result.", False, None)

    ssl_critical = facts.ssl_status in {
        "SSL EXPIRED",
        "SSL NOT YET VALID",
        "SSL HOSTNAME MISMATCH",
        "SSL UNTRUSTED",
        "SSL ERROR",
    }
    if rules.require_valid_ssl and ssl_critical:
        return HealthDecision(
            HealthStatus.UNHEALTHY,
            "The SSL certificate is not valid and trusted.",
            True,
            False,
        )
    code_ok = facts.http_code is not None and rules.accepted_status_min <= facts.http_code <= rules.accepted_status_max
    hard_failure = not facts.dns_ok or not facts.connection_ok or not code_ok or not facts.content_ok

    if hard_failure and facts.consecutive_failures >= rules.failure_threshold:
        if not facts.dns_ok:
            reason = "The domain name could not be resolved."
        elif not facts.connection_ok:
            reason = "The HTTPS connection could not be completed."
        elif not code_ok:
            reason = f"HTTP {facts.http_code or 'response'} is outside the expected range."
        elif not facts.content_ok:
            reason = "The response did not match the configured content rule."
        else:
            reason = "The SSL certificate is not valid and trusted."
        return HealthDecision(HealthStatus.UNHEALTHY, reason, True, False)

    if hard_failure:
        return HealthDecision(
            HealthStatus.DEGRADED,
            f"Temporary failure {max(1, facts.consecutive_failures)} of {rules.failure_threshold}.",
            True,
            True,
        )
    if facts.latency_ms is not None and facts.latency_ms >= rules.critical_latency_ms:
        return HealthDecision(
            HealthStatus.UNHEALTHY,
            f"Response time is above the {rules.critical_latency_ms} ms critical threshold.",
            True,
            False,
        )
    if facts.latency_ms is not None and facts.latency_ms >= rules.warning_latency_ms:
        return HealthDecision(
            HealthStatus.DEGRADED,
            f"Response time is above the {rules.warning_latency_ms} ms warning threshold.",
            True,
            True,
        )
    if facts.ssl_status == "SSL EXPIRES SOON":
        return HealthDecision(HealthStatus.DEGRADED, "The SSL certificate expires soon.", True, True)
    return HealthDecision(HealthStatus.HEALTHY, "All configured checks passed.", True, True)
