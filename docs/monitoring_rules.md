# Monitoring rules

The status order is:

1. Maintenance
2. Unknown when no reliable result exists
3. Unhealthy for confirmed certificate failures, critical latency, or failures
   at the configured threshold
4. Degraded for warnings and temporary failures
5. Healthy when every required rule passes

The default accepted HTTP range is `200` through `399`.

The default warning response time is `1000 ms`. The critical response time is
`3000 ms`.

An SSL expiry warning is Degraded because the site remains usable. An expired,
not yet valid, untrusted, or mismatched certificate is Unhealthy when valid SSL
is required.

The first normal network or HTTP failure is Degraded. The default incident
threshold is three consecutive failures. A confirmed certificate security
failure becomes Unhealthy immediately.

Maintenance and Unknown are excluded from observed uptime. Healthy and
Degraded count as available. Unhealthy counts as unavailable.

The p95 value uses linear interpolation over sorted valid response times.
Checks without a response time are excluded from latency statistics.
