Set up or diagnose Prometheus, Grafana, Loki or OpenTelemetry data and alerts.

## Inspect

Identify the installed components, versions and data path. Inspect relevant configuration and bounded recent logs. For a scrape or export failure, establish source, receiver, endpoint, authentication and network context. Do not print telemetry credentials or raw private traces.

Distinguish absent data, stale data, query error and a genuinely zero value. Check timestamps, time zones, labels and retention. A dashboard loading does not prove its data source works. High-cardinality labels can create resource pressure; inspect actual series and storage before changing limits.

## Propose

Use a narrow config preview and the component's supported validator. Deployment, reload, scrape-target changes and alert routing are user-run actions. Preserve existing data and dashboards. Do not delete storage or disable an alert to hide an unhealthy component.

## Verify

Confirm a fresh known signal reaches the intended query and dashboard. For alerts, use an authorized bounded exercise and verify delivery and recovery behavior. A valid alert expression is not proof a notification reaches its recipient. Do not send test messages without explicit authorization.
