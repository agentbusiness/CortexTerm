Find system errors around a boot, restart, shutdown or sleep event.

## Inspect

Establish the target and time window, including time zone. On Linux, use `journalctl -b -p err -n 40 --no-pager`; `-b -1` selects the previous boot when retained. Kernel access may be restricted. Missing previous logs means retention is unknown, not that no error occurred.

On macOS, use a short `log show --last 10m --style compact --predicate '<specific predicate>'` query. For sleep and wake history, inspect a bounded section of `pmset -g log`. Crash reports can supply exception and process information; read the relevant report section, not every report.

## Interpret

Quote the decisive line and its time. Correlate nearby events without declaring causation from timing alone. A forced power-off may leave no final log. Time changes and multiple boots can make timestamps misleading.

Give the next specific diagnostic check. Do not clear journals, rotate logs or disable logging while investigating. Any repair remains a user-run proposal, followed by verification of the original symptom.
