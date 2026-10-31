Kafka consumer lag grows, a consumer group stalls, or offsets need investigation.

## Inspect

Confirm cluster, group, topic, client version and observation interval. Use the installed consumer-group tool's supported `--bootstrap-server <endpoint> --describe --group <group>` with protected client settings. Inspect the group's state and members when authorized. Limit output to relevant partitions; report if the tool times out.

## Interpret

Compare committed offset, log-end offset, partition assignment and progress over time. Lag alone does not identify the cause. Check missing consumers, repeated rebalances, processing errors, downstream slowness and broker health. A group's committed offset is not always the application's completed business work.

## Change and verify

Resetting offsets changes what will be replayed or skipped. Show a reviewed dry-run first using that release's tool. The user chooses execution after checking group state, scope and recovery consequences. Never use `--execute` as an inspection step.

Reading sample messages may change group membership or offsets; use an explicitly planned bounded user-run consumer with suitable commit settings. After remediation, observe sustained progress and application results; a single lag snapshot does not prove recovery.
