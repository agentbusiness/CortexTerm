Inspect Kafka topics and partitions or propose a controlled topic configuration change.

## Inspect

Confirm cluster identity, release, exact topic and account. Use the installed `kafka-topics.sh --help`, then its supported `--bootstrap-server <endpoint> --describe --topic <name>` form with the protected client configuration. Inspect named-topic configuration with the matching config tool. Avoid an unbounded all-topics inventory when one topic is relevant.

## Interpret

Explain partition count, leaders, replica assignments and in-sync replicas. A missing topic may be a naming, authorization or wrong-cluster problem. A leader existing does not establish that the requested durability is available. Compare replication factor with actual brokers and fault domains.

## Change and verify

Topic creation, deletion, partition increases, retention and reassignment are user-run changes. Increasing partitions can alter keyed message placement and consumer behavior; it is not a routine reversible tuning switch. Do not turn on automatic topic creation or lower replication to hide a failure.

Re-read the named topic's state/configuration after the user acts. Verify the intended application's behavior. Topic deletion or expired retention needs independent recovery data; a reverse config change cannot restore removed messages.
