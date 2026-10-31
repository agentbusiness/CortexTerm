RabbitMQ queues grow, messages stay unacknowledged, consumers vanish or dead letters accumulate.

## Inspect

Confirm cluster, virtual host and exact queue. Use a bounded metadata check such as `rabbitmqctl -q -t 5 list_queues -p <vhost> name messages_ready messages_unacknowledged consumers`, if supported and authorized. A large virtual host may need the management API's pagination and selected fields. Do not fetch message bodies by default.

## Interpret

Ready messages await delivery; unacknowledged messages were delivered but not acknowledged. Compare consumer counts, channel errors, processing rate and downstream failures over time. Queue depth alone does not prove that more consumers will help. Check queue type, policies, TTLs and dead-letter routing for the named queue.

## Change and verify

Purging deletes messages. Requeueing, consuming, acknowledging, changing policies and scaling consumers affect processing and can repeat business actions. Present the exact scoped user-run change and its consequences. Do not use a message-get endpoint as harmless inspection without checking its acknowledgement behavior.

Observe delivery/acknowledgement progress and application outcomes after remediation. A queue reaching zero can mean message loss, not successful processing.
