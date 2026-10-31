RabbitMQ AMQP connection, virtual-host permissions, TLS or broker availability failures.

## Inspect

Confirm broker/client versions, target endpoint, protocol, virtual host, account and connection network. AMQP, management HTTP and Erlang distribution use different listeners. Do not infer AMQP health from the management UI alone.

When locally authorized, use `rabbitmq-diagnostics -q ping`, `rabbitmq-diagnostics -q check_running` and listener inspection with the installed tool's supported timeout. CLI cookie authentication is different from an application's username/password. Never print the Erlang cookie, passwords or credential URLs.

## Interpret

Separate refused/timeout, TLS, authentication and virtual-host permission errors. Check advertised application endpoint and container networking. Default-user restrictions are not a reason to expose a privileged account remotely.

## Change and verify

Propose a specific listener, certificate, virtual-host permission or application setting correction. Creating users, changing permissions and restarting are user-run changes. Verify a deliberately chosen application connection and its intended operation afterward. Publishing, consuming, acknowledging and purging affect broker or application state; do not run them as supposedly read-only diagnostics.
