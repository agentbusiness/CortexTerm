Inspect or change a named cloud VM, network, disk or managed service in the intended account.

## Inspect

Establish provider, identity, account/project, region and exact resource ID. Use the current cloud CLI's help and the service's documented describe/get operation. Select only required fields and bound pagination. A resource name may repeat across regions or accounts.

For a VM, inspect state, machine type, disk, network interfaces, relevant access rules and recent status events. For a failed service, inspect its own error and dependency health. Local CLI success does not prove a remote application is reachable.

## Propose

Create, resize, stop, attach, delete and access-rule changes are user-run operations. Explain the affected resource and any persistence, availability or billing effect. Do not change a default account or open a broad source range just to make a command succeed. Check dependencies before removing a resource.

## Verify

Read the remote operation result and the resulting resource state, then the intended application behavior. Some operations are asynchronous; an accepted request is not completion. Establish the existing outcome before retrying a timed-out create or delete. Keep a product-specific recovery path where replacement or downtime is possible.
