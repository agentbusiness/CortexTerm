MongoDB replica-set health, primary selection, replication lag or write-concern problems.

## Inspect

Identify the intended replica set and role privileges. Inspect a bounded selection from `rs.status()` or the supported monitoring interface: member name, health, state and replication timestamps. Do not print whole configurations with credentials. Check the observation time and network path between members.

## Interpret

Separate a missing primary, unreachable member, lagging replication and a client configured for the wrong replica set. Lag timestamps during no writes need workload context. Write concern describes acknowledgement requirements; changing it changes durability/availability tradeoffs. A successful read on a secondary does not prove current primary writes are visible.

## Change and verify

Reconfiguration, forced elections, member removal, initial synchronization and resync are user-run cluster operations. Check quorum, recovery copy and version compatibility first. Never erase a member's data directory to fix an unexplained connection error. After the agreed action, verify membership, primary state, replication progress and the original application's read/write behavior. Report missing monitoring permissions as incomplete evidence.
