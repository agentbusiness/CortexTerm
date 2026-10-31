Back up, restore or migrate Neo4j with the correct edition and tool version.

## Inspect

Record server/tool version, edition, database state, size and recovery target. Check the installed `neo4j-admin` help. Online backup availability and command names depend on edition and release; a database dump commonly requires the database to be offline. Do not promise an online operation without checking.

## Prepare

Choose the documented backup/dump route for that deployment. Include authentication configuration, plugins and other required files separately as appropriate; database files alone are not the whole application. Protect backup output and verify free space. Backup, stopping a database and restoring are user-run changes.

## Restore and verify

Restore into an isolated compatible DBMS first. Do not use overwrite options or delete the existing store by default. Check migration/upgrade compatibility before starting a newer server on a copy. Validate database state, constraints, indexes, representative counts and graph queries. Confirm application access. Keep the original store and compatible runtime until recovery is demonstrated; a command exiting zero does not prove that a restored application works.
