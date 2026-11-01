# Protection collectors

This source is not a runtime validation. No build, privileged command or capture was run during implementation.

## Native endpoint producer

`event_sensor.c` uses Apple's supported Endpoint Security C API, notify events only. It never authorizes, blocks or opens observed files and never collects arguments, environment variables, file contents or network payloads. Its callback copies a bounded metadata record to a serial writer. A bounded queue and the Endpoint Security global sequence number report loss. A heartbeat reports producer liveness. The process uses PID, fork start time, executable and native pidversion; it does not attribute by PID alone. File observations are scoped to the requested user's home and user-originated system launch-item writes. CortexTerm's home (`~/.cortexterm`) is excluded to prevent a feedback loop.

Build/sign commands for integration into the existing release scripts (do not run as part of a source-only change):

```sh
xcrun clang -std=c11 -fblocks -O2 -Wall -Wextra -mmacosx-version-min=11.0 event_sensor.c -lEndpointSecurity -lbsm -o cortexterm-event-sensor
codesign --force --options runtime --timestamp --entitlements event-sensor.entitlements.plist --sign "$CORTEXTERM_SIGN_IDENTITY" cortexterm-event-sensor
```

Apple must grant the signing team's `com.apple.developer.endpoint-security.client` entitlement and the correct provisioning profile must accompany distribution. An entitlement plist alone does not grant access. The native producer needs root and Full Disk Access; it runs only as the installed sensor service. `cc-system` stays the normal user. Signing, notarization, provisioning, installation, permissions and real native captures remain deployment gates.

The release builder embeds `CortexTermEventSensor.app`, bundle ID `ai.cortexterm.event-sensor`, beside `cc-system`. Its signed installer asset lives at `CortexTermEventSensor.app/Contents/Resources/CortexTermEventSensor.pkg`. The installer places the provisioned helper at `/Library/Application Support/CortexTerm/Security/CortexTermEventSensor.app/Contents/MacOS/cortexterm-event-sensor`, root owned with no group/world writes, including every ancestor directory. A root:admin directory is accepted at mode 0755; a group-writable directory fails closed. Mutable plugin helpers are never elevated. Discovery also recognizes the exact enclosing `CortexTerm.app/Contents/Resources/security` asset location. The signing team comes from the signed `cc-system` executable or the optional compile-time `CORTEXTERM_ES_TEAM_ID`. `deep_install_command()` offers opening only the exact packaged installer with a trusted Developer ID Installer signature matching that team. Signature results are briefly cached by exact file metadata. Configuration never starts privileged work.

### The sensor service

The installer also installs `/Library/LaunchDaemons/ai.cortexterm.event-sensor.plist` and its postinstall script starts it (`launchctl bootstrap system`). It runs the helper as `--serve` at boot, kept alive by launchd. The helper waits on `/var/run/ai.cortexterm.event-sensor.sock` (root owned, mode 0666) and serves the one non-root user who connects: `getpeereid` gives the uid, the home comes from the user database and `~/.cortexterm` is excluded. Its stdout becomes the connection. When the connection ends the helper exits and launchd starts it again. A refused start (no entitlement, no Full Disk Access) is sent to the client as an `error` record before the helper ends.

While deep monitoring is on, a thread of `cc-system` connects by itself (no terminal, no sudo) after checking that the socket file and its peer are root; turning deep monitoring off ends it. Turning deep monitoring on without the service opens the signed installer; macOS asks for an administrator's approval once. Full Disk Access for `CortexTermEventSensor` is granted in System Settings; until it is, the sensor's status says so. There is no terminal capture mode.

The reader accepts only schema-1 native records, revalidates each field and replaces summaries with fixed statements. It hands each cleaned event to the collector in the same process through a bounded queue (4,096 events; more, and malformed or stale records, are counted as lost and shown in the sensor's status), and the collector appends what it takes to the graph stream `protection.events` (14 days) as their history. No file is written and raw producer output is never kept. The reader samples ordinary file changes and produces a bounded bulk-change observation after 50 distinct paths in 30 seconds; that signal alone is not ransomware proof.

Apple explicitly states in `eslogger(1)` that eslogger is not API and is not intended for applications. It is deliberately not used as the production producer here.

## Packet metadata

`tcpdump` runs as the current user, never sudo, in non-promiscuous mode on the macOS default-route interface or Linux `any`. macOS `pktap` is not used: creating it needs root even when BPF is readable. Missing capture permissions produce an unavailable sensor that names the missing BPF access. The filter selects ordinary IPv4/IPv6 TCP SYN packets only; the implementation stores parsed endpoint/port/time metadata and no raw packets. Packet buffers, line lengths, channels and aggregation tables are capped. IPv6 extension chains, UDP scans, traffic hidden by tunnels and probes discarded upstream are outside this collector's coverage. Multiport incoming attempts and non-web outbound address fan-out are distinct observations, not claims of access. Address/interface changes restart the collector and clear the previous network's counters. Collector exit and queue loss remain visible.

## External sensors

The operator may select at most four local Suricata EVE JSON or Zeek JSON conn logs. No network service is opened. Imported observations use an explicit `import:` provenance prefix and cannot acquire local process authority. Files must be absolute, regular, single-link, owned by the current user or root, not writable by group/others, and not symbolic links. Reads use file descriptors with no-follow/nonblocking flags, bounded bytes and line lengths. First attachment starts at EOF, rotation/truncation or a changed 64-byte cursor marker reports a continuity gap, and event timestamps are preserved. Stale logs are degraded, not a statement that the network is safe. Zeek failed-connection records can detect multiport probing within the selected sensor's visibility; Suricata alert records preserve numeric rule ID, endpoint addresses and severity without retaining arbitrary rule text.

Production verification must include benign and real packet sources, IPv4/IPv6, permissions denied, interface changes, long/partial input, log rotation, dropped records, signed native helper/FDA denial, service restarts, PID reuse, 8 GB hardware and both local model families. These checks require a later authorized build and real-app run; source inspection cannot substitute for them.

Recognized browser/store owners require matching signing identity/team and their own store path; these accesses are information-only context, never a trust exemption. Unexpected credential-store access remains a separate signal. Archive unlink events stay deletions, not archive creation. Native EOF emits a stopped record; a lost producer without clean EOF becomes stale.

Ordinary file-change bulk counting excludes the user Library and .cache directories to avoid treating routine app/browser cache churn as a user-file incident. Explicit credential, startup and archive observations remain visible there. These exclusions reduce coverage in those locations and are not malware trust exemptions.
