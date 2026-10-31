# Protection collectors

This source is not a runtime validation. No build, privileged command or capture was run during implementation.

## Native endpoint producer

`event_sensor.c` uses Apple's supported Endpoint Security C API, notify events only. It never authorizes, blocks or opens observed files and never collects arguments, environment variables, file contents or network payloads. Its callback copies a bounded metadata record to a serial writer. A bounded queue and the Endpoint Security global sequence number report loss. A heartbeat reports producer liveness. The process uses PID, fork start time, executable and native pidversion; it does not attribute by PID alone. File observations are scoped to the requested user's home and user-originated system launch-item writes. The private capture directory is excluded to prevent a feedback loop.

Build/sign commands for integration into the existing release scripts (do not run as part of a source-only change):

```sh
xcrun clang -std=c11 -fblocks -O2 -Wall -Wextra -mmacosx-version-min=11.0 event_sensor.c -lEndpointSecurity -lbsm -o cortexterm-event-sensor
codesign --force --options runtime --timestamp --entitlements event-sensor.entitlements.plist --sign "$CORTEXTERM_SIGN_IDENTITY" cortexterm-event-sensor
```

Apple must grant the signing team's `com.apple.developer.endpoint-security.client` entitlement and the correct provisioning profile must accompany distribution. An entitlement plist alone does not grant access. The responsible terminal needs Full Disk Access and the native producer needs root. The generated command uses sudo only for that producer. The `cc-system --security-events` sink stays the normal user and refuses root. Signing, notarization, provisioning, installation, permissions and real native captures remain deployment gates.

The release builder embeds `CortexTermEventSensor.app`, bundle ID `ai.cortexterm.event-sensor`, beside `cc-system`. Its signed installer asset lives at `CortexTermEventSensor.app/Contents/Resources/CortexTermEventSensor.pkg`. The installer places the provisioned helper at `/Library/Application Support/CortexTerm/Security/CortexTermEventSensor.app/Contents/MacOS/cortexterm-event-sensor`, root owned with no group/world writes, including every ancestor directory. A root:admin directory is accepted at mode 0755; a group-writable directory fails closed. Mutable plugin helpers are never elevated. Discovery also recognizes the exact enclosing `CortexTerm.app/Contents/Resources/security` asset location. `deep_capture_command()` returns no command until the fixed installed helper, its root-owned path, valid non-ad-hoc code signature, expected bundle identifier, endpoint entitlement, embedded provisioning profile/app ID/expiry and expected signing team validate. The team comes from the signed `cc-system` executable or the optional compile-time `CORTEXTERM_ES_TEAM_ID`. `deep_install_command()` offers opening only the exact packaged installer with a trusted Developer ID Installer signature matching that team. Signature results are briefly cached by exact file metadata. It includes `--uid`, `--home` and `--exclude-path`; do not wrap the entire pipeline in sudo. The generated command creates the private plugin data directory before capture starts. Configuration never starts privileged work. The operator ends capture with Control-C; turning off deep monitoring stops ingestion, not an explicitly user-started terminal producer.

The sink accepts only schema-1 native records, revalidates each field and replaces summaries with fixed statements. It writes private mode-0600 JSONL, rotating at 16 MiB and retaining one prior segment. A file lock rejects concurrent captures. Raw producer output is never written. The sink samples ordinary file changes and produces a bounded bulk-change observation after 50 distinct paths in 30 seconds; that signal alone is not ransomware proof.

Apple explicitly states in `eslogger(1)` that eslogger is not API and is not intended for applications. It is deliberately not used as the production producer here.

## Packet metadata

`tcpdump` runs as the current user, never sudo, in non-promiscuous mode on macOS `pktap,all` or Linux `any`. Missing capture permissions produce an unavailable sensor. The filter selects ordinary IPv4/IPv6 TCP SYN packets only; the implementation stores parsed endpoint/port/time metadata and no raw packets. Packet buffers, line lengths, channels and aggregation tables are capped. IPv6 extension chains, UDP scans, traffic hidden by tunnels and probes discarded upstream are outside this collector's coverage. Multiport incoming attempts and non-web outbound address fan-out are distinct observations, not claims of access. Address/interface changes restart the collector and clear the previous network's counters. Collector exit and queue loss remain visible.

## External sensors

The operator may select at most four local Suricata EVE JSON or Zeek JSON conn logs. No network service is opened. Imported observations use an explicit `import:` provenance prefix and cannot acquire local process authority. Files must be absolute, regular, single-link, owned by the current user or root, not writable by group/others, and not symbolic links. Reads use file descriptors with no-follow/nonblocking flags, bounded bytes and line lengths. First attachment starts at EOF, rotation/truncation or a changed 64-byte cursor marker reports a continuity gap, and event timestamps are preserved. Stale logs are degraded, not a statement that the network is safe. Zeek failed-connection records can detect multiport probing within the selected sensor's visibility; Suricata alert records preserve numeric rule ID, endpoint addresses and severity without retaining arbitrary rule text.

Production verification must include benign and real packet sources, IPv4/IPv6, permissions denied, interface changes, long/partial input, log rotation, dropped records, signed native helper/FDA denial, Ctrl-C, PID reuse, 8 GB hardware and both local model families. These checks require a later authorized build and real-app run; source inspection cannot substitute for them.

Recognized browser/store owners require matching signing identity/team and their own store path; these accesses are information-only context, never a trust exemption. Unexpected credential-store access remains a separate signal. Archive unlink events stay deletions, not archive creation. Native EOF emits a stopped record; a lost producer without clean EOF becomes stale.

Ordinary file-change bulk counting excludes the user Library and .cache directories to avoid treating routine app/browser cache churn as a user-file incident. Explicit credential, startup and archive observations remain visible there. These exclusions reduce coverage in those locations and are not malware trust exemptions.
