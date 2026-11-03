//! `system@1`: the machine itself, read without sudo. Resources (CPU, memory, GPU, power, disk,
//! network, thermal), processes (grouped by app, by Run or as a tree, with ports), process actions,
//! watchers that post the obvious (runaway CPU, memory climb, disk full, new open port) and the
//! workstation security sweep.
//!
//! The UI's right sidebar, the process view (what `top` / `htop` open) and the terminal flow's
//! questions ("who is on :5432?", "why is the fan loud?") all read these methods.

use serde::{Deserialize, Serialize};

/// App-local protection configuration. It grants no operating-system privileges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    pub packet_watch: bool,
    pub deep_watch: bool,
    pub investigate: bool,
    pub imports: Vec<ProtectionImport>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self { packet_watch: true, deep_watch: false, investigate: true, imports: Vec::new() }
    }
}

/// Explicitly selected local sensor file: `suricata` (EVE JSON), `zeek` (JSON conn log).
/// No network listener is opened and the file never constitutes trusted instructions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProtectionImport {
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProtectionSensor {
    pub id: String,
    pub label: String,
    /// starting | active | degraded | unavailable | disabled
    pub state: String,
    pub detail: String,
    pub last_at: u64,
    pub dropped: u64,
}

/// One observed fact. `subject` is an exact process incarnation, remote address or file identity;
/// temporal proximity alone is never a causal link. No secret contents or raw packet payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct SecurityObservation {
    pub id: String,
    pub at: u64,
    pub source: String,
    pub kind: String,
    pub severity: String,
    pub summary: String,
    pub rule: String,
    pub subject: String,
    pub pid: Option<u32>,
    /// Unix seconds, matching `Proc.started`; never infer identity from PID alone.
    pub process_started: Option<u64>,
    /// Native precision when available, Unix microseconds. Versions distinguish exec images.
    pub process_started_us: Option<u64>,
    pub process_version: Option<i32>,
    pub parent_pid: Option<u32>,
    pub executable: Option<String>,
    pub path: Option<String>,
    pub remote: Option<String>,
    pub port: Option<u16>,
    pub count: u64,
}

/// Model text must cite a nonempty subset of an incident's observation IDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SecurityClaim {
    pub text: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SecurityInvestigation {
    /// queued | running | complete | unavailable | failed
    pub state: String,
    pub summary: Vec<SecurityClaim>,
    pub alternatives: Vec<SecurityClaim>,
    /// Facts gathered by the bounded read-only checks, with their own observation IDs.
    #[serde(default)]
    pub observations: Vec<SecurityObservation>,
    pub unknowns: Vec<String>,
    pub next_steps: Vec<String>,
    pub checked_at: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SecurityIncident {
    pub id: String,
    pub key: String,
    pub first_at: u64,
    pub last_at: u64,
    pub title: String,
    pub severity: String,
    /// open | dismissed
    pub state: String,
    pub observations: Vec<SecurityObservation>,
    pub investigation: Option<SecurityInvestigation>,
    pub revision: u64,
    #[serde(default)]
    pub omitted_observations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SecurityException {
    pub id: String,
    pub incident_key: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub reason: String,
    /// Exact observation fingerprints present when allowed; new behaviour is not covered.
    #[serde(default)]
    pub observation_keys: Vec<String>,
    #[serde(default)]
    pub max_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProtectionStatus {
    pub at: u64,
    pub config: ProtectionConfig,
    pub sensors: Vec<ProtectionSensor>,
    pub incidents: Vec<SecurityIncident>,
    pub exceptions: Vec<SecurityException>,
    /// Opens the verified signed installer; installation still requires the user's OS approval.
    pub deep_install_command: Option<String>,
    /// The sensor service is installed: it starts at boot and CortexTerm reads it by itself.
    #[serde(default)]
    pub deep_service: bool,
    pub packet_capture_help: String,
    pub visibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ProtectionAction {
    pub id: String,
    /// dismiss | reopen | allow_hour | revoke_exception | investigate | stop_process
    pub action: String,
    #[serde(default)]
    pub confirm: bool,
    /// Binds a destructive confirmation to exactly the incident the user reviewed.
    #[serde(default)]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub expected_pid: Option<u32>,
    #[serde(default)]
    pub expected_process_started: Option<u64>,
    #[serde(default)]
    pub expected_process_started_us: Option<u64>,
    #[serde(default)]
    pub expected_process_version: Option<i32>,
    #[serde(default)]
    pub expected_executable: Option<String>,
}

pub mod methods {
    /// Local protection: sensor health, configuration, incidents and scoped exceptions.
    pub const PROTECTION_STATUS: &str = "system.protection.status";
    /// `ProtectionConfig` -> `ProtectionStatus`. UI only; never starts a privileged command.
    pub const PROTECTION_CONFIGURE: &str = "system.protection.configure";
    /// `{id}` -> `SecurityIncident` (the bounded, evidence-bearing incident timeline).
    pub const INCIDENT_GET: &str = "system.incident.get";
    /// `ProtectionAction` -> `ProtectionStatus`. Mutations require a local user action.
    pub const INCIDENT_ACT: &str = "system.incident.act";
    /// `{}` -> [`super::Metrics`]: the latest sample (sampled in the background).
    pub const METRICS: &str = "system.metrics";
    /// [`super::ProcessesParams`] -> [`super::ProcessList`].
    pub const PROCESSES: &str = "system.processes";
    /// `{pid}` -> [`super::ProcessDetail`]: one process with its ports, open files count, parent
    /// chain, executable, signature and quarantine flag; its last 20 minutes (one reading a scan),
    /// its threads, its open files and sockets, its children, and its monitor log when one runs.
    pub const PROCESS: &str = "system.process";
    /// [`super::MonitorParams`] -> [`super::MonitorReport`]: start or stop watching one process's
    /// files and network (its open files and sockets, read every 2 s, what came and went logged).
    pub const MONITOR: &str = "system.monitor";
    /// [`super::SignalParams`] -> `{ok, detail}`: send a signal to one of the user's processes.
    pub const SIGNAL: &str = "system.signal";
    /// [`super::ChangesParams`] -> [`super::MemoryChanges`]: how memory changed over the last
    /// minutes (kept for 30), in total and per app, biggest change first.
    pub const MEMORY_CHANGES: &str = "system.memory.changes";
    /// `{}` -> [`super::PortList`]: every listening TCP port with its process.
    pub const PORTS: &str = "system.ports";
    /// `{}` -> [`super::AlertList`]: current and recent alerts.
    pub const ALERTS: &str = "system.alerts";
    /// `{id, action}` -> `{ok}`: `dismiss` | `snooze` (1 h) | `ignore_kind` for an alert.
    pub const ALERT_ACT: &str = "system.alert.act";
    /// `{}` -> [`super::SweepReport`]: the last security sweep (`at` 0: none yet; reading never runs one).
    pub const SWEEP: &str = "system.sweep";
    /// `{}` -> [`super::SweepReport`]: run the sweep now.
    pub const SWEEP_RUN: &str = "system.sweep.run";
    /// `{}` -> [`super::SweepReport`]: close every open alert and incident, then run the sweep:
    /// what is still true comes back. Decisions are kept.
    pub const SWEEP_CLEAN: &str = "system.sweep.clean";
    /// [`super::DecideParams`] -> [`super::SweepReport`]: decide about a group of findings, or
    /// take the decision back. Kept in the graph across sweeps and restarts.
    pub const FINDING_DECIDE: &str = "system.finding.decide";
    /// [`super::VerifyParams`] -> [`super::Verified`]: after a fix ran, check the finding's area
    /// again; gone closes it, still there records the command as tried.
    pub const FINDING_VERIFY: &str = "system.finding.verify";
    /// [`super::HistoryParams`] -> [`super::History`]: what came up over the last days, bucketed.
    pub const SECURITY_HISTORY: &str = "system.security.history";
    /// [`super::CheckParams`] -> [`super::SweepReport`]: run the sweep's checks for some areas
    /// only (`settings`, `updates`, `apps`, `packages`, `malware`, `persistence`, `privacy`,
    /// `intrusion`, `network`, `agents`, `ssh`, `secrets`, or `all`). It never replaces the stored
    /// sweep; ignored findings come back marked. An area that misses `within_s` contributes the
    /// last sweep's findings for it, and `checked` says so.
    pub const CHECK: &str = "system.check";
    /// [`super::CveParams`] -> [`super::CveReport`]: one advisory (CVE, GHSA or another OSV id)
    /// from NVD, OSV, CISA KEV, EPSS and Apple's release notes (SOFA), checked against what is
    /// installed on this Mac. The advisory data is cached for a day.
    pub const CVE: &str = "system.cve";
    /// [`super::AskParams`] -> [`super::AskResult`]: the Mac security skills' `macsec` words
    /// (`check <area>…`, `cve <id>`, `areas`) answered as text for the model to read. The terminal's
    /// chat flow hands the model's `macsec` command here instead of running it in a shell.
    pub const ASK: &str = "system.ask";
    /// [`super::KeysSetParams`] -> [`super::KeysStatus`]: save a lookup key (`virustotal`,
    /// `abusech`) in the Keychain; an empty value removes it. For the UI: not a shell command.
    pub const KEYS_SET: &str = "system.keys.set";
    /// `{}` -> [`super::KeysStatus`]: which lookup keys are set. Never their values.
    pub const KEYS_STATUS: &str = "system.keys.status";
    /// [`super::TimelineParams`] -> [`super::Timeline`]: what happened around a process or a file,
    /// in time order (process starts, persistence changes, notable system log lines, downloads,
    /// the monitor log). Code gathers the rows; the model marks and explains them.
    pub const TIMELINE: &str = "system.timeline";
    /// `{}` -> [`super::SshHosts`]: hosts from `~/.ssh/config` (with Include), known_hosts and
    /// history, each with its effective settings (`ssh -G`) and reachability.
    pub const SSH_HOSTS: &str = "system.ssh.hosts";
    /// `{}` -> [`super::SshKeys`]: the keys in `~/.ssh` and in the running agent, with hygiene notes.
    pub const SSH_KEYS: &str = "system.ssh.keys";
    /// `{}` -> [`crate::contracts::service::ShareList`]: the services this plugin shares with the
    /// other apps on this machine and the mesh (`system.trace`, `system.schedule`).
    pub const SHARES: &str = "system.shares";

    // The schedule service (`system.schedule`): commands run at set times, each run traced.
    /// `{}` -> [`super::ScheduleList`]: the scheduled jobs and their last results.
    pub const SCHEDULE_LIST: &str = "system.schedule.list";
    /// `{id}` -> [`super::Schedule`].
    pub const SCHEDULE_GET: &str = "system.schedule.get";
    /// [`super::Schedule`] without `id` -> [`super::Schedule`]: a new scheduled job.
    pub const SCHEDULE_CREATE: &str = "system.schedule.create";
    /// [`super::Schedule`] -> [`super::Schedule`]: change one (its `id` names it).
    pub const SCHEDULE_EDIT: &str = "system.schedule.edit";
    /// `{id}` -> `{ok}`.
    pub const SCHEDULE_DELETE: &str = "system.schedule.delete";
    /// `{id}` -> [`super::ScheduleRun`]: run it now and wait for the result (traced).
    pub const SCHEDULE_RUN: &str = "system.schedule.run";
    /// [`super::ScheduleRunsParams`] -> `memory::TraceList`: the runs kept (a week), newest first:
    /// each run is a trace with its whole output.
    pub const SCHEDULE_RUNS_LIST: &str = "system.schedule.runs.list";
    /// [`super::TraceReadParams`] -> as [`TRACE_READ`]: one run, in the size asked for.
    pub const SCHEDULE_RUNS_READ: &str = "system.schedule.runs.read";

    // The trace service (`system.trace`): a week of what a process tree did, kept in IronGraph
    // through `memory@1` (its `memory.trace.*` methods and types). A trace only observes.
    /// [`super::TraceStartParams`] -> `memory::TraceInfo`: start recording a process and its
    /// children. Every Run a terminal starts is traced without asking (once it is seen running).
    pub const TRACE_RUN: &str = "system.trace.run";
    /// [`super::TraceStopParams`] -> `memory::TraceInfo`: stop recording.
    pub const TRACE_STOP: &str = "system.trace.stop";
    /// `memory::TraceListParams` -> `memory::TraceList`: the traces kept, newest first.
    pub const TRACE_LIST: &str = "system.trace.list";
    /// [`super::TraceReadParams`] -> by `size`: `line` `{line}`; `summary` `memory::TraceSummary`
    /// (without its series); `series` `{from, to, series}`; `records` `memory::TraceWindow`; with
    /// `at`, `service::Moment`.
    pub const TRACE_READ: &str = "system.trace.read";
    /// `{id}` -> `memory::TraceGraph`.
    pub const TRACE_GRAPH_GET: &str = "system.trace.graph.get";
    /// `{id}` -> `{}`: stop it if it records, and delete it.
    pub const TRACE_DELETE: &str = "system.trace.delete";
}

pub mod topics {
    /// [`super::Metrics`], about every 2 s while anyone is subscribed.
    pub const SAMPLE: &str = "system.sample";
    /// [`super::Alert`]: a watcher fired.
    pub const ALERT: &str = "system.alert";
    /// `service::ScheduleDone`: a scheduled job finished.
    pub const SCHEDULE_DONE: &str = "system.schedule.done";
}

/// One sample of the whole machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Metrics {
    /// Unix milliseconds.
    pub at: u64,
    /// e.g. "Apple M2", "MacBookAir10,1".
    #[serde(default)]
    pub machine: String,
    pub memory_total: u64,
    /// 0..100, all cores.
    pub cpu: f32,
    /// Per-core 0..100; performance cores first when known.
    #[serde(default)]
    pub cores: Vec<f32>,
    /// Performance / efficiency core counts (0 when unknown).
    #[serde(default)]
    pub p_cores: u32,
    #[serde(default)]
    pub e_cores: u32,
    pub memory_used: u64,
    #[serde(default)]
    pub memory_compressed: u64,
    #[serde(default)]
    pub swap_used: u64,
    /// normal | warn | critical
    pub pressure: String,
    /// How much of the GPU's capacity is in use (busy time scaled by its clock), 0..100 when known.
    #[serde(default)]
    pub gpu: Option<f32>,
    /// How much of the time the GPU is busy at any clock, 0..100 (a GPU idling at a low clock
    /// still counts as busy here, so this runs near 100 on a desktop with a few windows).
    #[serde(default)]
    pub gpu_active: Option<f32>,
    /// Watts when known.
    #[serde(default)]
    pub cpu_power: Option<f32>,
    #[serde(default)]
    pub gpu_power: Option<f32>,
    #[serde(default)]
    pub ane_power: Option<f32>,
    /// Average CPU and GPU die temperature in °C when known.
    #[serde(default)]
    pub cpu_temp: Option<f32>,
    #[serde(default)]
    pub gpu_temp: Option<f32>,
    /// The fastest fan in rpm; `None` on a Mac without fans.
    #[serde(default)]
    pub fan_rpm: Option<u32>,
    /// nominal | fair | serious | critical
    #[serde(default)]
    pub thermal: String,
    pub disk_total: u64,
    pub disk_free: u64,
    /// Bytes per second since the previous sample.
    #[serde(default)]
    pub disk_read: u64,
    #[serde(default)]
    pub disk_write: u64,
    #[serde(default)]
    pub net_rx: u64,
    #[serde(default)]
    pub net_tx: u64,
    #[serde(default)]
    pub battery: Option<Battery>,
    #[serde(default)]
    pub load: [f32; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Battery {
    pub percent: f32,
    pub charging: bool,
    #[serde(default)]
    pub watts: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessesParams {
    /// flat | app | tree
    #[serde(default)]
    pub group: String,
    /// cpu | memory | name
    #[serde(default)]
    pub sort: String,
    /// Case-insensitive match on name, command or port (`:5432`).
    #[serde(default)]
    pub filter: String,
    /// 0 = 200.
    #[serde(default)]
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// The command line, shortened.
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub user: String,
    pub cpu: f32,
    /// Bytes (the footprint Activity Monitor shows when available).
    pub memory: u64,
    #[serde(default)]
    pub disk_write: u64,
    /// Listening TCP ports.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// GPU use 0..100 since the previous sample (Metal clients), when known.
    #[serde(default)]
    pub gpu: Option<f32>,
    /// The app bundle or group name (`Docker Desktop`, `Safari`), when grouped by app.
    #[serde(default)]
    pub app: String,
    /// Unix seconds.
    #[serde(default)]
    pub started: u64,
    /// Process group id (a Run's processes share it).
    #[serde(default)]
    pub pgid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessGroup {
    pub name: String,
    pub cpu: f32,
    pub memory: u64,
    #[serde(default)]
    pub gpu: Option<f32>,
    #[serde(default)]
    pub disk_write: u64,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub processes: Vec<Proc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessList {
    pub at: u64,
    /// Flat and tree: one group named "" holding every process (tree: ordered depth first, with
    /// `ppid` giving the parent). App: one group per app.
    pub groups: Vec<ProcessGroup>,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessDetail {
    pub process: Proc,
    #[serde(default)]
    pub executable: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub open_files: u32,
    #[serde(default)]
    pub threads: u32,
    /// Parent chain, nearest first: `[(pid, name)]`.
    #[serde(default)]
    pub parents: Vec<(u32, String)>,
    /// signed | adhoc | unsigned | unknown
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub team_id: String,
    #[serde(default)]
    pub quarantined: bool,
    /// launchd restarts it when it ends.
    #[serde(default)]
    pub launchd_managed: bool,
    /// running | sleeping | stopped | zombie | "" (unknown)
    #[serde(default)]
    pub state: String,
    /// CPU time used since it started (user + system), ms.
    #[serde(default)]
    pub cpu_time_ms: u64,
    /// Bytes read from and written to disk since it started.
    #[serde(default)]
    pub disk_read_total: u64,
    #[serde(default)]
    pub disk_written_total: u64,
    /// The most memory it has held at once, when known.
    #[serde(default)]
    pub peak_memory: u64,
    /// One reading a scan (4 s) for the last 20 minutes, oldest first.
    #[serde(default)]
    pub history: Vec<ProcSample>,
    /// Busiest first; empty when this user may not read them.
    #[serde(default)]
    pub thread_list: Vec<ThreadSample>,
    /// Open files, sockets and pipes (`lsof`); empty when this user may not read them.
    #[serde(default)]
    pub files: Vec<OpenFile>,
    #[serde(default)]
    pub children: Vec<Proc>,
    /// The monitor log, while monitor mode is on for this process (or until its report is dropped).
    #[serde(default)]
    pub monitor: Option<MonitorReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcSample {
    /// Unix milliseconds.
    pub at: u64,
    pub cpu: f32,
    pub memory: u64,
    #[serde(default)]
    pub gpu: Option<f32>,
    #[serde(default)]
    pub disk_write: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ThreadSample {
    pub id: u64,
    #[serde(default)]
    pub name: String,
    /// running | waiting | stopped | uninterruptible | halted
    #[serde(default)]
    pub state: String,
    /// Share of one core, 0..100.
    pub cpu: f32,
    #[serde(default)]
    pub user_ms: u64,
    #[serde(default)]
    pub system_ms: u64,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OpenFile {
    /// `3`, `cwd`, `txt` (the program and its libraries), `mem`.
    pub fd: String,
    /// file | dir | tcp | udp | unix | pipe | device | other
    pub kind: String,
    /// A path, `local->remote` for a connection, or what lsof names it.
    pub name: String,
    /// r | w | u (both) | "" for a socket or mapping.
    #[serde(default)]
    pub mode: String,
    /// TCP state (`ESTABLISHED`, `LISTEN`), for a TCP socket.
    #[serde(default)]
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MonitorParams {
    pub pid: u32,
    /// true starts (or keeps) monitoring, false stops it; the log is kept until the next start.
    pub on: bool,
    /// Also watch its children (each Run's helpers, a server's workers).
    #[serde(default)]
    pub children: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MonitorEvent {
    /// Unix milliseconds the change was seen (within 2 s of when it happened).
    pub at: u64,
    pub pid: u32,
    /// open | close
    pub change: String,
    pub file: OpenFile,
}

/// One remote host the process talked to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MonitorHost {
    /// `140.82.112.3:443` (numeric; lsof is run with -n).
    pub address: String,
    /// tcp | udp
    pub kind: String,
    pub connections: u32,
    pub first: u64,
    pub last: u64,
}

/// Files opened under one folder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MonitorFolder {
    pub folder: String,
    /// Distinct files seen open.
    pub files: u32,
    /// Opened for writing at least once.
    pub written: bool,
    pub sample: Vec<String>,
}

/// What monitor mode saw, condensed (what the model is shown when asked to review it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MonitorReport {
    pub pid: u32,
    pub on: bool,
    pub children: bool,
    pub started: u64,
    #[serde(default)]
    pub stopped: Option<u64>,
    /// Polls made, and how many could not read the process (it ended, or another user owns it).
    pub polls: u32,
    pub failed: u32,
    /// The most recent changes, newest last (the last 500).
    pub events: Vec<MonitorEvent>,
    pub total_events: u32,
    pub hosts: Vec<MonitorHost>,
    pub folders: Vec<MonitorFolder>,
    pub listening: Vec<String>,
    /// What the rules noticed: secrets read, raw IPs on odd ports, writes outside the home or a
    /// temp folder. Plain sentences.
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalParams {
    pub pid: u32,
    /// TERM | KILL | INT | HUP | STOP | CONT
    pub signal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Port {
    pub port: u16,
    /// 127.0.0.1 | 0.0.0.0 | :: ...
    pub address: String,
    pub pid: u32,
    pub process: String,
    /// Listening on every interface (reachable from the network).
    pub public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PortList {
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Alert {
    pub id: String,
    /// cpu | memory | disk | port | persistence | unsigned | run
    pub kind: String,
    /// info | warn | high
    pub severity: String,
    /// One plain sentence.
    pub text: String,
    /// Unix milliseconds.
    pub at: u64,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub path: Option<String>,
    /// Suggested actions, e.g. `["kill", "show"]`.
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub dismissed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AlertList {
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ChangesParams {
    /// How far back, 1..30; 0 means all that is kept.
    #[serde(default)]
    pub minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MemoryChanges {
    /// Unix milliseconds of the oldest sample compared; 0 when there is no history yet.
    pub since: u64,
    pub used_then: u64,
    pub used_now: u64,
    pub swap_then: u64,
    pub swap_now: u64,
    /// The most memory used in the window, and when.
    pub peak: u64,
    pub peak_at: u64,
    /// Per app (helpers summed, as in the app grouping), the biggest changes first. An app that
    /// quit has `now` 0; one that started has `then` 0.
    pub apps: Vec<AppChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AppChange {
    pub app: String,
    pub then: u64,
    pub now: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Finding {
    /// high | medium | low | info
    pub severity: String,
    /// vuln | outdated | secret | ssh | persistence
    pub kind: String,
    /// One plain sentence.
    pub text: String,
    /// What fixes it, as a shell command when there is one (`brew upgrade openssl@3`). It is only
    /// ever offered, never run by the sweep.
    #[serde(default)]
    pub fix: Option<String>,
    /// Where the finding came from (`brew vulns`, `osv`, `zsh history`).
    #[serde(default)]
    pub source: String,
    /// Stable identity across sweeps (`kind:text`); what an ignore is remembered by.
    #[serde(default)]
    pub key: String,
    /// A decision covers it: listed apart, never alerted or counted.
    #[serde(default)]
    pub ignored: bool,
    /// What it is about, the same for every finding on one thing (`openssl@3`, an app's bundle
    /// path): findings are grouped and decided by it.
    #[serde(default)]
    pub group: String,
    /// The verdict of the decision covering it (see [`Decision`]); empty when open.
    #[serde(default)]
    pub decision: String,
    /// A command that ran to fix it and did not: a fresh check still found it.
    #[serde(default)]
    pub tried: Option<String>,
    /// The model's second look found it worse than code rated it (`password or keychain theft` …):
    /// it is raised one level. The model can only raise, never lower or close a finding.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raised: String,
    /// The graph node it is about, as (label, key): the plugin's own record, never sent.
    #[serde(skip)]
    pub about: Option<(String, String)>,
}

/// The person's decision about a group of findings. It hides them from the open list; the checks
/// keep running, and a finding worse than `severity` (or, with `keys`, any other finding) shows again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Decision {
    /// expected | false_alarm | accepted | vendor
    pub verdict: String,
    pub group: String,
    /// Only these findings (their keys); empty: the whole group.
    #[serde(default)]
    pub keys: Vec<String>,
    /// The worst severity it covers.
    pub severity: String,
    /// Unix milliseconds.
    pub at: u64,
    /// Unix milliseconds it ends; 0: no end.
    #[serde(default)]
    pub until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DecideParams {
    pub group: String,
    /// A [`Decision`] verdict; `fixed` checks again and closes what is gone; empty takes the
    /// group's decision back.
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub keys: Vec<String>,
    /// How long it holds; 0: no end.
    #[serde(default)]
    pub days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct VerifyParams {
    pub key: String,
    /// The command that ran to fix it.
    #[serde(default)]
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Verified {
    /// A fresh check of the finding's area no longer finds it.
    pub gone: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HistoryParams {
    /// 1, 7 or 30.
    #[serde(default)]
    pub days: u32,
}

/// New findings, incident facts and alerts over time, for the chart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct History {
    pub since: u64,
    pub bucket_ms: u64,
    /// Per bucket, oldest first: how many high, medium, low and info.
    pub series: Vec<[u32; 4]>,
    /// Per group (a finding's group, an incident or alert id): the buckets it had any in.
    pub hits: std::collections::BTreeMap<String, Vec<u32>>,
    /// What changed on the computer meanwhile (`macOS 26.1`, `3 apps updated`), oldest first.
    #[serde(default)]
    pub markers: Vec<Marker>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Marker {
    pub at: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimelineParams {
    /// The process (and its children) to centre on.
    #[serde(default)]
    pub pid: Option<u32>,
    /// The file to centre on (rows that name it or its file name).
    #[serde(default)]
    pub path: Option<String>,
    /// Unix milliseconds to start from; 0 means the last 24 hours.
    #[serde(default)]
    pub since_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TimelineRow {
    /// Unix milliseconds.
    pub at: u64,
    /// process | file | persistence | download | log | monitor
    pub source: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Timeline {
    /// Oldest first, at most 400.
    #[serde(default)]
    pub rows: Vec<TimelineRow>,
    /// Facts without a time (where a file came from, its hash, monitor flags).
    #[serde(default)]
    pub notes: Vec<String>,
    /// Sources that could not be read, with why.
    #[serde(default)]
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SweepReport {
    /// Unix milliseconds; 0 when it never ran.
    pub at: u64,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    /// What was checked, in words (`brew vulns`, `brew outdated`, `ssh keys`, ...).
    pub checked: Vec<String>,
    /// Checks that could not run, with why (`brew is not installed`).
    #[serde(default)]
    pub skipped: Vec<String>,
    /// The person's decisions in force.
    #[serde(default)]
    pub decisions: Vec<Decision>,
    /// The latest checks after a fix ran, newest first.
    #[serde(default)]
    pub fixes: Vec<FixCheck>,
}

/// A finding checked again after a command ran to fix it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FixCheck {
    pub at: u64,
    pub group: String,
    pub text: String,
    /// Empty when the person only asked for a fresh check.
    pub command: String,
    pub gone: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CheckParams {
    /// Area names or aliases, any case (`settings`, `firewall`, `updates`, `all`, ...).
    pub areas: Vec<String>,
    /// Overall deadline in seconds; none when absent.
    #[serde(default)]
    pub within_s: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct KeysSetParams {
    /// `virustotal` | `abusech`.
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// Which lookup keys the hash reputation check has (saved, or `ABUSE_CH_KEY` in the environment).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct KeysStatus {
    #[serde(default)]
    pub virustotal: bool,
    #[serde(default)]
    pub abusech: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveParams {
    /// `CVE-2024-3094`, `GHSA-qwgh-2vcv-g2f7`, `RUSTSEC-2024-0001`, `PYSEC-…`, `MAL-…`, `GO-…`.
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AskParams {
    /// The words after `macsec` (`["check", "settings"]`).
    pub args: Vec<String>,
    /// The knowledge notes (Markdown) whose entries for the findings are added to a check's text.
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AskResult {
    pub text: String,
    /// 0 when it answered, 2 when the words were wrong, 1 when the check failed.
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveReport {
    /// The id as asked, normalised.
    pub id: String,
    /// The same advisory under other ids (CVE, GHSA, ...).
    #[serde(default)]
    pub aliases: Vec<String>,
    /// One line.
    #[serde(default)]
    pub title: String,
    /// At most 600 characters.
    #[serde(default)]
    pub summary: String,
    /// `YYYY-MM-DD`, empty when unknown.
    #[serde(default)]
    pub published: String,
    #[serde(default)]
    pub modified: String,
    #[serde(default)]
    pub cvss: Option<Cvss>,
    /// `CWE-79`, ...
    #[serde(default)]
    pub cwe: Vec<String>,
    /// On CISA's list of vulnerabilities exploited in the wild.
    #[serde(default)]
    pub kev: Option<Kev>,
    #[serde(default)]
    pub epss: Option<Epss>,
    /// At most 8; vendor advisories and patches first.
    #[serde(default)]
    pub references: Vec<CveReference>,
    /// What the advisory says it covers, at most 20.
    #[serde(default)]
    pub affects: Vec<CveAffects>,
    /// What on this Mac it was compared with.
    #[serde(default)]
    pub matches: Vec<CveMatch>,
    /// affected | fixed | not-affected | unknown | not-found
    pub verdict: String,
    /// One plain sentence for a person.
    pub verdict_text: String,
    /// What was looked up and compared, in words.
    #[serde(default)]
    pub checked: Vec<String>,
    /// What could not be, with why.
    #[serde(default)]
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Cvss {
    /// `4.0`, `3.1`, `3.0` or `2.0`.
    pub version: String,
    /// 0.0..10.0.
    pub score: f64,
    /// CRITICAL | HIGH | MEDIUM | LOW | NONE
    pub severity: String,
    #[serde(default)]
    pub vector: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Kev {
    /// `YYYY-MM-DD` CISA added it; empty when unknown.
    #[serde(default)]
    pub added: String,
    /// `YYYY-MM-DD` US federal agencies must fix it by.
    #[serde(default)]
    pub due: String,
    /// Known to be used in ransomware campaigns.
    #[serde(default)]
    pub ransomware: bool,
    /// CISA's required action.
    #[serde(default)]
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Epss {
    /// Probability of exploitation in the next 30 days, 0..1.
    pub score: f64,
    /// 0..1.
    pub percentile: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveReference {
    pub url: String,
    /// `Vendor Advisory`, `Patch`, `ADVISORY`, `FIX`, ...
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveAffects {
    /// nvd | osv | apple
    pub source: String,
    /// `google chrome`, `crates.io block-buffer`, `macOS 26`.
    pub what: String,
    /// `< 141.0.7390.65`, `>= 0.10.0, < 0.10.3`, `fixed in 26.1`.
    #[serde(default)]
    pub versions: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CveMatch {
    /// What on this Mac (`Google Chrome`, `block-buffer`, `macOS`).
    pub what: String,
    /// Its installed version, empty when unknown.
    #[serde(default)]
    pub version: String,
    /// Where it is (`/Applications`, `Homebrew`, `~/DEV/app (Cargo.lock)`).
    #[serde(default)]
    pub place: String,
    /// affected | fixed | not-affected | unknown
    pub verdict: String,
    /// One plain clause.
    pub why: String,
    /// What fixes it, as a command or a step; only ever offered.
    #[serde(default)]
    pub fix: Option<String>,
    /// The graph node it was compared with, as (label, key), and the first version that fixes it:
    /// the plugin's own record, never sent.
    #[serde(skip)]
    pub about: Option<(String, String)>,
    #[serde(skip)]
    pub fixed_in: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SshHost {
    /// The alias you type (`prod-1`).
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    /// IdentityFile(s) in effect.
    #[serde(default)]
    pub identity: Vec<String>,
    #[serde(default)]
    pub proxy_jump: Option<String>,
    /// config | known_hosts | history | tailscale
    pub source: String,
    /// The config file and line it is defined at, when it comes from a config.
    #[serde(default)]
    pub defined_at: Option<String>,
    /// Unix milliseconds of the last `ssh` to it seen in history (0: never).
    #[serde(default)]
    pub last_used: u64,
    /// up | down | unknown (a TCP connect to its port, 2 s, refreshed at most every minute).
    #[serde(default)]
    pub reachable: String,
    /// mosh is installed here (offered per host).
    #[serde(default)]
    pub mosh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SshHosts {
    pub hosts: Vec<SshHost>,
    /// The agent in use: `1password` | `secretive` | `macos` | `other` | `none`, and its socket.
    pub agent: String,
    #[serde(default)]
    pub agent_socket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SshKey {
    /// File path, or `agent:<comment>` for a key only the agent holds.
    pub path: String,
    /// ed25519 | ecdsa | rsa | dsa | ed25519-sk | ecdsa-sk
    pub kind: String,
    #[serde(default)]
    pub bits: u32,
    pub fingerprint: String,
    #[serde(default)]
    pub comment: String,
    /// The private key needs a passphrase (unknown for agent-only keys: `None`).
    #[serde(default)]
    pub passphrase: Option<bool>,
    /// Loaded in the running agent.
    #[serde(default)]
    pub in_agent: bool,
    /// Hosts whose config names it.
    #[serde(default)]
    pub used_by: Vec<String>,
    /// good | weak | bad, and why in short phrases.
    pub health: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SshKeys {
    pub keys: Vec<SshKey>,
}

/// A job that runs on a schedule while the app runs (missed runs catch up once at start).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Schedule {
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// command (a shell command, run non-interactively in `cwd`) | sweep (the security sweep)
    pub kind: String,
    /// The command for kind `command`.
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub cwd: String,
    /// `daily HH:MM` | `hourly` | `every N min` | `weekly <mon..sun> HH:MM`
    pub when: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Alert when the output contains this text (case-insensitive), besides on failure.
    #[serde(default)]
    pub alert_on: String,
    /// Unix milliseconds.
    #[serde(default)]
    pub next: u64,
    #[serde(default)]
    pub last: Option<ScheduleRun>,
    /// The app that created it through the mesh (its stamped caller): only that app may change,
    /// run or delete it; the person may in CortexTerm. None for one made here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<crate::contracts::service::Caller>,
    /// Run in the write sandbox (writes only in `cwd`, temp, package caches and `writable`).
    #[serde(default)]
    pub sandboxed: bool,
    #[serde(default)]
    pub writable: Vec<String>,
    /// The person approved it in the asking app's window (as a run's `approved`); one made in
    /// CortexTerm is the person's own.
    #[serde(default)]
    pub approved: bool,
}

fn enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScheduleRun {
    pub id: String,
    pub name: String,
    /// Unix milliseconds.
    pub at: u64,
    pub duration_ms: u64,
    pub exit_code: i32,
    /// The last lines of its output (at most 40).
    #[serde(default)]
    pub tail: Vec<String>,
    /// It matched `alert_on` or failed: an alert was posted.
    #[serde(default)]
    pub alerted: bool,
    /// The run's trace (`trace://<id>`): its whole output, and what it did to the machine.
    #[serde(default)]
    pub trace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScheduleList {
    pub schedules: Vec<Schedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TraceStartParams {
    pub pid: u32,
    /// What lists call it; the process's command when empty.
    #[serde(default)]
    pub label: String,
    /// Who asked, for a member's request (`cortexcode on Mac mini`); empty for this app.
    #[serde(default)]
    pub asked_by: String,
    /// The asking plugin ends it with `system.trace.stop` (bringing the exit code and output), not
    /// when its processes are gone. Not for a call through the mesh.
    #[serde(default)]
    pub held: bool,
}

/// `system.trace.stop`: the app that ran the traced command may hand over how it ended and its
/// output, so the trace keeps them as a schedule run's does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TraceStopParams {
    pub id: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Output lines `[at, text]` (the first 20,000 are kept).
    #[serde(default)]
    pub output: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TraceReadParams {
    pub id: String,
    /// line | summary | series | records (`crate::contracts::service::Size`); summary when absent.
    #[serde(default)]
    pub size: String,
    /// Unix milliseconds; the whole trace when absent.
    #[serde(default)]
    pub from: Option<u64>,
    #[serde(default)]
    pub to: Option<u64>,
    /// For `records`: the kinds to keep (all when empty), and how many (0 = 500).
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub limit: u32,
    /// Unix milliseconds: the tree at that moment (`crate::contracts::service::Moment`) instead
    /// of a size.
    #[serde(default)]
    pub at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScheduleRunsParams {
    /// One schedule's runs; every schedule's when empty.
    #[serde(default)]
    pub id: String,
    /// 0 = 50.
    #[serde(default)]
    pub limit: u32,
}
