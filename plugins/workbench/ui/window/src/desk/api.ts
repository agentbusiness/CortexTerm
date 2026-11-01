/**
 * What the Desk reads from the plugins: the shapes of `terminal@1` (Runs, state, assess, complete),
 * `system@1` (metrics, processes, alerts, sweep) and `model@1` (info), as the window uses them.
 */

export interface Run {
  id: string;
  term_id: string;
  command: string;
  cwd: string;
  started: number;
  ended?: number | null;
  exit_code?: number | null;
  duration_ms: number;
  lines: number;
  bytes: number;
  format: string;
  errors: number;
  warnings: number;
  author: string;
  fullscreen: boolean;
  usual_ms: number;
}

export interface TermState {
  term_id: string;
  cwd: string;
  integrated: boolean;
  at_prompt: boolean;
  running?: Run | null;
  last_exit?: number | null;
  alternate_screen: boolean;
  interactive?: boolean;
  attention: string;
  git_branch?: string | null;
  /** What the running command asks (a prompt line, or a password: the terminal stopped echoing). */
  ask?: Ask | null;
  /** The Keychain key filled in during the running command. */
  keychain?: string | null;
}

export interface Ask {
  kind: 'confirm' | 'text' | 'secret';
  text: string;
  default?: string | null;
  /** confirm: the yes and the no answer as the prompt spells them. */
  options: string[];
  program: string;
  key: string;
  refused: boolean;
}

export interface Assessment {
  kind: 'shell' | 'ask' | 'unsure';
  text: string;
  program?: string | null;
  cwd: string;
  risk: string;
  safe: boolean;
  reasons: string[];
  matches?: { files: number; dirs: number; bytes: number; sample: string[] } | null;
  native_view?: string | null;
  native_target?: string | null;
  /** What the paste guard found; any makes it not safe, a high one always asks first. */
  threats?: Threat[];
}

/** One finding of the paste guard (`terminal.scan`, `terminal.assess`). */
export interface Threat {
  rule: string;
  severity: 'high' | 'medium';
  text: string;
}

/** `terminal.script.fetch`: the script a `curl … | sh` would run, fetched (never run) and scanned. */
export interface Script {
  url: string;
  text: string;
  bytes: number;
  truncated?: boolean;
  threats: Threat[];
}

/** `terminal.packages.check`: what OSV knows about the packages an install names. */
export interface PackageCheck {
  packages: { ecosystem: string; name: string; version?: string | null; malicious: string[]; vulns: string[] }[];
  error?: string | null;
}

export interface Completion {
  value: string;
  kind: string;
  description: string;
}

export interface Completions {
  from: number;
  items: Completion[];
  suggestion?: string | null;
}

export interface OutputLine {
  n: number;
  text: string;
  level: string;
  at: number;
  ansi?: string;
  /** Invisible characters or control codes were removed from it. */
  hidden?: boolean;
}

export interface RunOutput {
  run_id: string;
  total: number;
  matched: number;
  lines: OutputLine[];
  format: string;
}

export interface Histogram {
  run_id: string;
  bucket_ms: number;
  buckets: { at: number; info: number; warn: number; error: number }[];
}

export interface Metrics {
  at: number;
  machine: string;
  memory_total: number;
  cpu: number;
  cores: number[];
  p_cores: number;
  e_cores: number;
  memory_used: number;
  memory_compressed: number;
  swap_used: number;
  pressure: string;
  gpu?: number | null;
  gpu_active?: number | null;
  cpu_power?: number | null;
  gpu_power?: number | null;
  ane_power?: number | null;
  cpu_temp?: number | null;
  gpu_temp?: number | null;
  fan_rpm?: number | null;
  thermal: string;
  disk_total: number;
  disk_free: number;
  disk_read: number;
  disk_write: number;
  net_rx: number;
  net_tx: number;
  battery?: { percent: number; charging: boolean; watts?: number | null } | null;
  load: [number, number, number];
}

export interface Proc {
  pid: number;
  ppid: number;
  name: string;
  command: string;
  user: string;
  cpu: number;
  memory: number;
  disk_write: number;
  ports: number[];
  gpu?: number | null;
  app: string;
  started: number;
  pgid: number;
}

export interface ProcSample {
  at: number;
  cpu: number;
  memory: number;
  gpu?: number | null;
  disk_write: number;
}

export interface ThreadSample {
  id: number;
  name: string;
  state: string;
  cpu: number;
  user_ms: number;
  system_ms: number;
  priority: number;
}

export interface OpenFile {
  fd: string;
  kind: string;
  name: string;
  mode: string;
  state: string;
}

export interface MonitorReport {
  pid: number;
  on: boolean;
  children: boolean;
  started: number;
  stopped?: number | null;
  polls: number;
  failed: number;
  events: { at: number; pid: number; change: 'open' | 'close'; file: OpenFile }[];
  total_events: number;
  hosts: { address: string; kind: string; connections: number; first: number; last: number }[];
  folders: { folder: string; files: number; written: boolean; sample: string[] }[];
  listening: string[];
  flags: string[];
}

export interface ProcessDetail {
  process: Proc;
  executable: string;
  cwd: string;
  open_files: number;
  threads: number;
  parents: [number, string][];
  signature: string;
  team_id: string;
  quarantined: boolean;
  launchd_managed: boolean;
  state: string;
  cpu_time_ms: number;
  disk_read_total: number;
  disk_written_total: number;
  peak_memory: number;
  history: ProcSample[];
  thread_list: ThreadSample[];
  files: OpenFile[];
  children: Proc[];
  monitor?: MonitorReport | null;
}

export interface ProcessGroup {
  name: string;
  cpu: number;
  memory: number;
  disk_write: number;
  ports: number[];
  gpu?: number | null;
  processes: Proc[];
}

export interface Alert {
  id: string;
  kind: string;
  severity: string;
  text: string;
  at: number;
  pid?: number | null;
  port?: number | null;
  path?: string | null;
  actions: string[];
  dismissed: boolean;
}

export interface Finding {
  severity: string;
  kind: string;
  text: string;
  fix?: string | null;
  source: string;
  /** Stable across sweeps. */
  key: string;
  /** A decision covers it. */
  ignored?: boolean;
  /** What it is about: findings are grouped and decided by it. */
  group?: string;
  /** The covering decision's verdict; empty when open. */
  decision?: string;
  /** A fix command that ran and did not clear it. */
  tried?: string | null;
  /** The model's second look found it worse than its rating; raised one level. */
  raised?: string;
}

/** The person's decision about a group of findings (`system.finding.decide`). */
export interface Decision {
  /** expected | false_alarm | accepted | vendor */
  verdict: string;
  group: string;
  /** Only these findings; empty: the whole group up to `severity`. */
  keys: string[];
  severity: string;
  at: number;
  /** 0: no end. */
  until: number;
}

export interface SweepReport {
  at: number;
  duration_ms: number;
  findings: Finding[];
  checked: string[];
  skipped: string[];
  decisions?: Decision[];
  /** The latest checks after a fix, newest first. */
  fixes?: { at: number; group: string; text: string; command: string; gone: boolean }[];
}

/** `system.security.history`: per bucket, new high, medium, low and info; per group, its buckets. */
export interface History {
  since: number;
  bucket_ms: number;
  series: [number, number, number, number][];
  hits: Record<string, number[]>;
  /** What changed on the computer meanwhile (`macOS 26.1`, `3 apps updated`). */
  markers?: { at: number; text: string }[];
}

/** `system.cve`, the part the Alerts pane shows: each copy of the software it covers here. */
export interface CveReport {
  id: string;
  verdict: string;
  verdict_text: string;
  matches: { what: string; version: string; place: string; verdict: string; why: string; fix?: string | null }[];
}

export interface ModelInfo {
  model_id: string;
  variant: string;
  family: string;
  tags: string[];
  extra?: { source?: string; holder?: string; tier?: string; state?: string } & Record<string, unknown>;
}

export interface FileText {
  path: string;
  text: string;
  exists: boolean;
  writable: boolean;
  modified: number;
  bytes: number;
  too_large: boolean;
}

/** A traced process tree (`system.trace.list`, kept a week in IronGraph). */
export interface TraceInfo {
  id: string;
  label: string;
  command: string;
  cwd: string;
  pid: number;
  /** run | record | member */
  source: string;
  run_id?: string | null;
  asked_by: string;
  started: number;
  ended?: number | null;
  exit_code?: number | null;
  limits: string[];
  records: number;
}

export interface TraceRecord {
  at: number;
  kind: string;
  pid: number;
  ppid?: number;
  name?: string;
  text?: string;
  mode?: string;
  cpu?: number;
  memory?: number;
  gpu?: number;
  disk_write?: number;
  code?: number;
}

export interface TraceSummary {
  trace: TraceInfo;
  from: number;
  to: number;
  metrics: { name: string; min: number; avg: number; p95: number; max: number; max_at: number }[];
  series: { at: number; cpu: number; memory: number; gpu?: number | null }[];
  phases: { from: number; to: number; cpu: number; memory: number; busiest: string[] }[];
  processes: { name: string; count: number; cpu: number; memory: number }[];
  touched: { kind: string; name: string; how: string; count: number; first: number; last: number }[];
  errors: string[];
  text: string;
}

export interface TraceGraph {
  nodes: { id: string; kind: string; name: string; count: number }[];
  edges: { from: string; to: string; kind: string; count: number }[];
}

export const GB = 1_073_741_824;
export const MB = 1_048_576;

export function size(bytes: number): string {
  if (bytes >= GB) return `${(bytes / GB).toFixed(1)} GB`;
  if (bytes >= MB) return `${Math.round(bytes / MB)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} B`;
}

export function rate(bytes: number): string {
  if (bytes >= MB) return `${(bytes / MB).toFixed(1)} MB/s`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB/s`;
  return `${bytes} B/s`;
}

export function seconds(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

export function shortPath(path: string, home: string): string {
  if (home && path.startsWith(home)) return `~${path.slice(home.length)}` || '~';
  return path;
}

/** A shell word, quoted when it has to be. */
export function quote(word: string): string {
  return /^[\w@%+=:,./~-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`;
}

export interface SecurityObservation {
  id: string; at: number; source: string; kind: string; severity: string; summary: string; rule: string; subject: string;
  pid?: number | null; process_started?: number | null; parent_pid?: number | null; executable?: string | null;
  process_started_us?: number | null; process_version?: number | null;
  path?: string | null; remote?: string | null; port?: number | null; count: number;
}
export interface SecurityClaim { text: string; evidence: string[] }
export interface SecurityInvestigation {
  state: string; summary: SecurityClaim[]; alternatives: SecurityClaim[]; unknowns: string[]; next_steps: string[];
  checked_at: number; error?: string | null; observations: SecurityObservation[];
}
export interface SecurityIncident {
  id: string; key: string; first_at: number; last_at: number; title: string; severity: string; state: string;
  observations: SecurityObservation[]; investigation?: SecurityInvestigation | null; revision: number; omitted_observations?: number;
}
