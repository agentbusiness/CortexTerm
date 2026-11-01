/** Alerts & Security for one computer: broken sensors, a chart of what came up, one list grouped by
 * what it is about, and the person's decisions. Sensor, finding and model text is rendered as text,
 * never HTML or commands; fixes go through the assistant, which checks again after they run. */
import { Fragment, useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { Menu, ago, errorMessage, useRuntime } from '@cortex/sdk';
import type { Alert, CveReport, Decision, Finding, History, SweepReport } from './api';
import { quote } from './api';
import { useMachineAlerts } from './machine-data';
import './security-protection.css';

interface ProtectionImport { kind: 'suricata' | 'zeek'; path: string }
interface ProtectionConfig { packet_watch: boolean; deep_watch: boolean; investigate: boolean; imports: ProtectionImport[] }
interface ProtectionSensor { id: string; label: string; state: string; detail: string; last_at: number; dropped: number }
interface SecurityObservation {
  id: string; at: number; source: string; kind: string; severity: string; summary: string; rule: string; subject: string;
  pid?: number | null; process_started?: number | null; parent_pid?: number | null; executable?: string | null;
  process_started_us?: number | null; process_version?: number | null;
  path?: string | null; remote?: string | null; port?: number | null; count: number;
}
interface SecurityClaim { text: string; evidence: string[] }
interface SecurityInvestigation {
  state: string; summary: SecurityClaim[]; alternatives: SecurityClaim[]; unknowns: string[]; next_steps: string[];
  checked_at: number; error?: string | null; observations: SecurityObservation[];
}
interface SecurityIncident {
  id: string; key: string; first_at: number; last_at: number; title: string; severity: string; state: string;
  observations: SecurityObservation[]; investigation?: SecurityInvestigation | null; revision: number; omitted_observations?: number;
}
interface SecurityException {
  id: string; incident_key: string; created_at: number; expires_at: number; reason: string;
  observation_keys: string[]; max_severity: string;
}
interface ProtectionStatus {
  at: number; config: ProtectionConfig; sensors: ProtectionSensor[]; incidents: SecurityIncident[];
  exceptions: SecurityException[]; deep_install_command?: string | null; deep_service?: boolean;
  packet_capture_help: string; visibility: string;
}
interface StopTarget {
  id: string; revision: number; pid: number; started: number; executable: string;
  startedUs?: number; processVersion?: number;
}

type Ask = (text: string, intent: 'ask' | 'explain' | 'fix', runId?: string) => void;

/** One row of the list: a group of sweep findings, a live incident or a machine alert. */
interface Item {
  key: string;
  kind: 'sweep' | 'incident' | 'alert';
  title: string;
  /** The group's full name when the title is its last part. */
  where: string;
  text: string;
  severity: string;
  open: boolean;
  last: number;
  count: number;
  findings: Finding[];
  incident?: SecurityIncident;
  alert?: Alert;
  decision?: Decision;
}

const POLL_MS = 8_000;
const SLOW_MS = 60_000;
const RPC_MS = 20_000;
const MAX_TIMELINE = 100;
const PRIORITY: Record<string, string> = { critical: 'ACT NOW', high: 'ACT NOW', medium: 'SOON', warn: 'SOON', low: 'WATCH', info: 'NOTED' };
const priority = (severity: string) => PRIORITY[severity] ?? 'NOTED';
const VERDICTS = [
  ['expected', 'e', 'EXPECTED', 'Normal for this. Real, and fine.'],
  ['false_alarm', 'f', 'FALSE ALARM', 'The check is wrong here.'],
  ['accepted', 'r', 'ACCEPTED RISK', 'A real problem I live with for now.'],
  ['vendor', 'w', 'WAITING ON VENDOR', 'Only its maker can fix it.'],
] as const;
/** Attack stages (MITRE ATT&CK tactics in plain words), by the observation kinds the sensors record. */
const STAGES: [string, string, string[]][] = [
  ['PROBED', 'Reconnaissance', ['port_scan', 'network_alert']],
  ['GOT IN', 'Initial access', ['intrusion', 'malware', 'unsigned']],
  ['RAN', 'Execution', ['process_exec', 'execution', 'exec']],
  ['STAYED', 'Persistence', ['persistence', 'persistence_write']],
  ['TOOK SECRETS', 'Credential access', ['credential_access', 'credential', 'secret']],
  ['LOOKED AROUND', 'Discovery', ['network_sweep']],
  ['GATHERED', 'Collection', ['archive_created']],
  ['SENT OUT', 'Exfiltration', ['outbound', 'network']],
  ['CHANGED FILES', 'Impact', ['bulk_file_change']],
];
/** An advisory id in a finding's words. */
const ADVISORY = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|RUSTSEC-\d{4}-\d{4}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+)\b/i;
/** Lets the admin group read the packet capture devices until the next restart. */
const IMPORT_FORMATS: Record<ProtectionImport['kind'], string> = { suricata: 'Suricata EVE JSON', zeek: 'Zeek connection JSON' };
const GRANT_BPF = 'sudo chgrp admin /dev/bpf* && sudo chmod g+r /dev/bpf*';
const SYSTEM_PATH = /^\/(System|usr|bin|sbin)\//;
/** The outermost app or bundle a path is in, else the path. */
const bundleOf = (path: string) => /^(.*?\.(app|bundle|pkg))(\/|$)/.exec(path)?.[1] ?? path;
const verdictName = (verdict: string) => VERDICTS.find(([id]) => id === verdict)?.[2] ?? verdict.toUpperCase();
const plural = (n: number, word: string) => `${count(n)} ${word}${n === 1 ? '' : 's'}`;
const nameOf = (group: string) => (group.includes('/') ? group.split('/').filter(Boolean).pop() : group) || group;
const count = (value: number) => new Intl.NumberFormat().format(value);
const date = (at: number) => Number.isFinite(at) && at > 0 && at < 8_640_000_000_000_000 ? new Date(at) : null;
const time = (at: number) => date(at)?.toLocaleString() ?? 'Not recorded';
const iso = (at: number) => date(at)?.toISOString();
const rank = (severity: string) => (({ high: 0, warn: 1, medium: 1, low: 2, info: 3 } as Record<string, number>)[severity] ?? 4);
const tone = (value: string) => ['high', 'warn', 'medium', 'low', 'info'].includes(value) ? value : 'info';

function stopTarget(incident: SecurityIncident): StopTarget | null {
  // All facts with a process identity must agree. A correlated incident can contain children;
  // choosing an arbitrary last PID would stop something the person did not approve.
  const identities = incident.observations.filter((entry) => !entry.source.startsWith('import:') && entry.pid && entry.pid > 1 && entry.process_started && entry.executable);
  const first = identities[0];
  if (!first) return null;
  if (identities.some((entry) => entry.pid !== first.pid || entry.process_started !== first.process_started || entry.executable !== first.executable)) return null;
  const native = [...identities].sort((a, b) => b.at - a.at);
  const startedUs = native.find((entry) => entry.process_started_us != null)?.process_started_us ?? undefined;
  const processVersion = native.find((entry) => entry.process_version != null)?.process_version ?? undefined;
  if (identities.some((entry) => (startedUs !== undefined && entry.process_started_us != null && entry.process_started_us !== startedUs)
    || (processVersion !== undefined && entry.process_version != null && entry.process_version !== processVersion))) return null;
  return { id: incident.id, revision: incident.revision, pid: first.pid!, started: first.process_started!, executable: first.executable!, startedUs, processVersion };
}

function sameTarget(a: StopTarget | null, b: StopTarget | null) {
  return !!a && !!b && a.id === b.id && a.revision === b.revision && a.pid === b.pid && a.started === b.started
    && a.executable === b.executable && a.startedUs === b.startedUs && a.processVersion === b.processVersion;
}

function evidenceFor(incident: SecurityIncident) {
  const entries = new Map<string, SecurityObservation>();
  for (const observation of [...incident.observations, ...(incident.investigation?.observations ?? [])]) {
    if (observation.id && !entries.has(observation.id)) entries.set(observation.id, observation);
  }
  return [...entries.values()].sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
}

function Claims({ claims, ids, onEvidence }: { claims: SecurityClaim[]; ids: Set<string>; onEvidence: (id: string) => void }) {
  return <ul className="ct-protection-claims">{claims.slice(0, 8).map((claim, index) => {
    // An invalid response must never be promoted to a supported explanation in the UI.
    const valid = claim.evidence.length > 0 && claim.evidence.every((id) => ids.has(id));
    return <li key={index}>{valid ? <>
      <span dir="auto">{claim.text}</span>
      <span className="ct-protection-citations" aria-label="Supporting evidence">{[...new Set(claim.evidence)].slice(0, 8).map((id) => <button type="button" className="ct-protection-cite" key={id} onClick={() => onEvidence(id)} title={`Show observation ${id}`}>{id}</button>)}</span>
    </> : <span className="ct-warn">An explanation without matching evidence was withheld. Run the investigation again.</span>}</li>;
  })}</ul>;
}

/** The Alerts & Security pane's content, for the computer of its `ComputerScope`. */
export function SecurityPane({ onAsk, onCommand }: { onAsk: Ask; onCommand: (command: string) => void }) {
  const { client, node } = useRuntime();
  const machineAlerts = useMachineAlerts(node);
  const prefix = useId();
  const section = useRef<HTMLElement>(null);
  const mounted = useRef(false);
  const visible = useRef(true);
  const generation = useRef(0);
  const requestVersion = useRef(0);
  const reading = useRef(false);
  const busyRef = useRef(false);
  const controllers = useRef(new Set<AbortController>());
  const statusRef = useRef<ProtectionStatus | null>(null);
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionUncertain, setActionUncertain] = useState(false);
  const [loadProblem, setLoadProblem] = useState<string | null>(null);
  const [actionProblem, setActionProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [details, setDetails] = useState<Map<string, SecurityIncident>>(new Map());
  const [detailProblem, setDetailProblem] = useState<Record<string, string>>({});
  const [report, setReport] = useState<SweepReport | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [days, setDays] = useState(7);
  const [tab, setTab] = useState<'open' | 'decided'>('open');
  const [selected, setSelected] = useState('');
  const [deciding, setDeciding] = useState(false);
  const [openCheck, setOpenCheck] = useState('');
  const [coverage, setCoverage] = useState(false);
  const [sweeping, setSweeping] = useState(false);
  const [granting, setGranting] = useState(false);
  const [reported, setReported] = useState('');
  const [copies, setCopies] = useState<{ id: string; report?: CveReport; problem?: string } | null>(null);
  const [timelineLimits, setTimelineLimits] = useState<Record<string, number>>({});
  const [focusedEvidence, setFocusedEvidence] = useState<Record<string, string>>({});
  const [importKind, setImportKind] = useState<ProtectionImport['kind']>('suricata');
  const [importPath, setImportPath] = useState('');
  const [confirmStop, setConfirmStop] = useState<StopTarget | null>(null);

  const rpc = useCallback(async <T,>(method: string, params: unknown): Promise<T> => {
    const controller = new AbortController();
    controllers.current.add(controller);
    const timeout = window.setTimeout(() => controller.abort(new Error('The request took more than 20 seconds. Refresh before trying again.')), RPC_MS);
    try { return await client.call<T>(method, params, { signal: controller.signal }); }
    finally { window.clearTimeout(timeout); controllers.current.delete(controller); }
  }, [client]);

  const accept = useCallback((next: ProtectionStatus) => {
    statusRef.current = next;
    setStatus(next);
    setLoadProblem(null);
    setActionUncertain(false);
  }, []);

  const refresh = useCallback(async () => {
    if (!mounted.current || reading.current || busyRef.current) return;
    reading.current = true;
    const currentGeneration = generation.current;
    const version = ++requestVersion.current;
    try {
      const next = await rpc<ProtectionStatus>('system.protection.status', {});
      if (mounted.current && currentGeneration === generation.current && version === requestVersion.current) accept(next);
    } catch (cause) {
      if (mounted.current && currentGeneration === generation.current && version === requestVersion.current) setLoadProblem(errorMessage(cause));
    } finally {
      if (currentGeneration === generation.current) { reading.current = false; if (mounted.current) { setLoading(false); } }
    }
  }, [rpc, accept]);

  useEffect(() => {
    mounted.current = true;
    const currentGeneration = ++generation.current;
    requestVersion.current++;
    reading.current = false;
    busyRef.current = false;
    statusRef.current = null;
    setStatus(null); setLoading(true); setActionUncertain(false); setLoadProblem(null); setActionProblem(null); setBusy(null);
    setDetails(new Map()); setDetailProblem({}); setConfirmStop(null); setReport(null); setHistory(null); setSelected(''); setDeciding(false); setAsked(new Set());
    setImportPath(''); setTimelineLimits({}); setFocusedEvidence({});
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      if (!mounted.current || generation.current !== currentGeneration) return;
      if (visible.current && document.visibilityState !== 'hidden') await refresh();
      if (mounted.current && generation.current === currentGeneration) timer = setTimeout(() => void poll(), POLL_MS);
    };
    const wake = () => { if (generation.current === currentGeneration && document.visibilityState !== 'hidden' && visible.current) void refresh(); };
    const observer = typeof IntersectionObserver !== 'undefined' ? new IntersectionObserver(([entry]) => {
      if (generation.current !== currentGeneration) return;
      visible.current = !!entry?.isIntersecting;
      if (visible.current) wake();
    }) : null;
    visible.current = true;
    if (section.current) observer?.observe(section.current);
    document.addEventListener('visibilitychange', wake);
    void poll();
    return () => {
      mounted.current = false;
      generation.current++;
      if (timer !== undefined) clearTimeout(timer);
      observer?.disconnect();
      document.removeEventListener('visibilitychange', wake);
      for (const controller of controllers.current) controller.abort();
      controllers.current.clear();
    };
  }, [client, node, refresh]);

  const mutate = async (label: string, method: string, params: unknown): Promise<boolean> => {
    if (busyRef.current || !mounted.current) return false;
    busyRef.current = true;
    setBusy(label); setActionProblem(null);
    requestVersion.current++;
    const currentGeneration = generation.current;
    try {
      const next = await rpc<ProtectionStatus>(method, params);
      if (mounted.current && currentGeneration === generation.current) { accept(next); setConfirmStop(null); return true; }
    } catch (cause) {
      if (mounted.current && currentGeneration === generation.current) {
        setActionProblem(`${errorMessage(cause)} Refresh to see whether the action was applied before trying again.`);
        setActionUncertain(true); setConfirmStop(null);
      }
    } finally {
      if (currentGeneration === generation.current) { busyRef.current = false; if (mounted.current) setBusy(null); }
    }
    return false;
  };

  const configure = async (patch: Partial<ProtectionConfig>) => {
    const current = statusRef.current;
    if (!current) return false;
    return mutate('settings', 'system.protection.configure', { ...current.config, ...patch });
  };
  const act = (id: string, action: string) => mutate(`${id}:${action}`, 'system.incident.act', {
    id, action, confirm: action === 'allow_hour',
    ...(action === 'allow_hour' ? { expected_revision: incidents.find((entry) => entry.id === id)?.revision } : {}),
  });

  const loadIncident = async (id: string) => {
    const currentGeneration = generation.current;
    const version = requestVersion.current;
    try {
      const incident = await rpc<SecurityIncident>('system.incident.get', { id });
      if (mounted.current && currentGeneration === generation.current && version === requestVersion.current) {
        setDetails((current) => {
          const next = new Map(current);
          if ((next.get(id)?.revision ?? -1) <= incident.revision) next.set(id, incident);
          return next;
        });
        setDetailProblem((current) => { const next = { ...current }; delete next[id]; return next; });
      }
    } catch (cause) {
      if (mounted.current && currentGeneration === generation.current) setDetailProblem((current) => ({ ...current, [id]: errorMessage(cause) }));
    }
  };

  const incidents = useMemo(() => (status?.incidents ?? []).map((entry) => {
    const detail = details.get(entry.id);
    // Status is authoritative at equal revision: investigation state and repeat counts can
    // advance without changing the underlying evidence revision.
    return detail && detail.revision > entry.revision ? detail : entry;
  }).sort((a, b) => rank(a.severity) - rank(b.severity) || b.last_at - a.last_at), [status, details]);

  useEffect(() => {
    const incident = confirmStop ? incidents.find((entry) => entry.id === confirmStop.id) : null;
    if (confirmStop && (!incident || !sameTarget(confirmStop, stopTarget(incident)))) setConfirmStop(null);
  }, [incidents, confirmStop]);

  const goToEvidence = (incidentId: string, id: string) => {
    setTimelineLimits((current) => ({ ...current, [incidentId]: MAX_TIMELINE }));
    setFocusedEvidence((current) => ({ ...current, [incidentId]: id }));
    requestAnimationFrame(() => {
      const element = document.getElementById(`${prefix}-${incidentId}-${id}`);
      element?.scrollIntoView({ block: 'nearest', behavior: 'instant' });
      element?.focus({ preventScroll: true });
    });
  };

  const addImport = async () => {
    const path = importPath.trim();
    const config = statusRef.current?.config;
    if (!config || !path.startsWith('/') || path.length > 1024 || path.split('/').includes('..') || /[\u0000-\u001f\u007f]/.test(path)) {
      setActionProblem('Choose an absolute local log path of at most 1,024 characters, without parent traversal or control characters.'); return;
    }
    if (config.imports.length >= 4) { setActionProblem('Four sensor files are already connected. Remove one before adding another.'); return; }
    if (config.imports.some((entry) => entry.path === path)) { setActionProblem('This sensor file is already connected.'); return; }
    if (await configure({ imports: [...config.imports, { kind: importKind, path }] })) setImportPath('');
  };

  const hasProblem = !!loadProblem;
  const stale = !!status && Date.now() - status.at > 30_000;
  const exceptions = (status?.exceptions ?? []).filter((entry) => entry.expires_at > Date.now());
  const configurationDisabled = !!busy || hasProblem || stale || actionUncertain;

  // The sweep and the chart change slowly: read them on open, every minute and after a decision.
  const loadSlow = useCallback(async () => {
    const currentGeneration = generation.current;
    // The first read runs the sweep when there was none yet: minutes, so no 20 s limit.
    const [sweep, chart] = await Promise.allSettled([
      client.call<SweepReport>('system.sweep', {}),
      rpc<History>('system.security.history', { days }),
    ]);
    if (!mounted.current || currentGeneration !== generation.current) return;
    if (sweep.status === 'fulfilled') setReport(sweep.value);
    else setActionProblem(`The security sweep could not be read: ${errorMessage(sweep.reason)}`);
    if (chart.status === 'fulfilled') setHistory(chart.value);
  }, [client, rpc, days]);

  useEffect(() => {
    void loadSlow();
    const timer = setInterval(() => { if (document.visibilityState !== 'hidden') void loadSlow(); }, SLOW_MS);
    return () => clearInterval(timer);
  }, [loadSlow]);

  const items = useMemo(() => itemsOf(report, incidents, machineAlerts.alerts), [report, incidents, machineAlerts.alerts]);
  const shown = items.filter((item) => (tab === 'open') === item.open);
  // The worst open issues not asked about yet, each as a question a click asks in the chat.
  const [asked, setAsked] = useState<Set<string>>(() => new Set());
  const questions = items.filter((entry) => entry.open && !asked.has(entry.key)).slice(0, 3);
  const item = items.find((entry) => entry.key === selected);
  const openCount = items.filter((entry) => entry.open).length;
  const urgent = items.filter((entry) => entry.open && priority(entry.severity) === 'ACT NOW').length;

  useEffect(() => {
    if (item?.incident) void loadIncident(item.incident.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item?.incident?.id]);

  const select = (key: string) => { setSelected(key); setDeciding(false); setOpenCheck(''); setConfirmStop(null); setCopies(null); };

  const whereItLives = (id: string) => {
    setCopies({ id });
    client.call<CveReport>('system.cve', { id }).then((report) => { if (mounted.current) setCopies({ id, report }); })
      .catch((cause) => { if (mounted.current) setCopies({ id, problem: errorMessage(cause) }); });
  };

  const decide = async (group: string, verdict: string, keys: string[] = [], forDays = 0) => {
    if (busyRef.current) return false;
    busyRef.current = true;
    setBusy(verdict === 'fixed' ? 'checking' : 'deciding'); setActionProblem(null);
    try {
      const next = await client.call<SweepReport>('system.finding.decide', { group, verdict, keys, days: forDays });
      if (!mounted.current) return false;
      setReport(next); setDeciding(false);
      void refresh(); void loadSlow();
      return true;
    } catch (cause) {
      if (mounted.current) setActionProblem(errorMessage(cause));
      return false;
    } finally {
      busyRef.current = false;
      if (mounted.current) setBusy(null);
    }
  };

  const runSweep = async () => {
    setSweeping(true); setActionProblem(null);
    try { const next = await client.call<SweepReport>('system.sweep.run', {}); if (mounted.current) { setReport(next); void loadSlow(); void refresh(); } }
    catch (cause) { if (mounted.current) setActionProblem(errorMessage(cause)); }
    finally { if (mounted.current) setSweeping(false); }
  };

  const ask = (entry: Item, intent: 'ask' | 'fix') => {
    setAsked((done) => new Set(done).add(entry.key));
    if (entry.kind === 'sweep') {
      const worst = entry.findings[0];
      if (!worst) return;
      const more = entry.count > 1 ? `, one of ${entry.count} findings about ${entry.title}` : '';
      onAsk(`The security sweep says: "${worst.text}" (${worst.source}${more}). ${intent === 'fix' ? 'Fix it.' : 'Is this a problem, and what should I do?'}`, 'ask');
    } else {
      onAsk(`An alert says: "${entry.incident?.title ?? entry.alert?.text ?? entry.title}". What should I do?`, 'ask');
    }
  };

  const onDetailKey = (event: KeyboardEvent<HTMLElement>) => {
    if (!item || deciding || event.metaKey || event.ctrlKey || event.altKey || (event.target as HTMLElement).closest('input,textarea,select')) return;
    const key = event.key.toLowerCase();
    if (key === 'a') ask(item, 'ask');
    else if (key === 'f' && item.kind === 'sweep') ask(item, 'fix');
    else if (key === 'd' && item.kind === 'sweep') setDeciding(true);
    else if (key === 'i' && item.incident && status?.config.investigate) void act(item.incident.id, 'investigate');
    else if (key === 'r' && item.kind === 'incident' && item.incident) void copyReport(item.incident, evidenceFor(item.incident));
    else return;
    event.preventDefault();
  };

  const broken = (status?.sensors ?? []).filter((sensor) => sensor.state === 'unavailable' || sensor.state === 'degraded');
  const working = (status?.sensors ?? []).filter((sensor) => sensor.state === 'active' || sensor.state === 'starting').length;
  const highlight = item ? [...new Set([...(history?.hits[item.key] ?? []), ...(item.incident ? history?.hits[item.incident.id] ?? [] : [])])] : [];

  return <section ref={section} className="ct-asec ct-protection ct-sec" aria-labelledby={`${prefix}-heading`}>
    <header className="ct-sec-head">
      <h2 className="ct-label" id={`${prefix}-heading`}>ALERTS &amp; SECURITY</h2>
      {urgent > 0 && <span className="ct-label ct-warn">{urgent} NEED{urgent === 1 ? 'S' : ''} YOU</span>}
      <span className="ct-label ct-faint">{loading && !status ? 'LOADING…' : `${openCount} OPEN`}</span>
      <span className="grow" />
      <button type="button" className="detent sm" disabled={sweeping} title={report?.at ? `Last sweep ${ago(report.at)}` : 'The daily sweep has not run yet'} onClick={() => void runSweep()}>{sweeping ? 'SWEEPING…' : 'SWEEP NOW'}</button>
    </header>
    {questions.length > 0 && <nav className="ct-sec-ask" aria-label="Ask the assistant">
      <span className="ct-label">ASK</span>
      {questions.map((entry) => <button key={entry.key} type="button" title="Asks the assistant in the chat" onClick={() => ask(entry, 'ask')}>{questionOf(entry)}</button>)}
    </nav>}
    {loadProblem && <p className="ct-asec-note ct-warn" role="status">Protection status could not be refreshed: {loadProblem}. {status ? 'The last known status is shown.' : 'Monitoring coverage is unknown.'}</p>}
    {stale && !hasProblem && <p className="ct-asec-note ct-warn" role="status">This status is more than 30 seconds old.</p>}
    {actionProblem && <p className="ct-asec-note ct-warn" role="alert">{actionProblem}</p>}
    {machineAlerts.problem && <p className="ct-asec-note ct-warn" role="status">Alerts could not be read: {machineAlerts.problem}</p>}

    {status && <div className={`ct-sec-health${broken.length ? ' broken' : ''}`}>
      <span className="ct-label ct-blue">{working} OF {status.sensors.length} SENSORS WORKING</span>
      {broken.length > 0 && <span className="ct-label ct-warn ct-sec-broken" title={broken.map((sensor) => `${sensor.label}: ${sensor.detail}`).join('\n')}>{broken.map((sensor) => sensor.label).join(' · ')}</span>}
      <button type="button" className="detent sm" aria-expanded={coverage} onClick={() => setCoverage((value) => !value)}>COVERAGE {coverage ? '▾' : '▸'}</button>
    </div>}
    {status && coverage && coverageView()}

    <div className="ct-sec-chart-box">
      <div className="ct-sec-legend">
        <span className="ct-label">NEW FINDINGS BY PRIORITY</span>
        <span className="ct-label k0">ACT NOW</span><span className="ct-label k1">SOON</span><span className="ct-label k2">WATCH</span><span className="ct-label k3">NOTED</span>
        <span className="grow" />
        {[1, 7, 30].map((value) => <button key={value} type="button" className={`ct-seg${days === value ? ' on' : ''}`} onClick={() => setDays(value)}>{value === 1 ? '24 H' : `${value} D`}</button>)}
      </div>
      <Chart history={history} highlight={highlight} label={item?.title} />
    </div>

    <div className="ct-sec-body">
      <div className="ct-sec-list">
        <div className="ct-sec-tabs">
          <span className="ct-label ct-faint">GROUPED BY WHAT IT IS ABOUT</span>
          <span className="grow" />
          <button type="button" className={`ct-seg${tab === 'open' ? ' on' : ''}`} onClick={() => { setTab('open'); setSelected(''); }}>OPEN · {openCount}</button>
          <button type="button" className={`ct-seg${tab === 'decided' ? ' on' : ''}`} onClick={() => { setTab('decided'); setSelected(''); }}>DECIDED · {items.length - openCount}</button>
        </div>
        {tab === 'decided' && (report?.fixes ?? []).filter((fix) => fix.gone).slice(0, 8).map((fix) => fixCard(fix))}
        {shown.length === 0 && <p className="ct-asec-note">{tab === 'open' ? 'Nothing open. The checks only know what they can see; no findings is not an all-clear.' : 'No decisions yet.'}</p>}
        {shown.map((entry) => <Fragment key={entry.key}><button type="button" className={`ct-sec-row ${tone(entry.severity)}${entry.key === item?.key ? ' on' : ''}`} aria-pressed={entry.key === item?.key} onClick={() => select(entry.key === item?.key ? '' : entry.key)}>
          <span className="ct-label sev">{entry.open ? priority(entry.severity) : verdictName(entry.decision?.verdict ?? 'dismissed')}</span>
          <Hits hits={[...(history?.hits[entry.key] ?? []), ...(entry.incident ? history?.hits[entry.incident.id] ?? [] : [])]} buckets={history?.series.length ?? 0} />
          <span className="ct-sec-row-main"><span className="ct-sec-row-title" dir="auto">{entry.title}</span><span className="ct-sec-row-text" dir="auto">{entry.text}</span></span>
          <span className="ct-sec-row-side"><span className="ct-label ct-faint">{entry.kind === 'sweep' ? plural(entry.count, 'finding') : entry.kind === 'incident' ? 'INCIDENT' : entry.alert?.kind.toUpperCase()}</span><time className="ct-label ct-faint" dateTime={iso(entry.last)}>{date(entry.last) ? ago(entry.last) : ''}</time></span>
        </button>
        {item && entry.key === item.key && <section className="ct-sec-detail" tabIndex={-1} aria-label={item.title} onKeyDown={onDetailKey}>
          {deciding && item.kind === 'sweep' ? <DecideSheet item={item} before={precedent(report, item)} busy={!!busy} onCancel={() => setDeciding(false)} onDecide={(verdict, keys, forDays) => void decide(item.key, verdict, keys, forDays)} />
            : item.kind === 'sweep' ? sweepView(item) : item.incident ? incidentView(item, item.incident) : alertView(item)}
        </section>}
        </Fragment>)}
      </div>
    </div>
  </section>;

  function sweepView(entry: Item) {
    const decision = entry.decision;
    const checks = checksOf(entry.findings);
    const tried = entry.findings.find((finding) => finding.tried)?.tried;
    const raised = entry.findings.find((finding) => finding.raised)?.raised;
    const investigation = entry.incident?.investigation;
    const advisory = entry.findings.map((finding) => ADVISORY.exec(finding.text)?.[1]?.toUpperCase()).find(Boolean);
    return <>
      <div className="ct-sec-detail-head"><h3 dir="auto">{entry.title}</h3><span className="ct-label ct-faint">{entry.open ? priority(entry.severity) : verdictName(decision?.verdict ?? '')} · {plural(entry.count, 'finding')}</span></div>
      {entry.where && <code className="ct-sec-where" dir="ltr">{entry.where}</code>}
      {decision && <p className="ct-sec-decided">Decided <b>{verdictName(decision.verdict)}</b> {ago(decision.at)}: {decision.keys.length ? `only these ${plural(decision.keys.length, 'finding')}` : `everything about it up to ${priority(decision.severity).toLowerCase()}`}, {decision.until ? `until ${new Date(decision.until).toLocaleDateString()}` : 'no end'}. A worse finding shows again. <button type="button" className="detent sm" disabled={!!busy} onClick={() => void decide(entry.key, '')}>UNDO</button></p>}
      <ol className="ct-sec-findings">{checks.map((check) => <li key={check.id}>
        <span className={`ct-label ${tone(check.findings[0]!.severity)}`}>{priority(check.findings[0]!.severity)}</span>
        <span dir="auto">{check.findings.length > 1 && <b>{check.findings.length} × {check.source}. </b>}{check.findings[0]!.text}</span>
        {check.findings[0]!.fix && <code dir="ltr" title="The assistant offers it; it never runs by itself">{check.findings[0]!.fix}</code>}
        {check.findings.length > 1 && <button type="button" className="ct-seg" aria-expanded={openCheck === check.id} onClick={() => setOpenCheck(openCheck === check.id ? '' : check.id)}>{openCheck === check.id ? 'HIDE ▾' : `ALL ${check.findings.length} ▸`}</button>}
        {openCheck === check.id && <ul className="ct-sec-each">{check.findings.slice(0, 50).map((finding) => <li key={finding.key} dir="auto">{finding.text}</li>)}
          {check.findings.length > 50 && <li className="ct-faint">and {check.findings.length - 50} more. Ask about them, or decide about the whole group.</li>}</ul>}
      </li>)}</ol>
      {raised && <p className="ct-asec-note ct-warn">Raised by the assistant's second look: this looks like {raised}. The checks rated it one level lower.</p>}
      {tried && <p className="ct-asec-note ct-warn">Tried <code>{tried}</code>: a fresh check still finds it. The assistant won't offer it again.</p>}
      {(report?.fixes ?? []).filter((fix) => fix.group === entry.key).slice(0, 3).map((fix) => fixCard(fix))}
      {advisory && copiesView(entry, advisory)}
      {investigation && investigation.summary.length > 0 && <div className="ct-sec-read"><h4 className="ct-label ct-blue">THE MODEL'S READ</h4><Claims claims={investigation.summary} ids={new Set(evidenceFor(entry.incident!).map((e) => e.id))} onEvidence={() => undefined} /></div>}
      <div className="ct-protection-actions">
        <button type="button" className="detent sm warn" onClick={() => ask(entry, 'ask')}>A · ASK</button>
        {entry.findings.some((finding) => finding.fix) && <button type="button" className="detent sm" title="The assistant proposes the fix; you run it; it checks again" onClick={() => ask(entry, 'fix')}>F · FIX…</button>}
        {entry.open && <button type="button" className="detent sm" onClick={() => setDeciding(true)}>D · DECIDE…</button>}
        {entry.open && <button type="button" className="detent sm" disabled={!!busy} title="Check again now; closes what is gone" onClick={() => void decide(entry.key, 'fixed')}>{busy === 'checking' ? 'CHECKING…' : 'FIXED? CHECK AGAIN'}</button>}
        {entry.incident && <button type="button" className="detent sm" disabled={configurationDisabled || !status?.config.investigate || ['running', 'queued'].includes(investigation?.state ?? '')} onClick={() => void act(entry.incident!.id, 'investigate')}>I · INVESTIGATE</button>}
      </div>
    </>;
  }

  /** What a check after a fix found. */
  function fixCard(fix: NonNullable<SweepReport['fixes']>[number]) {
    return <div key={`${fix.at}${fix.group}`} className={`ct-sec-fix${fix.gone ? ' gone' : ''}`}>
      <span className="ct-label">{fix.gone ? 'FIXED · CHECKED AGAIN' : 'NOT FIXED · CHECKED AGAIN'} · {ago(fix.at).toUpperCase()}</span>
      {fix.command && <code dir="ltr">$ {fix.command}</code>}
      <span dir="auto">{fix.gone ? `${nameOf(fix.group)}: a fresh check no longer finds ${fix.text}.` : `${nameOf(fix.group)}: a fresh check still finds ${fix.text}.${fix.command ? ' The assistant will not offer this command again.' : ''}`}</span>
    </div>;
  }

  /** Commands that contain what an incident shows, for the person to read and run on the Line. */
  function containment(evidence: SecurityObservation[]) {
    const out: { label: string; title: string; command: string }[] = [];
    const plists = [...new Set(evidence.filter((e) => e.kind.startsWith('persistence') && e.path?.endsWith('.plist')).map((e) => e.path!))];
    for (const plist of plists.slice(0, 3)) {
      const system = plist.startsWith('/Library/');
      out.push({
        label: `DISABLE ${plist.split('/').pop()!.replace(/\.plist$/, '')}…`,
        title: 'Unload this login item and move its file to ~/Quarantined (undo: move it back)',
        command: system
          ? `sudo launchctl bootout system ${quote(plist)}; mkdir -p ~/Quarantined && sudo mv ${quote(plist)} ~/Quarantined/`
          : `launchctl bootout gui/$(id -u) ${quote(plist)}; mkdir -p ~/Quarantined && mv ${quote(plist)} ~/Quarantined/`,
      });
    }
    const remotes = [...new Set(evidence.filter((e) => e.remote && !e.source.startsWith('import:') && ['outbound', 'network', 'connection', 'network_alert'].includes(e.kind)).map((e) => e.remote!))].slice(0, 5);
    if (remotes.length) out.push({
      label: `BLOCK ${remotes.length === 1 ? remotes[0] : `${remotes.length} ADDRESSES`}…`,
      title: 'A packet-filter rule in its own anchor (undo: sudo pfctl -a com.apple/cortexterm -F rules)',
      command: `printf 'block drop out quick to %s\\n' ${remotes.map(quote).join(' ')} | sudo pfctl -a com.apple/cortexterm -f - && sudo pfctl -E`,
    });
    const files = [...new Set(evidence.flatMap((e) => [e.executable, e.kind === 'malware' ? e.path : null]).filter((path): path is string => !!path && path.startsWith('/') && !SYSTEM_PATH.test(path)).map(bundleOf))].slice(0, 2);
    for (const file of files) out.push({
      label: `QUARANTINE ${file.split('/').pop()}…`,
      title: 'Move it to ~/Quarantined, where it cannot run from its place (undo: move it back)',
      command: `mkdir -p ~/Quarantined && mv ${quote(file)} ~/Quarantined/`,
    });
    return out;
  }

  /** The case as plain text, to keep or send to someone. */
  function reportText(incident: SecurityIncident, evidence: SecurityObservation[]) {
    const stages = STAGES.filter(([, , list]) => evidence.some((e) => list.includes(e.kind))).map(([name, tactic]) => `${name.toLowerCase()} (${tactic})`);
    const investigation = incident.investigation;
    return [
      `Security incident on ${node ? 'a CortexTerm computer' : 'this Mac'}: ${incident.title}`,
      `Priority ${priority(incident.severity).toLowerCase()}, ${incident.state}. First seen ${time(incident.first_at)}, last ${time(incident.last_at)}.`,
      stages.length ? `Attack stages seen: ${stages.join(', ')}.` : '',
      ...(investigation?.summary.length ? ['', 'Local AI read (not verified):', ...investigation.summary.map((c) => `- ${c.text} [${c.evidence.join(', ')}]`)] : []),
      ...(investigation?.unknowns.length ? ['', 'Still unknown:', ...investigation.unknowns.map((u) => `- ${u}`)] : []),
      '', 'Observed:',
      ...evidence.map((e) => `${time(e.at)} [${e.id}] ${e.source}: ${e.summary}${e.executable ? ` | program ${e.executable}` : ''}${e.path ? ` | file ${e.path}` : ''}${e.remote ? ` | address ${e.remote}${e.port ? `:${e.port}` : ''}` : ''}`),
    ].filter((line, index, all) => line !== '' || all[index - 1] !== '').join('\n');
  }

  async function copyReport(incident: SecurityIncident, evidence: SecurityObservation[]) {
    try {
      await navigator.clipboard.writeText(reportText(incident, evidence));
      setReported(incident.id);
    } catch (cause) { setActionProblem(`The report could not be copied: ${errorMessage(cause)}`); }
  }

  /** Every copy of the flawed software here, from the CVE cross-check, each with its own way out. */
  function copiesView(entry: Item, id: string) {
    if (copies?.id !== id) return <button type="button" className="ct-seg" onClick={() => whereItLives(id)}>WHERE {id} LIVES ▸</button>;
    if (copies.problem) return <p className="ct-asec-note ct-warn">{id} could not be checked: {copies.problem}</p>;
    if (!copies.report) return <p className="ct-asec-note" role="status">Looking for every copy of what {id} covers…</p>;
    const worst = entry.findings[0]!;
    return <div className="ct-sec-copies">
      <h4 className="ct-label">WHERE IT LIVES · {copies.report.matches.length} {copies.report.matches.length === 1 ? 'COPY' : 'COPIES'}</h4>
      {copies.report.matches.length === 0 && <p className="ct-asec-note">{copies.report.verdict_text}</p>}
      {copies.report.matches.slice(0, 12).map((match, index) => {
        const affected = match.verdict === 'affected';
        const inApp = /\.app(\/|$)/.test(match.place);
        return <div key={index} className="ct-sec-copy">
          <span className={`ct-label ${affected ? 'ct-warn' : 'ct-faint'}`}>{match.verdict.replace('-', ' ').toUpperCase()}{affected && inApp && !match.fix ? ' · VENDOR' : ''}</span>
          <span><b>{match.what} {match.version}</b>{match.place && <code dir="ltr">{match.place}</code>}<small>{match.why}</small></span>
          {affected && match.fix && <button type="button" className="detent sm" title={match.fix} onClick={() => onAsk(`The security sweep says: "${worst.text}" (${worst.source}). Fix the copy ${match.what} ${match.version} at ${match.place || 'this Mac'} with ${match.fix}`, 'ask')}>FIX THIS COPY…</button>}
          {affected && !match.fix && <button type="button" className="detent sm" disabled={!!busy} title="Only its maker can fix a library inside their app" onClick={() => void decide(entry.key, 'vendor', entry.findings.filter((f) => !f.ignored).map((f) => f.key))}>WAITING ON VENDOR</button>}
        </div>;
      })}
    </div>;
  }

  /** The case: which attack stages its observations show, the investigation's steps, and what
   *  connected to what (only links an observation recorded). */
  function caseView(incident: SecurityIncident, evidence: SecurityObservation[]) {
    const kinds = new Set(evidence.map((e) => e.kind));
    const seen = STAGES.map(([name, tactic, list]) => ({ name, tactic, hit: evidence.filter((e) => list.includes(e.kind)) }));
    const investigation = incident.investigation;
    const contained = kinds.has('response');
    const steps: [string, boolean, string][] = [
      ['IS IT REAL?', investigation?.state === 'complete', investigation?.state === 'complete' ? 'Investigated' : 'I · INVESTIGATE runs read-only checks'],
      ['WHAT DID IT TOUCH?', evidence.some((e) => e.path || e.remote), 'The links below'],
      ['CONTAIN', contained, contained ? 'You stopped the process' : 'Stop or mute below; each asks you first'],
      ['CLEAN UP', false, 'Ask: the assistant walks through it'],
      ['LEARN', incident.state === 'dismissed', incident.state === 'dismissed' ? 'Dismissed' : 'Dismiss when settled'],
    ];
    const links = new Map<string, { verb: string; target: string; at: number }[]>();
    for (const e of evidence) {
      const target = e.path ?? (e.remote ? `${e.remote}${e.port ? `:${e.port}` : ''}` : null);
      if (!e.executable || !target) continue;
      const verb = e.kind.includes('credential') ? 'read' : e.kind.includes('persistence') ? 'set to start at login' : e.remote ? 'connected to' : e.kind.includes('archive') ? 'made archive' : e.kind.includes('unlink') ? 'removed' : 'changed';
      const list = links.get(e.executable) ?? [];
      if (!list.some((l) => l.verb === verb && l.target === target)) list.push({ verb, target, at: e.at });
      links.set(e.executable, list);
    }
    return <>
      <h4 className="ct-label">ATTACK STAGES SEEN · MITRE ATT&amp;CK</h4>
      <div className="ct-sec-stages">{seen.map((stage) => <span key={stage.name} className={stage.hit.length ? 'on' : ''} title={stage.tactic}>
        <span className="ct-label">{stage.name}</span><small>{stage.hit.length ? `${stage.hit.length} · ${stage.hit[0]!.kind.replace(/_/g, ' ')}` : 'not seen'}</small>
      </span>)}</div>
      <h4 className="ct-label">INVESTIGATION · NIST SP 800-61</h4>
      <ol className="ct-sec-steps">{steps.map(([name, done, note], index) => <li key={name} className={done ? 'done' : ''}><span className="ct-label">{index + 1} · {name}{done ? ' ✓' : ''}</span><small>{note}</small></li>)}</ol>
      {links.size > 0 && <><h4 className="ct-label">WHAT CONNECTED TO WHAT</h4>
        <ul className="ct-sec-links">{[...links].slice(0, 8).map(([program, list]) => <li key={program}>
          <code dir="ltr">{program}</code>
          <ul>{list.slice(0, 8).map((link, index) => <li key={index}><span>{link.verb} →</span><code dir="ltr">{link.target}</code><time className="ct-faint" dateTime={iso(link.at)}>{date(link.at)?.toLocaleTimeString()}</time></li>)}</ul>
        </li>)}</ul></>}
    </>;
  }

  function alertView(entry: Item) {
    const alert = entry.alert!;
    const alertAct = (action: string) => void machineAlerts.act(alert.id, action).catch((cause) => setActionProblem(errorMessage(cause)));
    return <>
      <div className="ct-sec-detail-head"><h3 dir="auto">{alert.text}</h3><span className="ct-label ct-faint">{alert.kind.toUpperCase()} · {new Date(alert.at).toLocaleTimeString()}</span></div>
      <div className="ct-protection-actions">
        <button type="button" className="detent sm warn" onClick={() => ask(entry, 'ask')}>A · WHAT NOW?</button>
        <button type="button" className="detent sm" onClick={() => alertAct('snooze')}>SNOOZE 1 H</button>
        <button type="button" className="detent sm" onClick={() => alertAct('dismiss')}>IT'S FINE</button>
        <button type="button" className="detent sm" onClick={() => alertAct('ignore_kind')}>NEVER THIS KIND</button>
      </div>
    </>;
  }

  function incidentView(entry: Item, base: SecurityIncident) {
    const incident = details.get(base.id) && details.get(base.id)!.revision >= base.revision ? details.get(base.id)! : base;
    const evidence = evidenceFor(incident);
    const ids = new Set(evidence.map((e) => e.id));
    const investigation = incident.investigation;
    const target = stopTarget(incident);
    const confirming = sameTarget(confirmStop, target);
    const excepted = exceptions.some((e) => e.incident_key === incident.key);
    const evidenceLimit = timelineLimits[incident.id] ?? 15;
    const timeline = evidence.slice(0, evidenceLimit);
    const focused = evidence.find((e) => e.id === focusedEvidence[incident.id]);
    if (focused && !timeline.some((e) => e.id === focused.id)) timeline.push(focused);
    return <>
      <div className="ct-sec-detail-head"><h3 dir="auto">{incident.title}</h3><span className="ct-label ct-faint">{incident.state === 'dismissed' ? 'DISMISSED' : excepted ? 'MUTED 1 H' : priority(incident.severity)} · {plural(evidence.length, 'observation')}</span></div>
      <p className="ct-protection-meta">First {time(incident.first_at)} · last {time(incident.last_at)}</p>
      {detailProblem[incident.id] && <p className="ct-asec-note ct-warn" role="status">The full incident could not be read: {detailProblem[incident.id]}. <button type="button" className="detent sm" onClick={() => void loadIncident(incident.id)}>RETRY</button></p>}
      {caseView(incident, evidence)}
      <div className="ct-protection-investigation">
        <h4 className="ct-label ct-blue">THE MODEL'S READ{investigation ? ` · ${investigation.state.toUpperCase()}` : ''}</h4>
        {!investigation && <p className="ct-asec-note">Not investigated yet.</p>}
        {investigation?.state === 'queued' && <p className="ct-asec-note" role="status">Waiting for the local model. Detection keeps running.</p>}
        {investigation?.state === 'running' && <p className="ct-asec-note" role="status">Checking the evidence with read-only tools.</p>}
        {investigation?.error && <p className="ct-asec-note ct-warn" role="status">{investigation.error}</p>}
        {investigation && investigation.summary.length > 0 && <Claims claims={investigation.summary} ids={ids} onEvidence={(id) => goToEvidence(incident.id, id)} />}
        {investigation && investigation.alternatives.length > 0 && <><h5 className="ct-label">COULD ALSO BE</h5><Claims claims={investigation.alternatives} ids={ids} onEvidence={(id) => goToEvidence(incident.id, id)} /></>}
        {investigation && investigation.unknowns.length > 0 && <><h5 className="ct-label">STILL UNKNOWN</h5><ul className="ct-protection-claims">{investigation.unknowns.slice(0, 8).map((text, index) => <li key={index} dir="auto">{text}</li>)}</ul></>}
        {investigation && investigation.next_steps.length > 0 && <><h5 className="ct-label">NEXT STEPS</h5><ol className="ct-protection-claims">{investigation.next_steps.slice(0, 5).map((text, index) => <li key={index} dir="auto">{text}</li>)}</ol></>}
      </div>
      <div className="ct-protection-actions">
        <button type="button" className="detent sm warn" onClick={() => ask(entry, 'ask')}>A · ASK</button>
        <button type="button" className="detent sm" disabled={configurationDisabled || !status?.config.investigate || ['running', 'queued'].includes(investigation?.state ?? '')} title={status?.config.investigate ? 'Read-only checks with the local model' : 'Turn on AI investigation under Coverage first'} onClick={() => void act(incident.id, 'investigate')}>I · INVESTIGATE</button>
        <button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void act(incident.id, incident.state === 'dismissed' ? 'reopen' : 'dismiss')}>{incident.state === 'dismissed' ? 'REOPEN' : 'DISMISS'}</button>
        <button type="button" className="detent sm" disabled={configurationDisabled} title="Mutes only these recorded patterns of this exact program for one hour. New behaviour and higher severity still alert; collection continues." onClick={() => void act(incident.id, 'allow_hour')}>MUTE THESE 1 H</button>
        {target && <button type="button" className="detent sm warn" disabled={configurationDisabled} onClick={() => setConfirmStop(confirming ? null : target)}>STOP PROCESS…</button>}
        {containment(evidence).map((step) => <button key={step.command} type="button" className="detent sm warn" title={`${step.title}. Goes on the Line for you to read and run.`} onClick={() => onCommand(step.command)}>{step.label}</button>)}
        <button type="button" className="detent sm" onClick={() => void copyReport(incident, evidence)}>{reported === incident.id ? 'REPORT COPIED' : 'R · REPORT AS TEXT'}</button>
      </div>
      {confirming && target && <div className="ct-protection-confirm" role="group" aria-label="Confirm stopping this process">
        <p>Stop <code dir="ltr">{target.executable}</code> (PID {target.pid}, started {time(target.started * 1000)})? This may interrupt work or lose unsaved changes. CT checks this exact process again before acting.</p>
        <div className="ct-protection-actions"><button type="button" className="detent sm warn" disabled={configurationDisabled} onClick={() => void mutate(`${incident.id}:stop`, 'system.incident.act', { id: target.id, action: 'stop_process', confirm: true, expected_revision: target.revision, expected_pid: target.pid, expected_process_started: target.started, expected_executable: target.executable, expected_process_started_us: target.startedUs, expected_process_version: target.processVersion })}>CONFIRM STOP PID {target.pid}</button><button type="button" className="detent sm" onClick={() => setConfirmStop(null)}>CANCEL</button></div>
      </div>}
      <h4 className="ct-label">WHAT WAS SEEN</h4>
      {(incident.omitted_observations ?? 0) > 0 && <p className="ct-asec-note">{count(incident.omitted_observations ?? 0)} older observations were dropped by the retention limit.</p>}
      <ol className="ct-protection-timeline">{timeline.map((entry) => <li key={entry.id} id={`${prefix}-${incident.id}-${entry.id}`} tabIndex={-1}>
        <div className="ct-protection-evidence-meta"><time dateTime={iso(entry.at)} title={time(entry.at)}>{time(entry.at)}</time><span>{entry.source}</span><code>{entry.id}</code>{entry.count > 1 && <span>×{count(entry.count)}</span>}</div>
        <p dir="auto">{entry.summary}</p>
        {(entry.executable || entry.path || entry.remote) && <dl className="ct-protection-facts">
          {entry.executable && <><dt>Program</dt><dd><code dir="ltr">{entry.executable}</code>{entry.pid ? ` · PID ${entry.pid}` : ''}</dd></>}
          {entry.path && <><dt>File</dt><dd><code dir="ltr">{entry.path}</code></dd></>}
          {entry.remote && <><dt>Address</dt><dd><code dir="ltr">{entry.remote}{entry.port ? ` · port ${entry.port}` : ''}</code></dd></>}
        </dl>}
      </li>)}</ol>
      {evidence.length > evidenceLimit && evidenceLimit < MAX_TIMELINE && <button type="button" className="ct-seg" onClick={() => setTimelineLimits((current) => ({ ...current, [incident.id]: Math.min(MAX_TIMELINE, evidenceLimit + 25) }))}>{count(evidence.length - evidenceLimit)} MORE ▸</button>}
    </>;
  }

  function coverageView() {
    const config = status!.config;
    const toggle = (key: 'packet_watch' | 'deep_watch' | 'investigate', label: string, note: string) => <div className="ct-sec-switch">
      <button type="button" className="sw" aria-pressed={config[key]} aria-label={label} disabled={configurationDisabled} onClick={() => void configure({ [key]: !config[key] } as Partial<ProtectionConfig>)} />
      <span>{label}<small>{note}</small></span>
    </div>;
    return <div className="ct-sec-coverage">
      <p className="ct-asec-note" dir="auto">{status!.visibility}</p>
      <ul className="ct-protection-sensors" aria-label="Monitoring coverage">{[...broken, ...status!.sensors.filter((sensor) => !broken.includes(sensor))].slice(0, 32).map((sensor) => <li key={sensor.id}>
        <div className="ct-protection-sensor-head"><span className="ct-label">{sensor.label}</span><span className={`ct-label ct-protection-state ${sensor.state === 'active' ? '' : sensor.state === 'disabled' ? 'ct-faint' : 'ct-warn'}`}>{sensor.state || 'unknown'}</span></div>
        <p className="ct-asec-note" dir="auto">{sensor.detail}</p>
        {sensor.id === 'packet-watch' && sensor.state === 'unavailable' && !granting && <button type="button" className="detent sm warn" onClick={() => setGranting(true)}>HOW TO GRANT</button>}
        {sensor.id === 'packet-watch' && granting && <div className="ct-sec-grant">
          <p>Scan detection reads packet headers through macOS's capture devices (<code>/dev/bpf*</code>), which only root can read by default. CT never asks for administrator rights by itself. This command lets the admin group, which you are in, read them until the Mac restarts; for a permanent grant, install Wireshark's ChmodBPF. Scan detection starts within 30 seconds.</p>
          <pre dir="ltr">{GRANT_BPF}</pre>
          <div className="ct-protection-actions"><button type="button" className="detent sm warn" onClick={() => { onCommand(GRANT_BPF); setGranting(false); }}>PUT IT ON THE LINE</button><button type="button" className="detent sm" onClick={() => setGranting(false)}>CLOSE</button></div>
        </div>}
        <p className="ct-protection-meta">{date(sensor.last_at) ? <time dateTime={iso(sensor.last_at)} title={time(sensor.last_at)}>Last seen {ago(sensor.last_at)}</time> : 'Nothing seen yet'}{sensor.dropped > 0 && <span className="ct-warn"> · {count(sensor.dropped)} events lost</span>}</p>
      </li>)}</ul>
      {toggle('packet_watch', 'Watch for network scans', 'Packet metadata, when macOS allows capture.')}
      {toggle('deep_watch', 'Read deep activity events', 'Needs the native sensor: turning this on installs it once.')}
      {toggle('investigate', 'Investigate incidents with local AI', 'Read-only checks. The model never decides or acts.')}
      {status!.packet_capture_help && <p className="ct-asec-note" dir="auto">{status!.packet_capture_help}</p>}
      <details className="ct-protection-setup">
        <summary>Deep activity capture</summary>
        {status!.deep_service ? <p className="ct-asec-note">The sensor service is installed. It starts when the Mac starts, and CT reads its events while deep activity events are on. Nothing to run.</p>
        : status!.deep_install_command ? <p className="ct-asec-note">Turning on deep activity events opens the sensor's installer. macOS asks for your password once; after that the sensor starts with the Mac and CT reads it by itself.</p>
        : <p className="ct-asec-note">This build has no signed sensor: it needs Apple's Endpoint Security approval for the signing team first.</p>}
      </details>
      <details className="ct-protection-setup">
        <summary>Connect a network sensor log</summary>
        <p className="ct-asec-note">To see other devices, connect a local Suricata EVE or Zeek JSON log from your router or network sensor. CT only reads the file.</p>
        <form className="ct-protection-import" onSubmit={(event) => { event.preventDefault(); void addImport(); }}>
          <div className="ct-protection-field"><span className="ct-label">FORMAT</span><Menu label="" value={IMPORT_FORMATS[importKind]} disabled={configurationDisabled} items={(Object.keys(IMPORT_FORMATS) as ProtectionImport['kind'][]).map((kind) => ({ key: kind, label: IMPORT_FORMATS[kind], selected: kind === importKind, onSelect: () => setImportKind(kind) }))} /></div>
          <label><span className="ct-label">LOCAL LOG PATH</span><input type="text" value={importPath} maxLength={1024} spellCheck={false} autoComplete="off" placeholder="/absolute/path/to/sensor.jsonl" disabled={configurationDisabled || config.imports.length >= 4} onChange={(event) => setImportPath(event.target.value)} /></label>
          <button type="submit" className="detent sm" disabled={configurationDisabled || !importPath.trim() || config.imports.length >= 4}>CONNECT FILE</button>
        </form>
        <ul className="ct-protection-imports">{config.imports.slice(0, 4).map((entry) => <li key={`${entry.kind}:${entry.path}`}><span><span className="ct-label">{entry.kind}</span><code dir="ltr">{entry.path}</code></span><button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void configure({ imports: config.imports.filter((current) => current.path !== entry.path) })}>REMOVE</button></li>)}</ul>
      </details>
      {exceptions.length > 0 && <div className="ct-protection-exceptions"><h4 className="ct-label">MUTED FOR AN HOUR · {count(exceptions.length)}</h4>
        <ul>{exceptions.slice(0, 64).map((exception) => <li key={exception.id}>
          <div><p dir="auto">{incidents.find((entry) => entry.key === exception.incident_key)?.title || 'A recorded incident'}</p><p className="ct-protection-meta">until {time(exception.expires_at)} · up to {exception.max_severity || 'recorded'} severity</p></div>
          <button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void act(exception.id, 'revoke_exception')}>REVOKE</button>
        </li>)}</ul></div>}
      <LookupKeys />
    </div>;
  }
}

/** Sweep groups, live incidents and machine alerts as one list, open and worst first. */
function itemsOf(report: SweepReport | null, incidents: SecurityIncident[], alerts: Alert[]): Item[] {
  const items: Item[] = [];
  const groups = new Map<string, Finding[]>();
  for (const finding of report?.findings ?? []) {
    const group = finding.group || finding.source;
    groups.set(group, [...(groups.get(group) ?? []), finding]);
  }
  for (const [group, findings] of groups) {
    const open = findings.filter((finding) => !finding.ignored);
    const listed = (open.length ? open : findings).sort((a, b) => rank(a.severity) - rank(b.severity));
    const incident = incidents.find((entry) => entry.key === `group:${group}` && entry.state !== 'dismissed') ?? incidents.find((entry) => entry.key === `group:${group}`);
    const title = nameOf(group);
    items.push({
      key: group, kind: 'sweep', title, where: title === group ? '' : group, text: listed[0]!.text,
      severity: listed[0]!.severity, open: open.length > 0, last: incident?.last_at ?? report?.at ?? 0, count: listed.length,
      findings: listed, incident, decision: report?.decisions?.find((decision) => decision.group === group),
    });
  }
  for (const incident of incidents) {
    if (incident.key.startsWith('group:')) continue;
    items.push({ key: incident.id, kind: 'incident', title: incident.title, where: '', text: `${plural(incident.observations.length, 'linked observation')}`, severity: incident.severity, open: incident.state !== 'dismissed', last: incident.last_at, count: incident.observations.length, findings: [], incident });
  }
  // A security alert is also its incident (same title): listed once, as the incident.
  const titles = new Set(incidents.map((incident) => incident.title));
  for (const alert of alerts) {
    if (alert.dismissed || alert.kind === 'security-incident' || titles.has(alert.text)) continue;
    items.push({ key: alert.id, kind: 'alert', title: alert.text, where: '', text: alert.kind, severity: alert.severity, open: true, last: alert.at, count: 1, findings: [], alert });
  }
  return items.sort((a, b) => Number(b.open) - Number(a.open) || rank(a.severity) - rank(b.severity) || b.last - a.last);
}

/** An open issue as the question a person would ask about it. */
function questionOf(entry: Item): string {
  const cve = /CVE-\d{4}-\d+/.exec(entry.title)?.[0];
  if (cve) return `How do I fix ${cve}?`;
  if (entry.kind === 'incident') return `Is this an attack: ${entry.title}?`;
  if (entry.kind === 'sweep') return `What should I do about ${entry.title}?`;
  return `What does this mean: ${entry.title}?`;
}

/** A group's findings by the check that found them, worst first: one line per check, not one per file. */
function checksOf(findings: Finding[]): { id: string; source: string; findings: Finding[] }[] {
  const checks = new Map<string, { id: string; source: string; findings: Finding[] }>();
  for (const finding of findings) {
    const id = `${finding.source}:${finding.kind}`;
    const check = checks.get(id) ?? { id, source: finding.source, findings: [] };
    check.findings.push(finding);
    checks.set(id, check);
  }
  return [...checks.values()].sort((a, b) => rank(a.findings[0]!.severity) - rank(b.findings[0]!.severity) || b.findings.length - a.findings.length);
}

/** What the person chose before for findings from the same check about other things. */
function precedent(report: SweepReport | null, item: Item): { verdict: string; count: number; source: string } | null {
  const source = item.findings[0]?.source;
  if (!source) return null;
  const votes = new Map<string, number>();
  for (const finding of report?.findings ?? []) {
    if (finding.decision && finding.source === source && (finding.group || finding.source) !== item.key) votes.set(finding.decision, (votes.get(finding.decision) ?? 0) + 1);
  }
  const [verdict, count] = [...votes].sort((a, b) => b[1] - a[1])[0] ?? [];
  return verdict && count ? { verdict, count, source } : null;
}

/** New findings per bucket, one line per priority; the selected item's buckets shaded. */
function Chart({ history, highlight, label }: { history: History | null; highlight: number[]; label?: string }) {
  if (!history || history.series.length === 0) return <div className="ct-sec-chart"><p className="ct-asec-note">{history ? 'Nothing recorded yet.' : 'Loading…'}</p></div>;
  const n = history.series.length;
  const max = Math.max(1, ...history.series.flat());
  const points = (level: number) => history.series.map((row, x) => `${((x + 0.5) * 1000) / n},${(118 - ((row[level] ?? 0) / max) * 110).toFixed(1)}`).join(' ');
  const totals = [0, 1, 2, 3].map((level) => history.series.reduce((sum, row) => sum + (row[level] ?? 0), 0));
  const day = (at: number) => new Date(at).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' }).toUpperCase();
  const when = (at: number) => new Date(at).toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  const span = history.bucket_ms * n;
  const x = (at: number) => Math.min(1000, Math.max(0, ((at - history.since) / span) * 1000));
  const markers = history.markers ?? [];
  return <div className="ct-sec-chart">
    <svg viewBox="0 0 1000 120" preserveAspectRatio="none" role="img" aria-label={`Since ${new Date(history.since).toLocaleString()}: ${totals[0]} act now, ${totals[1]} soon, ${totals[2]} watch, ${totals[3]} noted${label && highlight.length ? `; ${label} shaded` : ''}`}>
      {highlight.map((bucket) => <rect key={bucket} className="hit" x={(bucket * 1000) / n} y={0} width={1000 / n} height={120} />)}
      {[3, 2, 1, 0].map((level) => <polyline key={level} className={`k${level}`} points={points(level)} />)}
      {markers.map((marker) => <line key={`${marker.at}${marker.text}`} className="mark" x1={x(marker.at)} x2={x(marker.at)} y1={0} y2={120} />)}
    </svg>
    <div className="ct-sec-axis ct-label ct-faint"><span>{day(history.since)}</span><span>{day(history.since + (history.bucket_ms * n) / 2)}</span><span>NOW</span></div>
    {markers.length > 0 && <ul className="ct-sec-markers" aria-label="What changed meanwhile">{markers.map((marker) => <li key={`${marker.at}${marker.text}`}><time dateTime={iso(marker.at)}>{when(marker.at)}</time><span dir="auto">{marker.text}</span></li>)}</ul>}
  </div>;
}

/** Where in the chart's span an item had anything, as ticks. */
function Hits({ hits, buckets }: { hits: number[]; buckets: number }) {
  return <svg className="ct-sec-hits" viewBox={`0 0 ${Math.max(1, buckets)} 10`} preserveAspectRatio="none" aria-hidden="true">
    {hits.map((bucket) => <rect key={bucket} x={bucket} y={0} width={1} height={10} />)}
  </svg>;
}

/** What is true, how far it reaches, how long; and in words what that does. Enter decides, Escape
 *  cancels, E F R W pick the verdict. */
function DecideSheet({ item, before, busy, onCancel, onDecide }: { item: Item; before: { verdict: string; count: number; source: string } | null; busy: boolean; onCancel: () => void; onDecide: (verdict: string, keys: string[], days: number) => void }) {
  const [verdict, setVerdict] = useState(before?.verdict ?? '');
  const [whole, setWhole] = useState(true);
  const [days, setDays] = useState(0);
  const first = useRef<HTMLButtonElement>(null);
  useEffect(() => first.current?.focus(), []);
  const open = item.findings.filter((finding) => !finding.ignored);
  const keys = whole ? [] : open.map((finding) => finding.key);
  const apply = () => { if (verdict && !busy) onDecide(verdict, keys, days); };
  const onKey = (event: KeyboardEvent<HTMLElement>) => {
    if ((event.target as HTMLElement).closest('input,textarea,select') || event.metaKey || event.ctrlKey || event.altKey) return;
    const picked = VERDICTS.find(([, key]) => key === event.key.toLowerCase());
    if (picked) setVerdict(picked[0]);
    else if (event.key === 'Enter') apply();
    else if (event.key === 'Escape') onCancel();
    else return;
    event.preventDefault();
    event.stopPropagation();
  };
  const worst = priority(open[0]?.severity ?? 'info').toLowerCase();
  return <div className="ct-sec-decide" role="group" aria-label={`Decide about ${item.title}`} onKeyDown={onKey}>
    <div className="ct-sec-detail-head"><h3 dir="auto">Decide: {item.title}</h3><span className="ct-label ct-faint">{plural(open.length, 'finding')}</span></div>
    {before && <p className="ct-sec-before">Last time, for {plural(before.count, 'finding')} from {before.source}, you chose <b>{verdictName(before.verdict)}</b>. It is picked; change it if this one is different.</p>}
    <h4 className="ct-label">1 · WHAT IS TRUE?</h4>
    <div className="ct-sec-verdicts">{VERDICTS.map(([id, key, name, note], index) => <button key={id} ref={index === 0 ? first : undefined} type="button" aria-pressed={verdict === id} onClick={() => setVerdict(id)}>
      <span className="ct-label">{key.toUpperCase()} · {name}</span><span>{note}</span>
    </button>)}</div>
    <h4 className="ct-label">2 · HOW FAR?</h4>
    <div className="ct-sec-scope">
      <button type="button" aria-pressed={whole} onClick={() => setWhole(true)}><b>Everything about {item.title}</b> up to {worst}. New findings about it are covered too; a worse one shows again.</button>
      <button type="button" aria-pressed={!whole} onClick={() => setWhole(false)}><b>Only these {plural(open.length, 'finding')}.</b> Any other finding about it shows again.</button>
    </div>
    <h4 className="ct-label">3 · HOW LONG?</h4>
    <div className="ct-sec-tabs">{([[0, 'NO END'], [30, '30 DAYS']] as const).map(([value, name]) => <button key={value} type="button" className={`ct-seg${days === value ? ' on' : ''}`} onClick={() => setDays(value)}>{name}</button>)}</div>
    <p className="ct-sec-what">{verdict ? `${verdictName(verdict).toLowerCase().replace(/^./, (c) => c.toUpperCase())}: ` : ''}{whole ? `these findings and new ones about ${item.title} move to Decided` : `these ${plural(open.length, 'finding')} move to Decided`}{days ? ' for 30 days' : ', until you undo it'}. The checks keep running and nothing is deleted.{verdict === 'vendor' ? ' When an update fixes it, the next sweep closes it.' : ''}</p>
    <div className="ct-protection-actions">
      <button type="button" className="detent sm warn" disabled={!verdict || busy} onClick={apply}>↵ · DECIDE</button>
      <button type="button" className="detent sm" onClick={onCancel}>ESC · CANCEL</button>
    </div>
  </div>;
}

/** The hash lookups' keys (`system.keys.*`): kept in the Keychain by the system plugin, which
 *  only says which are set; a value typed here goes there and is not shown again. */
const LOOKUP_KEYS = [['virustotal', 'VIRUSTOTAL'], ['abusech', 'ABUSE.CH']] as const;
type KeysStatus = Record<(typeof LOOKUP_KEYS)[number][0], boolean>;

function LookupKeys() {
  const client = useRuntime().client;
  const [status, setStatus] = useState<KeysStatus | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    client.call<KeysStatus>('system.keys.status', {}).then(setStatus).catch((cause) => setProblem(errorMessage(cause)));
  }, [client]);
  const save = (name: string, value: string) => {
    setProblem(null);
    client.call<KeysStatus>('system.keys.set', { name, value }).then((next) => {
      setStatus(next);
      setValues((current) => ({ ...current, [name]: '' }));
    }).catch((cause) => setProblem(errorMessage(cause)));
  };
  return (
    <div className="ct-sec-keys">
      <h4 className="ct-label">LOOKUP KEYS · HASH REPUTATION · KEPT IN THE KEYCHAIN</h4>
      {LOOKUP_KEYS.map(([name, label]) => (
        <form key={name} className="ct-find" onSubmit={(event) => { event.preventDefault(); save(name, values[name] ?? ''); }}>
          <span className="ct-label" style={{ flex: '0 0 84px' }}>{label}</span>
          <span className={`ct-label ${status?.[name] ? '' : 'ct-faint'}`} style={{ flex: '0 0 60px' }}>{status ? (status[name] ? 'SET' : 'NOT SET') : '…'}</span>
          <input type="password" value={values[name] ?? ''} placeholder={status?.[name] ? 'replace the key' : 'paste the key'} autoComplete="off" spellCheck={false} onChange={(event) => setValues((current) => ({ ...current, [name]: event.target.value }))} />
          <button type="submit" className="detent sm" disabled={!(values[name] ?? '').trim()}>SAVE</button>
          {status?.[name] && <button type="button" className="detent sm" onClick={() => save(name, '')}>REMOVE</button>}
        </form>
      ))}
      {problem && <p className="ct-asec-note ct-warn">{problem}</p>}
    </div>
  );
}
