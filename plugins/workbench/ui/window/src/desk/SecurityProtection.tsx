/** Local protection controls. Sensor/model text is rendered as text, never HTML or commands. */
import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { ago, errorMessage, useRuntime } from '@cortex/sdk';
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
  exceptions: SecurityException[]; deep_capture_command?: string | null; deep_install_command?: string | null;
  packet_capture_help: string; visibility: string;
}
interface StopTarget {
  id: string; revision: number; pid: number; started: number; executable: string;
  startedUs?: number; processVersion?: number;
}

const POLL_MS = 8_000;
const RPC_MS = 20_000;
const PAGE = 12;
const MAX_TIMELINE = 100;
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
  if (!identities.length) return null;
  const first = identities[0];
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

/** Extends the existing AlertsPane. No new app shell, routes or privilege prompts. */
export function SecurityProtection() {
  const { client, node } = useRuntime();
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
  const [refreshing, setRefreshing] = useState(false);
  const [actionUncertain, setActionUncertain] = useState(false);
  const [loadProblem, setLoadProblem] = useState<string | null>(null);
  const [actionProblem, setActionProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [details, setDetails] = useState<Map<string, SecurityIncident>>(new Map());
  const [detailProblem, setDetailProblem] = useState<Record<string, string>>({});
  const [showDismissed, setShowDismissed] = useState(false);
  const [limit, setLimit] = useState(PAGE);
  const [timelineLimits, setTimelineLimits] = useState<Record<string, number>>({});
  const [focusedEvidence, setFocusedEvidence] = useState<Record<string, string>>({});
  const [importKind, setImportKind] = useState<ProtectionImport['kind']>('suricata');
  const [importPath, setImportPath] = useState('');
  const [confirmStop, setConfirmStop] = useState<StopTarget | null>(null);
  const [copied, setCopied] = useState<'capture' | 'install' | null>(null);
  const [copyProblem, setCopyProblem] = useState<string | null>(null);

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
    setRefreshing(true);
    const currentGeneration = generation.current;
    const version = ++requestVersion.current;
    try {
      const next = await rpc<ProtectionStatus>('system.protection.status', {});
      if (mounted.current && currentGeneration === generation.current && version === requestVersion.current) accept(next);
    } catch (cause) {
      if (mounted.current && currentGeneration === generation.current && version === requestVersion.current) setLoadProblem(errorMessage(cause));
    } finally {
      if (currentGeneration === generation.current) { reading.current = false; if (mounted.current) { setLoading(false); setRefreshing(false); } }
    }
  }, [rpc, accept]);

  useEffect(() => {
    mounted.current = true;
    const currentGeneration = ++generation.current;
    requestVersion.current++;
    reading.current = false;
    busyRef.current = false;
    statusRef.current = null;
    setStatus(null); setLoading(true); setRefreshing(false); setActionUncertain(false); setLoadProblem(null); setActionProblem(null); setBusy(null);
    setExpanded(new Set()); setDetails(new Map()); setDetailProblem({}); setConfirmStop(null);
    setImportPath(''); setLimit(PAGE); setTimelineLimits({}); setFocusedEvidence({}); setCopied(null); setCopyProblem(null);
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

  const toggleIncident = (id: string) => {
    const opening = !expanded.has(id);
    setExpanded((current) => { const next = new Set(current); if (opening) next.add(id); else next.delete(id); return next; });
    if (opening) void loadIncident(id);
    else if (confirmStop?.id === id) setConfirmStop(null);
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

  const copyCommand = async (kind: 'capture' | 'install') => {
    const command = kind === 'capture' ? statusRef.current?.deep_capture_command : statusRef.current?.deep_install_command;
    if (!command) return;
    const currentGeneration = generation.current;
    setCopyProblem(null); setCopied(null);
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable. Select and copy the command below.');
      await navigator.clipboard.writeText(command);
      if (mounted.current && currentGeneration === generation.current) setCopied(kind);
    } catch (cause) { if (mounted.current && currentGeneration === generation.current) setCopyProblem(errorMessage(cause)); }
  };

  const hasProblem = !!loadProblem;
  const stale = !!status && Date.now() - status.at > 30_000;
  const shown = incidents.filter((entry) => showDismissed || entry.state !== 'dismissed');
  const open = incidents.filter((entry) => entry.state !== 'dismissed').length;
  const exceptions = (status?.exceptions ?? []).filter((entry) => entry.expires_at > Date.now());
  const configurationDisabled = !!busy || hasProblem || stale || actionUncertain;

  return <section ref={section} className="ct-asec ct-protection" aria-labelledby={`${prefix}-heading`}>
    <header className="ct-asec-head ct-protection-head">
      <h2 className="ct-label" id={`${prefix}-heading`}>PROTECTION</h2>
      <span className="ct-label ct-faint">{loading && !status ? 'LOADING…' : hasProblem ? 'UNAVAILABLE' : stale ? 'STALE' : status ? `${count(open)} OPEN` : 'UNAVAILABLE'}</span>
      <span className="grow" />
      <button type="button" className="detent sm" disabled={!!busy || refreshing} onClick={() => void refresh()}>{refreshing ? 'REFRESHING…' : 'REFRESH'}</button>
    </header>
    {loadProblem && <p className="ct-asec-note ct-warn" role="status">Protection status could not be refreshed: {loadProblem}. {status ? 'The last known status is shown below.' : 'Monitoring coverage is unknown.'}</p>}
    {stale && !hasProblem && <p className="ct-asec-note ct-warn" role="status">This status is more than 30 seconds old. Refresh before changing protection.</p>}
    {actionProblem && <p className="ct-asec-note ct-warn" role="alert">{actionProblem}</p>}
    {busy && <p className="ct-asec-note" role="status">Applying your action…</p>}
    {status && <>
      <p className="ct-asec-note ct-protection-visibility" dir="auto">{status.visibility || 'Visibility has not been reported. Coverage is unknown.'}</p>
      <ul className="ct-protection-sensors" aria-label="Monitoring coverage">{status.sensors.slice(0, 32).map((sensor) => <li key={sensor.id}>
        <div className="ct-protection-sensor-head"><span className="ct-label">{sensor.label}</span><span className={`ct-label ct-protection-state ${sensor.state === 'active' ? '' : sensor.state === 'disabled' ? 'ct-faint' : 'ct-warn'}`}>{sensor.state || 'unknown'}</span></div>
        <p className="ct-asec-note" dir="auto">{sensor.detail || 'No coverage details were reported.'}</p>
        <p className="ct-protection-meta">{date(sensor.last_at) ? <time dateTime={iso(sensor.last_at)} title={time(sensor.last_at)}>Last observation {ago(sensor.last_at)}</time> : 'No observations recorded'}{sensor.dropped > 0 && <span className="ct-warn"> · {count(sensor.dropped)} events lost or skipped</span>}</p>
      </li>)}</ul>
      {status.sensors.length === 0 && <p className="ct-asec-note ct-warn">No sensor health was reported. Monitoring coverage is unknown.</p>}

      <details className="ct-protection-settings">
        <summary className="ct-label">MONITORING SETTINGS</summary>
        <fieldset disabled={configurationDisabled} className="ct-protection-options">
          <legend className="ct-protection-sr">Protection monitoring settings</legend>
          <label><input type="checkbox" checked={status.config.packet_watch} onChange={(event) => void configure({ packet_watch: event.target.checked })} /><span>Watch for network scans<small>Uses packet metadata when macOS permits capture.</small></span></label>
          <label><input type="checkbox" checked={status.config.deep_watch} onChange={(event) => void configure({ deep_watch: event.target.checked })} /><span>Read deep activity events<small>Requires the separately authorized capture below.</small></span></label>
          <label><input type="checkbox" checked={status.config.investigate} onChange={(event) => void configure({ investigate: event.target.checked })} /><span>Investigate incidents with local AI<small>Read-only checks. The model does not authorize actions.</small></span></label>
        </fieldset>
        {status.packet_capture_help && <p className="ct-asec-note" dir="auto">{status.packet_capture_help}</p>}
        <details className="ct-protection-setup">
          <summary>Deep activity capture</summary>
          {status.deep_capture_command ? <>
            <p className="ct-asec-note">The verified native sensor is installed. This command requests administrator permission in your terminal and keeps capture running there. Review it before running. CT copies it only; changing the setting above never runs it.</p>
            <pre className="ct-protection-command" tabIndex={0} aria-label="Deep activity capture command"><code>{status.deep_capture_command}</code></pre>
            <button type="button" className="detent sm" onClick={() => void copyCommand('capture')}>{copied === 'capture' ? 'COPIED' : 'COPY CAPTURE COMMAND'}</button>
          </> : status.deep_install_command ? <>
            <p className="ct-asec-note">Install the verified, signed native sensor first. This command opens the macOS installer. Installation and the required security permissions need your approval in macOS. Review the installer before approving it. CT copies this command only; it does not install or start the sensor.</p>
            <pre className="ct-protection-command" tabIndex={0} aria-label="Native sensor installer command"><code>{status.deep_install_command}</code></pre>
            <button type="button" className="detent sm" onClick={() => void copyCommand('install')}>{copied === 'install' ? 'COPIED' : 'COPY INSTALLER COMMAND'}</button>
            <p className="ct-asec-note">After installation and macOS approval, refresh protection to check sensor availability.</p>
          </> : <p className="ct-asec-note">Deep activity capture is unavailable. CT could not verify an installed sensor or a signed installer for this computer. The sensor details above explain the available coverage.</p>}
          {copyProblem && <p className="ct-asec-note ct-warn" role="status">{copyProblem}</p>}
        </details>
        <details className="ct-protection-setup">
          <summary>Connect a network sensor log</summary>
          <p className="ct-asec-note">To observe other devices, connect a local Suricata EVE or Zeek JSON connection log from your router or network sensor. CT reads the selected file; it does not configure the router or open a listening service. Existing log history is not treated as a live alert.</p>
          <form className="ct-protection-import" onSubmit={(event) => { event.preventDefault(); void addImport(); }}>
            <label><span className="ct-label">FORMAT</span><select value={importKind} disabled={configurationDisabled} onChange={(event) => setImportKind(event.target.value as ProtectionImport['kind'])}><option value="suricata">Suricata EVE JSON</option><option value="zeek">Zeek connection JSON</option></select></label>
            <label><span className="ct-label">LOCAL LOG PATH</span><input type="text" value={importPath} maxLength={1024} spellCheck={false} autoComplete="off" placeholder="/absolute/path/to/sensor.jsonl" disabled={configurationDisabled || status.config.imports.length >= 4} onChange={(event) => setImportPath(event.target.value)} /></label>
            <button type="submit" className="detent sm" disabled={configurationDisabled || !importPath.trim() || status.config.imports.length >= 4}>CONNECT FILE</button>
          </form>
          <ul className="ct-protection-imports">{status.config.imports.slice(0, 4).map((entry) => <li key={`${entry.kind}:${entry.path}`}><span><span className="ct-label">{entry.kind}</span><code dir="ltr">{entry.path}</code></span><button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void configure({ imports: status.config.imports.filter((current) => current.path !== entry.path) })}>REMOVE</button></li>)}</ul>
        </details>
      </details>

      <div className="ct-protection-incidents">
        <div className="ct-protection-list-head"><h3 className="ct-label">INCIDENTS</h3><label className="ct-protection-dismissed"><input type="checkbox" checked={showDismissed} onChange={(event) => { setShowDismissed(event.target.checked); setLimit(PAGE); }} />Show dismissed</label></div>
        {shown.length === 0 && <p className="ct-asec-note">{incidents.length ? 'No open incidents in the retained observations.' : 'No incidents recorded in the available observations.'} This does not establish that the Mac or network is safe.</p>}
        {shown.slice(0, limit).map((incident) => {
          const isOpen = expanded.has(incident.id);
          const evidence = evidenceFor(incident);
          const ids = new Set(evidence.map((entry) => entry.id));
          const investigation = incident.investigation;
          const target = stopTarget(incident);
          const confirming = sameTarget(confirmStop, target);
          const excepted = exceptions.some((entry) => entry.incident_key === incident.key);
          const evidenceLimit = timelineLimits[incident.id] ?? 15;
          const timeline = evidence.slice(0, evidenceLimit);
          const focused = evidence.find((entry) => entry.id === focusedEvidence[incident.id]);
          if (focused && !timeline.some((entry) => entry.id === focused.id)) timeline.push(focused);
          return <article key={incident.id} className={`ct-protection-incident ${tone(incident.severity)}`}>
            <button type="button" className="ct-protection-incident-toggle" aria-expanded={isOpen} aria-controls={`${prefix}-${incident.id}-detail`} onClick={() => toggleIncident(incident.id)}>
              <span className="ct-protection-incident-meta"><span className="ct-label sev">{incident.severity || 'unknown'}</span><time className="ct-label ct-faint" dateTime={iso(incident.last_at)} title={time(incident.last_at)}>{date(incident.last_at) ? ago(incident.last_at) : 'TIME UNKNOWN'}</time><span className="ct-label ct-faint">{incident.state === 'dismissed' ? 'DISMISSED' : excepted ? 'SCOPED MUTE' : investigation?.state === 'running' ? 'INVESTIGATING' : 'OPEN'}</span></span>
              <span className="ct-protection-incident-title" dir="auto">{incident.title}</span><span className="ct-protection-incident-hint">{isOpen ? 'Hide evidence' : `Review ${count(evidence.length)} retained observations`}{(incident.omitted_observations ?? 0) > 0 ? ` · ${count(incident.omitted_observations ?? 0)} older facts omitted` : ''}</span>
            </button>
            {isOpen && <div className="ct-protection-incident-detail" id={`${prefix}-${incident.id}-detail`}>
              <p className="ct-protection-meta">First observed {time(incident.first_at)} · Last observed {time(incident.last_at)}</p>
              {detailProblem[incident.id] && <p className="ct-asec-note ct-warn" role="status">The full incident could not be refreshed: {detailProblem[incident.id]}. Available evidence is shown below. <button type="button" className="detent sm" onClick={() => void loadIncident(incident.id)}>RETRY</button></p>}
              <h4 className="ct-label">OBSERVED ACTIVITY</h4>
              {(incident.omitted_observations ?? 0) > 0 && <p className="ct-asec-note">{count(incident.omitted_observations ?? 0)} older timeline facts were omitted by the retention limit. This retained timeline is not a complete audit log.</p>}
              <ol className="ct-protection-timeline">{timeline.map((entry) => <li key={entry.id} id={`${prefix}-${incident.id}-${entry.id}`} tabIndex={-1}>
                <div className="ct-protection-evidence-meta"><time dateTime={iso(entry.at)} title={time(entry.at)}>{time(entry.at)}</time><span>{entry.source}</span><code>{entry.id}</code>{entry.count > 1 && <span>Count: {count(entry.count)}</span>}</div>
                <p dir="auto">{entry.summary}</p>
                {(entry.executable || entry.path || entry.remote || entry.rule) && <dl className="ct-protection-facts">
                  {entry.executable && <><dt>Program</dt><dd><code dir="ltr">{entry.executable}</code>{entry.pid ? ` · PID ${entry.pid}` : ''}</dd></>}
                  {entry.path && <><dt>File</dt><dd><code dir="ltr">{entry.path}</code></dd></>}
                  {entry.remote && <><dt>Address</dt><dd><code dir="ltr">{entry.remote}{entry.port ? ` · port ${entry.port}` : ''}</code></dd></>}
                  {entry.rule && <><dt>Detection</dt><dd>{entry.rule}</dd></>}
                </dl>}
              </li>)}</ol>
              {evidence.length > evidenceLimit && <button type="button" className="detent sm" onClick={() => setTimelineLimits((current) => ({ ...current, [incident.id]: Math.min(MAX_TIMELINE, evidenceLimit + 25) }))} disabled={evidenceLimit >= MAX_TIMELINE}>{evidenceLimit >= MAX_TIMELINE ? '100 OBSERVATIONS SHOWN' : `SHOW MORE · ${count(evidence.length - evidenceLimit)} REMAINING`}</button>}
              <div className="ct-protection-investigation">
                <h4 className="ct-label">AI INVESTIGATION{investigation ? ` · ${investigation.state.toUpperCase()}` : ''}</h4>
                {!investigation && <p className="ct-asec-note">No AI investigation is recorded for this incident.</p>}
                {investigation && <>
                  {investigation.state === 'queued' && <p className="ct-asec-note" role="status">Waiting for the local model. Detection remains active.</p>}
                  {investigation.state === 'running' && <p className="ct-asec-note" role="status">Checking the recorded evidence with read-only tools.</p>}
                  {investigation.error && <p className="ct-asec-note ct-warn" role="status">{investigation.error}</p>}
                  {(investigation.state === 'failed' || investigation.state === 'unavailable') && !investigation.error && <p className="ct-asec-note ct-warn">The investigation did not complete. The observed activity above remains available.</p>}
                  {investigation.summary.length > 0 && <Claims claims={investigation.summary} ids={ids} onEvidence={(id) => goToEvidence(incident.id, id)} />}
                  {investigation.alternatives.length > 0 && <><h5 className="ct-label">POSSIBLE EXPLANATIONS</h5><Claims claims={investigation.alternatives} ids={ids} onEvidence={(id) => goToEvidence(incident.id, id)} /></>}
                  {investigation.unknowns.length > 0 && <><h5 className="ct-label">STILL UNKNOWN</h5><ul className="ct-protection-claims">{investigation.unknowns.slice(0, 8).map((entry, index) => <li key={index} dir="auto">{entry}</li>)}</ul></>}
                  {investigation.next_steps.length > 0 && <><h5 className="ct-label">SUGGESTED NEXT STEPS</h5><ol className="ct-protection-claims">{investigation.next_steps.slice(0, 5).map((entry, index) => <li key={index} dir="auto">{entry}</li>)}</ol></>}
                  {investigation.checked_at > 0 && <p className="ct-protection-meta">Investigated {time(investigation.checked_at)}. Suggestions have not been executed.</p>}
                </>}
              </div>
              <div className="ct-protection-actions">
                <button type="button" className="detent sm" disabled={configurationDisabled || !status.config.investigate || investigation?.state === 'running' || investigation?.state === 'queued'} title={status.config.investigate ? 'Run bounded read-only checks with the local model' : 'Enable AI investigation in Monitoring Settings first'} onClick={() => void act(incident.id, 'investigate')}>INVESTIGATE</button>
                <button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void act(incident.id, incident.state === 'dismissed' ? 'reopen' : 'dismiss')}>{incident.state === 'dismissed' ? 'REOPEN' : 'DISMISS'}</button>
                <button type="button" className="detent sm" disabled={configurationDisabled} title="Confirm muting only these recorded patterns for this exact entity for one hour. New behaviour and higher severity still alert. Observations continue." onClick={() => void act(incident.id, 'allow_hour')}>MUTE THESE 1 H</button>
                {target && <button type="button" className="detent sm warn" disabled={configurationDisabled} onClick={() => setConfirmStop(confirming ? null : target)}>STOP PROCESS…</button>}
              </div>
              {excepted && <p className="ct-asec-note">A temporary exception covers previously selected patterns for this entity. New behaviour or higher severity can still alert. “Mute these 1 h” replaces it with the patterns currently recorded.</p>}
              {confirming && target && <div className="ct-protection-confirm" role="group" aria-label="Confirm stopping this process">
                <p>Stop <code dir="ltr">{target.executable}</code> (PID {target.pid}, started {time(target.started * 1000)})? This may interrupt work or lose unsaved changes. CT will recheck this exact process before acting.</p>
                <div className="ct-protection-actions"><button type="button" className="detent sm warn" disabled={configurationDisabled} onClick={() => void mutate(`${incident.id}:stop`, 'system.incident.act', { id: target.id, action: 'stop_process', confirm: true, expected_revision: target.revision, expected_pid: target.pid, expected_process_started: target.started, expected_executable: target.executable, expected_process_started_us: target.startedUs, expected_process_version: target.processVersion })}>CONFIRM STOP PID {target.pid}</button><button type="button" className="detent sm" onClick={() => setConfirmStop(null)}>CANCEL</button></div>
              </div>}
            </div>}
          </article>;
        })}
        {shown.length > limit && <button type="button" className="detent sm" onClick={() => setLimit((current) => current + PAGE)}>SHOW MORE INCIDENTS · {count(shown.length - limit)} REMAINING</button>}
      </div>

      <details className="ct-protection-exceptions" open={exceptions.length > 0}>
        <summary className="ct-label">TEMPORARY EXCEPTIONS · {count(exceptions.length)}</summary>
        {exceptions.length === 0 && <p className="ct-asec-note">No active temporary exceptions.</p>}
        <ul>{exceptions.slice(0, 64).map((exception) => <li key={exception.id}>
          <div><p dir="auto">{incidents.find((entry) => entry.key === exception.incident_key)?.title || 'A recorded incident'}</p><p className="ct-protection-meta">{count(exception.observation_keys?.length ?? 0)} recorded patterns · up to {exception.max_severity || 'recorded'} severity · expires {time(exception.expires_at)}</p><p>{exception.reason || 'Only the selected recorded patterns for this exact entity are muted. New behaviour and higher severity are not covered.'}</p><details><summary>View exact entity</summary><code dir="ltr">{exception.incident_key}</code></details></div>
          <button type="button" className="detent sm" disabled={configurationDisabled} onClick={() => void act(exception.id, 'revoke_exception')}>REVOKE</button>
        </li>)}</ul>
      </details>
      <p className="ct-protection-meta">Status from {time(status.at)}. Evidence stays in this computer’s CT memory.</p>
    </>}
  </section>;
}
