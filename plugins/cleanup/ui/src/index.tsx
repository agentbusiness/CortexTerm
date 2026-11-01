/** The CLEANUP tab of the right pane: how full the disk is, what can come back (by kind, biggest
 * first), who is using what, and per find CLEAN · KEEP · NOT NOW · WHY. "Clean up with AI" shows
 * the local model's plan first: steps the plugin's rules allow, and suggestions left to the
 * person. Everything runs on the computer the pane is scoped to. */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { ago, definePlugin, errorMessage, useEvent, useRuntime, useSlotState } from '@cortex/sdk';
import './cleanup.css';

interface Decision { verdict: string; by: string; reason: string; at_ms: number; until_ms: number }
interface Item {
  id: string; path: string; title: string; kind: string; recipe: string; bytes: number; files: number; newest_ms: number;
  project: string; scope: 'whole' | 'stale' | 'copies'; safety: 'regenerable' | 'review'; state: string; in_use_by: string[];
  why: string; regenerate: string; how: string; copies: string[]; decision?: Decision | null;
}
interface Report {
  disk: { total: number; free: number };
  scan: { id: string; started_ms: number; finished_ms: number; files: number; bytes: number; stopped: boolean; skipped_kept: number } | null;
  running: boolean; items: Item[]; freed_bytes: number;
}
interface Progress { phase: string; files: number; bytes: number; folder: string; found: number; found_bytes: number }
interface PlannedStep { id: string; action: 'clean' | 'keep' | 'later'; reason: string; allowed: boolean; bytes: number }
interface Plan { steps: PlannedStep[]; freed: number }
interface Applied { outcomes: { id: string; ok: boolean; freed: number; detail: string }[]; freed: number }

const KINDS: [string, string][] = [['build', 'BUILD'], ['cache', 'CACHES'], ['agent', 'AGENTS'], ['duplicate', 'DUPES'], ['temp', 'TEMP'], ['model', 'MODELS'], ['stale', 'FORGOTTEN'], ['trash', 'TRASH']];
const PHASES: Record<string, string> = { places: 'KNOWN PLACES', walk: 'HOME FOLDER', duplicates: 'DUPLICATES', checks: 'WHO USES WHAT' };
const HOW: Record<string, string> = { delete: 'DELETED, COMES BACK', trash: 'TO THE TRASH', command: "TOOL'S OWN CLEAN", clone: 'COPIES BECOME CLONES', empty: 'EMPTIED FOR GOOD' };

function size(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}
const open = (item: Item) => item.state === 'open' || item.state === 'warm' || item.state === 'in_use';
const tilde = (path: string, home: string) => (home && path.startsWith(home) ? `~${path.slice(home.length)}` : path);
const homeOf = (items: Item[]) => {
  const match = items.map((item) => /^(\/Users\/[^/]+|\/home\/[^/]+)/.exec(item.path)?.[1]).find(Boolean);
  return match ?? '';
};

function Cleanup() {
  const { client } = useRuntime();
  const [report, setReport] = useState<Report | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [problem, setProblem] = useState('');
  const [filter, setFilter] = useSlotState<string>('filter', 'all');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState('');
  const [why, setWhy] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<Record<string, string>>({});
  const [plan, setPlan] = useState<Plan | null>(null);
  const [planning, setPlanning] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [note, setNote] = useState('');

  const load = useCallback(() => client.call<Report>('cleanup.status', {}).then((next) => { setReport(next); if (!next.running) setProgress(null); })
    .catch((error) => setProblem(errorMessage(error))), [client]);
  useEffect(() => { void load(); }, [load]);
  useEvent('cleanup.progress', (_topic, data) => setProgress(data as Progress));
  useEvent('cleanup.changed', () => void load());

  const items = report?.items ?? [];
  const home = useMemo(() => homeOf(items), [items]);
  const live = items.filter(open);
  const kept = items.filter((item) => !open(item));
  const byKind = useMemo(() => {
    const totals = new Map<string, number>();
    for (const item of live) totals.set(item.kind, (totals.get(item.kind) ?? 0) + item.bytes);
    return totals;
  }, [live]);
  const reclaimable = live.reduce((sum, item) => sum + item.bytes, 0);
  const shown = filter === 'kept' ? kept : live.filter((item) => filter === 'all' || item.kind === filter);
  const chosen = live.filter((item) => selected.has(item.id) && item.state !== 'in_use');
  const chosenBytes = chosen.reduce((sum, item) => sum + item.bytes, 0);

  const act = async (steps: { id: string; action: string; reason?: string }[], by: 'user' | 'ai' = 'user') => {
    setProblem(''); setNote(''); setConfirm('');
    setBusy((current) => ({ ...current, ...Object.fromEntries(steps.map((step) => [step.id, step.action])) }));
    try {
      const result = await client.call<Applied>('cleanup.apply', { steps, by }, { signal: AbortSignal.timeout(30 * 60_000) });
      const failed = result.outcomes.filter((outcome) => !outcome.ok);
      if (result.freed) setNote(`${size(result.freed)} freed${failed.length ? ` · ${failed.length} not done` : ''}`);
      if (failed.length) setProblem(failed.map((outcome) => `${tilde(items.find((item) => item.id === outcome.id)?.path ?? outcome.id, home)}: ${outcome.detail}`).join('\n'));
      setSelected((current) => { const next = new Set(current); steps.forEach((step) => next.delete(step.id)); return next; });
    } catch (error) { setProblem(errorMessage(error)); }
    finally {
      setBusy((current) => { const next = { ...current }; steps.forEach((step) => delete next[step.id]); return next; });
      void load();
    }
  };
  const scan = () => client.call<Report>('cleanup.scan', {}).then(setReport).catch((error) => setProblem(errorMessage(error)));
  const stop = () => client.call<Report>('cleanup.stop', {}).catch((error) => setProblem(errorMessage(error)));
  const explain = (item: Item) => {
    setWhy((current) => ({ ...current, [item.id]: '…' }));
    client.call<{ text: string }>('cleanup.explain', { id: item.id }, { signal: AbortSignal.timeout(200_000) })
      .then((result) => setWhy((current) => ({ ...current, [item.id]: result.text })))
      .catch((error) => setWhy((current) => ({ ...current, [item.id]: errorMessage(error) })));
  };
  const askPlan = () => {
    setPlanning(true); setPlan(null); setProblem('');
    client.call<Plan>('cleanup.plan', { ids: filter === 'all' || filter === 'kept' ? [] : live.filter((item) => item.kind === filter).map((item) => item.id) }, { signal: AbortSignal.timeout(15 * 60_000) })
      .then(setPlan).catch((error) => setProblem(errorMessage(error))).finally(() => setPlanning(false));
  };
  const applyPlan = () => {
    if (!plan) return;
    const steps = plan.steps.filter((step) => step.allowed).map(({ id, action, reason }) => ({ id, action, reason }));
    setPlan(null);
    void act(steps, 'ai');
  };
  const toggle = (id: string) => setSelected((current) => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  const twice = (key: string, run: () => void) => { if (confirm === key) run(); else setConfirm(key); };

  const disk = report?.disk;
  const used = disk ? disk.total - disk.free : 0;
  const scanInfo = report?.scan;
  const running = report?.running || !!progress && !scanInfo?.finished_ms;
  const byId = new Map(items.map((item) => [item.id, item]));

  return <section className="cu" aria-label="Disk cleanup">
    <header className="cu-head">
      <div className="cu-figure">
        <span className="cu-big">{size(reclaimable)}</span>
        <span className="ct-label">CAN COME BACK</span>
      </div>
      <span className="cu-grow" />
      {running
        ? <button type="button" className="detent sm" onClick={() => void stop()}>STOP</button>
        : <button type="button" className="detent sm" onClick={() => void scan()}>{scanInfo ? 'SCAN AGAIN' : 'SCAN'}</button>}
    </header>

    {disk && disk.total > 0 && <div className="cu-meter" role="img" aria-label={`${size(disk.free)} free of ${size(disk.total)}, ${size(reclaimable)} can come back`}>
      <div className="cu-bar">
        {KINDS.map(([kind]) => byKind.get(kind) ? <span key={kind} className={`cu-seg cu-k-${kind}`} style={{ width: `${Math.max(0.6, (byKind.get(kind)! / disk.total) * 100)}%` }} title={`${kind}: ${size(byKind.get(kind)!)}`} /> : null)}
        <span className="cu-seg cu-used" style={{ width: `${Math.max(0, ((used - reclaimable) / disk.total) * 100)}%` }} />
      </div>
      <p className="cu-meta">{size(disk.free)} FREE OF {size(disk.total)}{report && report.freed_bytes > 0 ? ` · ${size(report.freed_bytes)} FREED SO FAR` : ''}</p>
    </div>}

    {running && <div className="cu-progress" aria-live="polite">
      <p className="cu-meta"><span className="cu-pulse" aria-hidden="true" />{PHASES[progress?.phase ?? 'places'] ?? 'SCANNING'} · {(progress?.files ?? 0).toLocaleString()} FILES · {size(progress?.bytes ?? 0)} READ</p>
      <p className="cu-path">{progress?.folder ?? ''}</p>
    </div>}
    {!running && scanInfo?.finished_ms ? <p className="cu-meta">SCANNED {ago(scanInfo.finished_ms).toUpperCase()} · {scanInfo.files.toLocaleString()} FILES{scanInfo.skipped_kept ? ` · ${scanInfo.skipped_kept} KEPT, NOT READ` : ''}{scanInfo.stopped ? ' · STOPPED EARLY' : ''}</p> : null}
    {!running && !scanInfo && <p className="cu-hint">Scan to see what build output, caches, agent leftovers, old temporary files, forgotten folders and duplicate files hold. Nothing is removed until you say so.</p>}

    {live.length > 0 && <nav className="cu-kinds" aria-label="Kinds">
      <button type="button" className={`ct-seg${filter === 'all' ? ' on' : ''}`} onClick={() => setFilter('all')}>ALL</button>
      {KINDS.filter(([kind]) => byKind.get(kind)).map(([kind, label]) => <button key={kind} type="button" className={`ct-seg${filter === kind ? ' on' : ''}`} onClick={() => setFilter(kind)}>
        <span className={`cu-dot cu-k-${kind}`} aria-hidden="true" />{label} {size(byKind.get(kind)!)}</button>)}
      {kept.length > 0 && <button type="button" className={`ct-seg${filter === 'kept' ? ' on' : ''}`} onClick={() => setFilter('kept')}>KEPT {kept.length}</button>}
    </nav>}

    {live.length > 0 && !plan && <div className="cu-ai">
      <button type="button" className="detent sm warn" disabled={planning || running} onClick={askPlan}>{planning ? 'THE MODEL IS PLANNING…' : 'CLEAN UP WITH AI'}</button>
      <span className="cu-hint-sm">The model plans; it may clean only what comes back and is idle.</span>
    </div>}

    {plan && <div className="cu-plan" aria-label="The model's plan">
      <div className="cu-plan-head"><span className="ct-label">AI PLAN · FREES {size(plan.freed)}</span><span className="cu-grow" />
        <button type="button" className="detent sm warn" disabled={!plan.steps.some((step) => step.allowed)} onClick={applyPlan}>APPLY {plan.steps.filter((step) => step.allowed).length}</button>
        <button type="button" className="detent sm" onClick={() => setPlan(null)}>DISCARD</button></div>
      <ul>{plan.steps.map((step) => { const item = byId.get(step.id); return <li key={step.id} className={step.allowed ? '' : 'cu-suggest'}>
        <span className={`cu-verdict cu-v-${step.action}`}>{step.action === 'clean' ? 'CLEAN' : step.action === 'keep' ? 'KEEP' : 'NOT NOW'}</span>
        <span className="cu-plan-text"><b>{item?.title ?? step.id}</b> {size(step.bytes)}<br /><span className="cu-path">{item ? tilde(item.path, home) : ''}</span><br />{step.reason}
          {!step.allowed && <><br /><span className="ct-label">YOURS TO DECIDE</span></>}</span>
      </li>; })}</ul>
    </div>}

    {problem && <p className="cu-problem" role="alert">{problem}</p>}
    {note && <p className="cu-note" role="status">{note}</p>}

    <ul className="cu-list" aria-label="Finds">
      {shown.map((item) => {
        const isOpen = expanded === item.id;
        const doing = busy[item.id];
        const pick = selected.has(item.id);
        return <li key={item.id} className={`cu-item${pick ? ' cu-picked' : ''}${item.state === 'in_use' ? ' cu-busy' : ''}`}>
          <div className="cu-row">
            {open(item) && <button type="button" className="cu-mark" aria-pressed={pick} disabled={item.state === 'in_use'} aria-label={`Select ${item.title}`} onClick={() => toggle(item.id)} />}
            <button type="button" className="cu-main" aria-expanded={isOpen} onClick={() => setExpanded(isOpen ? '' : item.id)}>
              <span className="cu-title"><span className={`cu-dot cu-k-${item.kind}`} aria-hidden="true" />{item.title}{item.scope === 'stale' ? ' · older builds' : ''}</span>
              <span className="cu-path" title={item.path}>{tilde(item.path, home)}</span>
              <span className="cu-tags">
                {item.state === 'in_use' && <span className="cu-tag cu-tag-hot">IN USE</span>}
                {item.state === 'warm' && <span className="cu-tag">CHANGED {ago(item.newest_ms).toUpperCase()}</span>}
                {item.state === 'kept' && <span className="cu-tag">KEPT · NOT SCANNED</span>}
                {item.state === 'later' && item.decision && <span className="cu-tag">BACK {new Date(item.decision.until_ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }).toUpperCase()}</span>}
                {item.safety === 'review' && <span className="cu-tag">REVIEW</span>}
                {item.state === 'open' && item.newest_ms > 0 && <span className="cu-tag">{ago(item.newest_ms).toUpperCase()}</span>}
              </span>
            </button>
            <span className="cu-size">{size(item.bytes)}</span>
          </div>
          {isOpen && <div className="cu-detail">
            <p>{item.why}</p>
            {item.in_use_by.length > 0 && <p className="cu-hot">{item.in_use_by.join(' · ')}</p>}
            {item.regenerate && <p className="cu-meta">COMES BACK WITH <code>{item.regenerate}</code></p>}
            {item.project && <p className="cu-meta">PROJECT <span className="cu-path">{tilde(item.project, home)}</span></p>}
            {item.copies.length > 0 && <ul className="cu-copies">{item.copies.map((copy) => <li key={copy} className="cu-path">{tilde(copy, home)}</li>)}</ul>}
            <p className="cu-meta">{HOW[item.how] ?? item.how.toUpperCase()} · {item.files.toLocaleString()} FILE{item.files === 1 ? '' : 'S'}{item.decision ? ` · LAST: ${item.decision.verdict.toUpperCase()} BY ${item.decision.by.toUpperCase()}${item.decision.reason ? ` (${item.decision.reason})` : ''}` : ''}</p>
            {why[item.id] && <p className="cu-why">{why[item.id]}</p>}
            <div className="cu-actions">
              {open(item) && <button type="button" className="detent sm warn" disabled={!!doing || item.state === 'in_use'}
                onClick={() => item.how === 'empty' || item.safety === 'review' ? twice(item.id, () => void act([{ id: item.id, action: 'clean' }])) : void act([{ id: item.id, action: 'clean' }])}>
                {doing === 'clean' ? 'CLEANING…' : confirm === item.id ? (item.how === 'empty' ? 'EMPTY FOR GOOD?' : 'TO THE TRASH?') : 'CLEAN'}</button>}
              {open(item) && <button type="button" className="detent sm" disabled={!!doing} title="Intended: never offered or scanned again" onClick={() => void act([{ id: item.id, action: 'keep' }])}>KEEP</button>}
              {open(item) && <button type="button" className="detent sm" disabled={!!doing} title="Hidden for 30 days" onClick={() => void act([{ id: item.id, action: 'later' }])}>NOT NOW</button>}
              {!open(item) && <button type="button" className="detent sm" disabled={!!doing} onClick={() => void act([{ id: item.id, action: 'reset' }])}>LOOK AGAIN</button>}
              <button type="button" className="detent sm" disabled={why[item.id] === '…'} onClick={() => explain(item)}>{why[item.id] === '…' ? 'ASKING…' : 'WHAT IS IT?'}</button>
            </div>
          </div>}
        </li>;
      })}
    </ul>
    {report && !running && scanInfo && shown.length === 0 && <p className="cu-hint">{filter === 'kept' ? 'Nothing kept.' : 'Nothing to clean here.'}</p>}

    {chosen.length > 0 && <footer className="cu-foot">
      <span className="ct-label">{chosen.length} SELECTED · {size(chosenBytes)}</span><span className="cu-grow" />
      <button type="button" className="detent sm warn" onClick={() => twice('selected', () => void act(chosen.map((item) => ({ id: item.id, action: 'clean' }))))}>
        {confirm === 'selected' ? `CONFIRM · ${size(chosenBytes)}` : 'CLEAN SELECTED'}</button>
      <button type="button" className="detent sm" onClick={() => void act(chosen.map((item) => ({ id: item.id, action: 'later' })))}>NOT NOW</button>
    </footer>}
  </section>;
}

export default definePlugin({ slot: 'machine.cleanup@1', component: Cleanup });
