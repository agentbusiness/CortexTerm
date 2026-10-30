/**
 * Traces: a week of what a process tree did (`system.trace.*`, kept in IronGraph). The list of
 * traces kept, and one trace: its numbers, the tree over time with its phases and the processes as
 * they started, what it touched (a graph of programs, folders, hosts and ports), and the summary a
 * model reads as `trace://<id>`. Every Run is traced by itself; RECORD on Investigate traces any
 * other process; CortexCode traces the commands its agents run.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { ago, errorMessage, runtime } from '@cortex/sdk';
import type { TraceGraph, TraceInfo, TraceRecord, TraceSummary } from './api';
import { rate, seconds, shortPath, size } from './api';

type Ask = (text: string, intent: 'ask' | 'explain' | 'fix', runId?: string) => void;

export function Traces({ open, home, onOpen, onAsk, onOpenRun }: {
  open: string; home: string; onOpen: (id: string) => void; onAsk: Ask; onOpenRun: (runId: string) => void;
}) {
  return open ? <TraceView id={open} home={home} onClose={() => onOpen('')} onAsk={onAsk} onOpenRun={onOpenRun} /> : <TraceList home={home} onOpen={onOpen} />;
}

// --- the traces kept ----------------------------------------------------------------------------

function sourceOf(trace: TraceInfo): string {
  if (trace.source === 'run') return 'RUN';
  if (trace.source === 'record') return 'RECORDED';
  return (trace.asked_by || 'member').split(' ')[0]!.toUpperCase();
}

function TraceList({ home, onOpen }: { home: string; onOpen: (id: string) => void }) {
  const client = runtime().client;
  const [traces, setTraces] = useState<TraceInfo[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [filter, setFilter] = useState('ALL');
  useEffect(() => {
    let stopped = false;
    const load = () => client.call<{ traces: TraceInfo[] }>('system.trace.list', { limit: 200 })
      .then((list) => { if (!stopped) { setTraces(list?.traces ?? []); setProblem(null); } })
      .catch((cause) => { if (!stopped) setProblem(errorMessage(cause)); });
    void load();
    const timer = setInterval(load, 5000);
    return () => { stopped = true; clearInterval(timer); };
  }, [client]);

  const list = traces ?? [];
  const recording = list.filter((trace) => trace.ended == null).length;
  const sources = useMemo(() => {
    const counts = new Map<string, number>();
    for (const trace of list) counts.set(sourceOf(trace), (counts.get(sourceOf(trace)) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [list]);
  const shown = filter === 'ALL' ? list : list.filter((trace) => sourceOf(trace) === filter);

  return (
    <div className="ct-inv ct-traces" aria-label="Traces">
      <div className="ct-inv-meta ct-label ct-faint">
        <span>{list.length} KEPT</span><span>FOR 7 DAYS</span>
        <span className="grow" />
        {recording > 0 && <span className="ct-blue"><span className="ct-inv-pulse" aria-hidden />{recording} RECORDING</span>}
      </div>
      <div className="ct-side-head ct-trace-filter">
        <button type="button" className={`ct-seg${filter === 'ALL' ? ' on' : ''}`} onClick={() => setFilter('ALL')}>ALL</button>
        {sources.map(([source, count]) => (
          <button key={source} type="button" className={`ct-seg${filter === source ? ' on' : ''}`} onClick={() => setFilter(source)}>{source} {count}</button>
        ))}
      </div>
      {problem && <p className="ct-hint ct-warn">{problem}</p>}
      {traces == null && !problem && <p className="ct-hint">Reading the traces…</p>}
      {traces != null && shown.length === 0 && (
        <p className="ct-hint">No trace yet. A command that runs long enough to be seen in a terminal is traced by itself; RECORD on a process traces any other.</p>
      )}
      <div className="ct-trace-rows">
        {shown.map((trace) => {
          const live = trace.ended == null;
          const failed = trace.exit_code != null && trace.exit_code !== 0;
          return (
            <button key={trace.id} type="button" className="ct-trace-row" onClick={() => onOpen(trace.id)}>
              <span className="top">
                <span className="cmd ct-mono">{trace.label}</span>
                <span className="dur ct-mono">{seconds((trace.ended ?? Date.now()) - trace.started)}</span>
              </span>
              <span className="sub ct-label ct-faint">
                <span className={trace.source === 'member' ? 'ct-blue' : trace.source === 'record' ? 'ct-warn' : ''}>{sourceOf(trace)}</span>
                <span className="where">{trace.cwd ? shortPath(trace.cwd, home).toUpperCase() : `PID ${trace.pid}`}</span>
                <span className="grow" />
                {live ? <span className="rec">RECORDING</span> : <span className={failed ? 'ct-warn' : ''}>{trace.exit_code != null ? `EXIT ${trace.exit_code}` : 'ENDED'}</span>}
                <span>{ago(trace.started).toUpperCase()}</span>
              </span>
            </button>
          );
        })}
      </div>
      <p className="ct-inv-hint ct-label ct-faint">EVERY RUN IS TRACED · RECORD ON A PROCESS TRACES ANY OTHER · KEPT A WEEK IN IRONGRAPH</p>
    </div>
  );
}

// --- one trace ----------------------------------------------------------------------------------

function TraceView({ id, home, onClose, onAsk, onOpenRun }: { id: string; home: string; onClose: () => void; onAsk: Ask; onOpenRun: (runId: string) => void }) {
  const client = runtime().client;
  const [summary, setSummary] = useState<TraceSummary | null>(null);
  const [whole, setWhole] = useState<TraceSummary | null>(null);
  const [starts, setStarts] = useState<TraceRecord[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  const [zoom, setZoom] = useState<{ from: number; to: number } | null>(null);
  const [tab, setTab] = useState<'graph' | 'folders' | 'hosts' | 'log'>('graph');
  const [copied, setCopied] = useState(false);
  const live = whole != null && whole.trace.ended == null;

  useEffect(() => {
    let stopped = false;
    setSummary(null);
    setWhole(null);
    const load = () => summaryOf(id)
      .then((value) => { if (!stopped && value) { setWhole(value); setProblem(null); } })
      .catch((cause) => { if (!stopped) setProblem(errorMessage(cause)); });
    void load();
    const timer = setInterval(() => { if (!stopped) void load(); }, 5000);
    return () => { stopped = true; clearInterval(timer); };
  }, [id, client]);

  // A zoomed phase is its own summary (finer chart, its own peaks); the whole one otherwise.
  useEffect(() => {
    if (!zoom) { setSummary(whole); return; }
    let stopped = false;
    summaryOf(id, zoom.from, zoom.to)
      .then((value) => { if (!stopped && value) setSummary(value); }).catch(() => undefined);
    return () => { stopped = true; };
  }, [zoom, whole, id, client]);

  useEffect(() => {
    if (!whole) return;
    let stopped = false;
    client.call<{ records: TraceRecord[] }>('system.trace.read', { id, size: 'records', from: whole.from, to: whole.to, kinds: ['start'], limit: 2000 })
      .then((value) => { if (!stopped) setStarts(value?.records ?? []); }).catch(() => undefined);
    return () => { stopped = true; };
  }, [id, whole?.to, client]); // eslint-disable-line react-hooks/exhaustive-deps

  // The summary and the chart's points are two sizes of one read (`system.trace.read`).
  const summaryOf = (traceId: string, from?: number, to?: number) => Promise.all([
    client.call<TraceSummary>('system.trace.read', { id: traceId, size: 'summary', from, to }, { signal: AbortSignal.timeout(20_000) }),
    client.call<{ series: TraceSummary['series'] }>('system.trace.read', { id: traceId, size: 'series', from, to }, { signal: AbortSignal.timeout(20_000) }),
  ]).then(([summary, series]) => (summary ? { ...summary, series: series?.series ?? [] } : null));
  const stop = () => client.call('system.trace.stop', { id }).catch((cause) => setProblem(errorMessage(cause)));
  const remove = () => client.call('system.trace.delete', { id }).then(onClose).catch((cause) => setProblem(errorMessage(cause)));

  if (!summary || !whole) {
    return (
      <div className="ct-inv">
        <header className="ct-inv-head"><span className="ct-inv-name ct-mono">trace</span><span className="grow" /><button type="button" className="detent sm" onClick={onClose}>CLOSE</button></header>
        <p className="ct-hint">{problem ?? 'Reading the trace…'}</p>
      </div>
    );
  }
  const trace = whole.trace;
  const metric = (name: string) => summary.metrics.find((m) => m.name === name);
  const cpu = metric('cpu');
  const mem = metric('memory');
  const gpu = metric('gpu');
  const disk = metric('disk_write');
  const processes = summary.processes.reduce((sum, p) => sum + p.count, 0);
  const hosts = summary.touched.filter((t) => t.kind === 'host');
  const listens = summary.touched.filter((t) => t.kind === 'port');
  const at = (ms: number) => `+${seconds(Math.max(0, ms - whole.from))}`;

  return (
    <div className="ct-inv ct-trace" aria-label={`Trace ${trace.label}`}>
      <header className="ct-inv-head">
        <span className="ct-inv-name ct-mono" title={trace.command}>{trace.label}</span>
        <span className={`ct-inv-state ct-label ${live ? 'running' : 'ended'}`}>{live ? 'RECORDING' : 'ENDED'}</span>
        <span className="grow" />
        <button type="button" className="detent sm" onClick={onClose}>CLOSE</button>
      </header>
      <div className="ct-inv-meta ct-label ct-faint">
        <span>{trace.source === 'run' ? 'A RUN' : trace.source === 'record' ? 'RECORDED' : `ASKED BY ${trace.asked_by.toUpperCase()}`}</span>
        <span>{clock(trace.started)} → {trace.ended ? clock(trace.ended) : 'NOW'}</span>
        {trace.exit_code != null && <span className={trace.exit_code !== 0 ? 'ct-warn' : ''}>EXIT {trace.exit_code}</span>}
        <span>{trace.records.toLocaleString()} RECORDS</span>
      </div>
      {trace.cwd && <div className="ct-inv-cwd ct-label ct-faint">IN <span className="ct-mono">{shortPath(trace.cwd, home)}</span></div>}
      <div className="ct-inv-actions">
        <button type="button" className="detent sm warn" onClick={() => onAsk(explainQuestion(whole), 'explain')}>EXPLAIN</button>
        {trace.run_id && <button type="button" className="detent sm" onClick={() => onOpenRun(trace.run_id!)}>FULL LOG</button>}
        {live && <button type="button" className="detent sm" onClick={() => void stop()}>STOP</button>}
        <button type="button" className="detent sm" onClick={() => { void navigator.clipboard?.writeText(`trace://${trace.id}`); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>{copied ? 'COPIED' : 'COPY TRACE://'}</button>
        <button type="button" className="detent sm" onClick={() => void remove()}>DELETE</button>
      </div>
      {problem && <p className="ct-hint ct-warn">{problem}</p>}
      {trace.limits.map((limit) => <p key={limit} className="ct-hint">{limit}</p>)}

      <div className="ct-inv-tiles">
        <Stat label="CPU P95" value={cpu ? `${Math.round(cpu.p95)}%` : '–'} note={cpu ? `avg ${Math.round(cpu.avg)} · peak ${Math.round(cpu.max)} at ${at(cpu.max_at)}` : ''} hot={(cpu?.p95 ?? 0) > 80} />
        <Stat label="MEM PEAK" value={mem ? size(mem.max) : '–'} note={mem ? `at ${at(mem.max_at)} · avg ${size(mem.avg)}` : ''} />
        <Stat label="GPU" value={gpu && gpu.max >= 1 ? `${Math.round(gpu.p95)}%` : '0%'} note={gpu && gpu.max >= 1 ? `peak ${Math.round(gpu.max)}` : 'never used'} />
        <Stat label="PROCESSES" value={String(processes)} note={`${summary.processes.length} program${summary.processes.length === 1 ? '' : 's'}`} />
        <Stat label="DISK W" value={disk && disk.max > 0 ? rate(disk.max) : '0'} note={disk && disk.max > 0 ? `peak · avg ${rate(disk.avg)}` : 'nothing written'} />
        <Stat label="NETWORK" value={`${hosts.length} host${hosts.length === 1 ? '' : 's'}`} note={listens.length ? `listens on ${listens.map((l) => l.name).join(' ')}` : hosts[0]?.name ?? 'none seen'} />
      </div>

      <section className="ct-inv-sec">
        <div className="ct-side-head">
          <span className="ct-label ct-faint">OVER TIME</span>
          <span className="ct-inv-key ct-label"><span className="cpu">CPU</span><span className="mem">MEM</span><span className="k-run">PHASES</span><span className="k-start">CHILDREN</span></span>
          <span className="grow" />
          <button type="button" className={`ct-seg${zoom ? '' : ' on'}`} onClick={() => setZoom(null)}>WHOLE</button>
          <button type="button" className={`ct-seg${zoom ? ' on' : ''}`} disabled={!zoom} title="Pick a phase to zoom into it">ZOOM</button>
        </div>
        {summary.series.length < 2 ? <p className="ct-hint">The chart fills in as the tree is read (every 4 s).</p> : (
          <TraceChart summary={summary} starts={starts.filter((s) => s.at >= summary.from && s.at <= summary.to)} phases={whole.phases} />
        )}
      </section>

      <section className="ct-inv-sec">
        <div className="ct-side-head"><span className="ct-label ct-faint">PHASES · {whole.phases.length}</span><span className="grow" /><span className="ct-label ct-faint">FROM ONE-MINUTE ROLLUPS · CLICK TO ZOOM</span></div>
        {whole.phases.length === 0 ? <p className="ct-hint">No phases yet.</p> : (
          <div className="ct-inv-impact">
            {whole.phases.map((phase) => {
              const on = zoom?.from === phase.from;
              return (
                <button key={phase.from} type="button" className={`ct-inv-impact-row${on ? ' on' : ''}`} onClick={() => setZoom(on ? null : { from: phase.from, to: phase.to })}>
                  <span className="when ct-mono ct-faint">{clock(phase.from)} · {seconds(phase.to - phase.from)}</span>
                  <span className="cmd">{phase.busiest.length ? phase.busiest.join(', ') : 'idle'}</span>
                  <span className={`d ct-mono${phase.cpu >= 80 ? ' ct-warn' : ''}`}>{Math.round(phase.cpu)}% · {size(phase.memory)}</span>
                </button>
              );
            })}
          </div>
        )}
      </section>

      <section className="ct-inv-sec">
        <div className="ct-side-head">
          <span className="ct-label ct-faint">WHAT IT TOUCHED</span>
          <span className="grow" />
          {(['graph', 'folders', 'hosts', 'log'] as const).map((value) => (
            <button key={value} type="button" className={`ct-seg${tab === value ? ' on' : ''}`} onClick={() => setTab(value)}>{value.toUpperCase()}</button>
          ))}
        </div>
        {tab === 'graph' && <Graph id={id} home={home} refresh={whole.trace.records} />}
        {tab === 'folders' && <Touched list={summary.touched.filter((t) => t.kind === 'folder')} home={home} empty="No file seen open." />}
        {tab === 'hosts' && <Touched list={summary.touched.filter((t) => t.kind !== 'folder')} home={home} empty="No connection or listening port seen." />}
        {tab === 'log' && <Log id={id} from={summary.from} to={summary.to} home={home} />}
        <p className="ct-inv-hint ct-label ct-faint">FILES ARE GROUPED BY FOLDER, PROCESSES BY PROGRAM · READ EVERY 2 S, A FILE OPEN LESS THAN THAT IS NOT SEEN</p>
      </section>

      <section className="ct-inv-sec ct-trace-model">
        <div className="ct-side-head"><span className="ct-label">WHAT THE MODEL READS</span><span className="grow" /><span className="ct-label ct-faint ct-mono">trace://{trace.id}</span></div>
        {whole.errors.length > 0 && whole.errors.slice(0, 3).map((line) => <div key={line} className="ct-inv-flag ct-mono">{line}</div>)}
        <code className="ct-inv-cmd ct-mono ct-trace-text">{whole.text}</code>
      </section>
    </div>
  );
}

function Stat({ label, value, note, hot }: { label: string; value: string; note?: string; hot?: boolean }) {
  return (
    <div className="ct-tile">
      <div className="ct-tile-head"><span className="ct-faint">{label}</span><span className="grow" /><span className={hot ? 'ct-warn' : ''}>{value}</span></div>
      {note && <div className="ct-faint ct-tile-note" title={note}>{note}</div>}
    </div>
  );
}

// --- the chart ----------------------------------------------------------------------------------

const LANE = 44;
const GAP = 8;
const TOP = 14;

/** The tree's CPU (and GPU when used) and memory on one time axis; the phases as bands; a tick at
 *  the bottom for every process that started. Hover reads a moment. */
function TraceChart({ summary, starts, phases }: { summary: TraceSummary; starts: TraceRecord[]; phases: TraceSummary['phases'] }) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(320);
  const [hover, setHover] = useState<number | null>(null);
  useEffect(() => {
    const node = box.current;
    if (!node) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(160, Math.round(entry!.contentRect.width))));
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  const points = summary.series;
  const { from, to } = summary;
  const span = Math.max(1, to - from);
  const x = (at: number) => ((Math.min(Math.max(at, from), to) - from) / span) * width;
  const atOf = (px: number) => from + (px / width) * span;
  const cpuTop = Math.max(100, ...points.map((p) => p.cpu)) * 1.08;
  const memTop = Math.max(1, ...points.map((p) => p.memory)) * 1.12;
  const hasGpu = points.some((p) => (p.gpu ?? 0) >= 1);
  const lanes = [
    { key: 'cpu', label: 'CPU', top: cpuTop, value: (p: TraceSummary['series'][number]) => p.cpu, scale: `${Math.round(cpuTop)}%` },
    ...(hasGpu ? [{ key: 'gpu', label: 'GPU', top: 100, value: (p: TraceSummary['series'][number]) => p.gpu ?? 0, scale: '100%' }] : []),
    { key: 'mem', label: 'MEM', top: memTop, value: (p: TraceSummary['series'][number]) => p.memory, scale: size(memTop) },
  ];
  const ticksY = TOP + lanes.length * (LANE + GAP);
  const height = ticksY + 12;
  const laneY = (index: number) => TOP + index * (LANE + GAP);
  const reading = hover != null ? points.reduce((best, p) => (Math.abs(p.at - hover) < Math.abs(best.at - hover) ? p : best), points[0]!) : null;
  const bucket = span / Math.max(1, points.length);
  const near = reading ? starts.filter((s) => Math.abs(s.at - reading.at) <= bucket) : [];
  const names = [...new Set(near.map((s) => s.name).filter(Boolean))];

  const ticks = useMemo(() => {
    const minutes = span / 60_000;
    const step = (minutes > 120 ? 30 : minutes > 30 ? 10 : minutes > 10 ? 5 : minutes > 4 ? 1 : minutes > 1 ? 0.5 : 1 / 6) * 60_000;
    const out: number[] = [];
    for (let t = Math.ceil(from / step) * step; t <= to; t += step) out.push(t);
    return out;
  }, [from, to, span]);

  return (
    <div className="ct-inv-chart" ref={box}>
      <div className="ct-inv-readout ct-mono">
        {reading ? <>
          <span className="ct-faint">{clock(reading.at)}</span>
          <span className="cpu">CPU {Math.round(reading.cpu)}%</span>
          {hasGpu && <span className="gpu">GPU {Math.round(reading.gpu ?? 0)}%</span>}
          <span className="mem">MEM {size(reading.memory)}</span>
          {names.length > 0 && <span className="k-run">started {names.slice(0, 4).join(', ')}</span>}
        </> : <span className="ct-faint">Hover to read a moment · the phases are the orange bands</span>}
      </div>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="ct-inv-svg"
        onMouseMove={(event) => { const rect = event.currentTarget.getBoundingClientRect(); setHover(atOf(event.clientX - rect.left)); }}
        onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={TOP - 2} y2={ticksY} stroke="var(--rule)" />
            <text x={x(t) + 3} y={9} className="ct-inv-tick">{clock(t, true)}</text>
          </g>
        ))}
        {phases.filter((p) => p.to > from && p.from < to).map((phase, index) => {
          const x1 = x(phase.from);
          const x2 = Math.max(x1 + 1, x(phase.to));
          return (
            <g key={phase.from}>
              <rect x={x1} y={TOP - 2} width={x2 - x1} height={ticksY - TOP + 2} fill={`color-mix(in srgb, var(--rubric) ${phase.cpu >= 50 ? 13 : 6}%, transparent)`} />
              {index > 0 && <line x1={x1} x2={x1} y1={TOP - 2} y2={ticksY} stroke="var(--rubric)" />}
            </g>
          );
        })}
        {lanes.map((lane, index) => {
          const y0 = laneY(index);
          const y = (value: number) => y0 + LANE - (Math.min(value, lane.top) / lane.top) * LANE;
          const line = points.map((p) => `${x(p.at).toFixed(1)},${y(lane.value(p)).toFixed(1)}`).join(' ');
          const area = `${x(points[0]!.at)},${y0 + LANE} ${line} ${x(points[points.length - 1]!.at)},${y0 + LANE}`;
          const colour = lane.key === 'cpu' ? 'var(--counter)' : lane.key === 'gpu' ? 'var(--rubric-lift)' : 'var(--ink-2)';
          return (
            <g key={lane.key}>
              <line x1={0} x2={width} y1={y0 + LANE} y2={y0 + LANE} stroke="var(--rule-2)" />
              <polygon points={area} fill={`color-mix(in srgb, ${colour} 14%, transparent)`} />
              <polyline points={line} fill="none" stroke={colour} strokeWidth={1.5} strokeLinejoin="round" />
              <text x={3} y={y0 + 10} className="ct-inv-lane">{lane.label}</text>
              <text x={width - 3} y={y0 + 10} className="ct-inv-lane end">{lane.scale}</text>
              {reading && <circle cx={x(reading.at)} cy={y(lane.value(reading))} r={2.5} fill={colour} />}
            </g>
          );
        })}
        {starts.map((start, index) => (
          <line key={`${start.pid}:${index}`} x1={x(start.at)} x2={x(start.at)} y1={ticksY + 2} y2={ticksY + 11} stroke="var(--rubric-lift)" />
        ))}
        {hover != null && <line x1={x(hover)} x2={x(hover)} y1={TOP - 2} y2={ticksY} stroke="var(--ink)" strokeDasharray="2 2" />}
      </svg>
    </div>
  );
}

// --- what it touched ----------------------------------------------------------------------------

function Touched({ list, home, empty }: { list: TraceSummary['touched']; home: string; empty: string }) {
  if (list.length === 0) return <p className="ct-hint">{empty}</p>;
  return (
    <div className="ct-inv-list ct-mono">
      {list.map((item) => (
        <div key={`${item.kind}:${item.name}:${item.how}`} className="ct-inv-item" title={item.name}>
          <span className={`kind ${item.how === 'wrote' ? 'ct-warn' : item.kind === 'folder' ? 'k-file' : 'k-net'}`}>{item.how === 'connected' ? 'TCP' : item.how}</span>
          <span className="name">{item.kind === 'folder' ? shortPath(item.name, home) : item.name}</span>
          <span className="num">{item.count}{item.kind === 'folder' ? '' : '×'}</span>
          <span className="num ct-faint">{clock(item.last, true)}</span>
        </div>
      ))}
    </div>
  );
}

const SHOWN = 4;

/** Programs in rows by who started whom; under them the folders, hosts and ports they used. */
function Graph({ id, home, refresh }: { id: string; home: string; refresh: number }) {
  const client = runtime().client;
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(320);
  const [graph, setGraph] = useState<TraceGraph | null>(null);
  useEffect(() => {
    const node = box.current;
    if (!node) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(200, Math.round(entry!.contentRect.width))));
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    let stopped = false;
    client.call<TraceGraph>('system.trace.graph.get', { id }).then((value) => { if (!stopped && value) setGraph(value); }).catch(() => undefined);
    return () => { stopped = true; };
  }, [id, refresh, client]);

  const layout = useMemo(() => {
    if (!graph) return null;
    const programs = graph.nodes.filter((n) => n.kind === 'process');
    const spawned = graph.edges.filter((e) => e.kind === 'spawned');
    const parents = new Set(spawned.map((e) => e.to));
    const rows: string[][] = [];
    const placed = new Set<string>();
    let level = programs.filter((p) => !parents.has(p.id)).map((p) => p.id);
    if (level.length === 0) level = programs.slice(0, 1).map((p) => p.id);
    while (level.length && rows.length < 3) {
      const row = level.filter((nodeId) => !placed.has(nodeId));
      row.forEach((nodeId) => placed.add(nodeId));
      if (row.length) rows.push(row);
      level = spawned.filter((e) => row.includes(e.from)).map((e) => e.to);
    }
    const weight = (nodeId: string) => graph.edges.filter((e) => e.to === nodeId || e.from === nodeId).reduce((sum, e) => sum + e.count, 0);
    const resources = graph.nodes.filter((n) => n.kind !== 'process').sort((a, b) => weight(b.id) - weight(a.id));
    return { rows: rows.map((row) => row.sort((a, b) => weight(b) - weight(a))), resources, byId: new Map(graph.nodes.map((n) => [n.id, n])) };
  }, [graph]);

  if (!graph || !layout) return <div ref={box}><p className="ct-hint">Reading the graph…</p></div>;
  if (graph.nodes.length === 0) return <div ref={box}><p className="ct-hint">Nothing in the graph yet.</p></div>;
  const ROW = 58;
  const BOX = 22;
  const rows = [...layout.rows.map((row) => row.slice(0, SHOWN)), layout.resources.slice(0, SHOWN).map((n) => n.id)].filter((row) => row.length);
  const more = [...layout.rows.map((row) => row.length - SHOWN), layout.resources.length - SHOWN].map((n) => Math.max(0, n));
  const height = rows.length * ROW;
  const spot = new Map<string, { x: number; y: number; w: number }>();
  rows.forEach((row, r) => {
    const w = (width - 8 * (row.length - 1)) / row.length;
    row.forEach((nodeId, i) => spot.set(nodeId, { x: i * (w + 8), y: r * ROW + 14, w }));
  });
  const label = (nodeId: string) => {
    const node = layout.byId.get(nodeId)!;
    const name = node.kind === 'folder' ? shortPath(node.name, home).split('/').slice(-2).join('/') : node.name;
    return node.kind === 'process' && node.count > 1 ? `${name} ×${node.count}` : node.kind === 'folder' && node.count > 1 ? `${name} ${node.count}` : name;
  };
  return (
    <div ref={box} className="ct-trace-graph">
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Programs and what they used">
        {graph.edges.filter((e) => spot.has(e.from) && spot.has(e.to)).map((edge) => {
          const a = spot.get(edge.from)!;
          const b = spot.get(edge.to)!;
          const [x1, y1, x2, y2] = [a.x + a.w / 2, a.y + BOX, b.x + b.w / 2, b.y];
          const wrote = edge.kind === 'wrote';
          return (
            <g key={`${edge.from}>${edge.to}>${edge.kind}`}>
              <title>{`${layout.byId.get(edge.from)?.name} ${edge.kind} ${layout.byId.get(edge.to)?.name} (${edge.count}×)`}</title>
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={wrote ? 'var(--rubric)' : 'var(--rule-2)'} strokeWidth={wrote ? 1.5 : 1} />
              <text x={(x1 + x2) / 2 + 3} y={(y1 + y2) / 2 + 3} className={`ct-trace-edge${wrote ? ' wrote' : ''}`}>{edge.kind.toUpperCase()}</text>
            </g>
          );
        })}
        {[...spot.entries()].map(([nodeId, s]) => {
          const node = layout.byId.get(nodeId)!;
          return (
            <g key={nodeId}>
              <title>{node.name}</title>
              <rect x={s.x + 0.5} y={s.y + 0.5} width={s.w - 1} height={BOX} className={`ct-trace-node ${node.kind}`} />
              <foreignObject x={s.x + 4} y={s.y + 4} width={Math.max(0, s.w - 8)} height={BOX - 6}>
                <div className="ct-trace-node-label ct-mono">{label(nodeId)}</div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
      {more.some((n) => n > 0) && <p className="ct-hint">{more.reduce((a, b) => a + b, 0)} more in FOLDERS, HOSTS and LOG.</p>}
    </div>
  );
}

function Log({ id, from, to, home }: { id: string; from: number; to: number; home: string }) {
  const client = runtime().client;
  const [records, setRecords] = useState<TraceRecord[] | null>(null);
  const [more, setMore] = useState(false);
  useEffect(() => {
    let stopped = false;
    client.call<{ records: TraceRecord[]; more: boolean }>('system.trace.read', { id, size: 'records', from, to, kinds: ['start', 'end', 'open', 'close', 'connect', 'listen', 'output', 'exit'], limit: 400 })
      .then((value) => { if (!stopped) { setRecords(value?.records ?? []); setMore(value?.more ?? false); } }).catch(() => setRecords([]));
    return () => { stopped = true; };
  }, [id, from, to, client]);
  if (records == null) return <p className="ct-hint">Reading the records…</p>;
  if (records.length === 0) return <p className="ct-hint">No records but samples in this span.</p>;
  return (
    <div className="ct-inv-list ct-mono ct-inv-log">
      {records.map((record, index) => (
        <div key={`${record.at}:${index}`} className={`ct-inv-item ${record.kind === 'close' || record.kind === 'end' ? 'close' : 'open'}`}>
          <span className="t ct-faint">{clock(record.at)}</span>
          <span className="kind">{record.kind}</span>
          <span className="name">{
            record.kind === 'exit' ? `exit ${record.code ?? '?'}`
              : record.kind === 'start' || record.kind === 'end' ? `${record.name ?? ''} ${record.pid}`
                : record.kind === 'open' || record.kind === 'close' ? shortPath(record.text ?? '', home)
                  : record.text}</span>
        </div>
      ))}
      {more && <div className="ct-faint">The first 400; zoom into a phase for the rest.</div>}
    </div>
  );
}

function explainQuestion(summary: TraceSummary): string {
  const t = summary.trace;
  return `What did \`${t.command || t.label}\` do while it was traced, and is anything in it unusual or worth fixing? Here is its trace summary:\n${summary.text}`;
}

function clock(at: number, short?: boolean): string {
  return new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', ...(short ? {} : { second: '2-digit' }), hour12: false });
}
