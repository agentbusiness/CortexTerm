/**
 * Investigate: one process in the side pane. Its last 20 minutes (CPU, GPU, memory) on one time
 * axis with the terminal's Runs laid over it, so a climb lines up with the command that came
 * before it; which Runs moved it; the output at any moment of the chart; its threads, open files
 * and sockets; and monitor mode, which logs what it opens and talks to and hands the condensed
 * report to the model for a review. The model explains; the buttons act.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { ago, errorMessage, runtime } from '@cortex/sdk';
import type { MonitorReport, OpenFile, Proc, ProcessDetail, ProcSample, Run, RunOutput, TraceInfo } from './api';
import { quote, seconds, shortPath, size } from './api';

type Ask = (text: string, intent: 'ask' | 'explain' | 'fix', runId?: string) => void;

const RANGES = { '5M': 5 * 60_000, '20M': 20 * 60_000 } as const;
type Range = keyof typeof RANGES;

export function Investigate({ pid, home, onAsk, onSignal, onShell, onOpenFile, onOpenRun, onInvestigate, onOpenTrace, onClose }: {
  pid: number; home: string; onAsk: Ask; onSignal: (proc: Proc, signal: string) => void; onShell: (command: string) => void;
  onOpenFile: (path: string) => void; onOpenRun: (runId: string) => void; onInvestigate: (pid: number) => void; onOpenTrace: (id: string) => void; onClose: () => void;
}) {
  const client = runtime().client;
  const [detail, setDetail] = useState<ProcessDetail | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [range, setRange] = useState<Range>('20M');
  const [pinned, setPinned] = useState<number | null>(null);
  const [picked, setPicked] = useState<string | null>(null);

  const read = useRef<() => void>(() => undefined);
  useEffect(() => {
    let stopped = false;
    setDetail(null);
    setGone(false);
    setPinned(null);
    setPicked(null);
    read.current = () => client.call<ProcessDetail>('system.process', { pid }, { signal: AbortSignal.timeout(10_000) })
      .then((value) => { if (!stopped && value) { setDetail(value); setProblem(null); setGone(false); } })
      .catch((cause) => { if (!stopped) { const text = errorMessage(cause); if (/no process/i.test(text)) setGone(true); else setProblem(text); } });
    read.current();
    const timer = setInterval(() => read.current(), 3000);
    return () => { stopped = true; clearInterval(timer); };
  }, [pid, client]);

  useEffect(() => {
    let stopped = false;
    const load = () => client.call<{ runs: Run[] }>('terminal.runs', { limit: 200 })
      .then((list) => { if (!stopped) setRuns(list?.runs ?? []); }).catch(() => undefined);
    void load();
    const timer = setInterval(load, 5000);
    return () => { stopped = true; clearInterval(timer); };
  }, [client]);

  // The trace recording this process now, if any (RECORD starts one; it keeps a week of it).
  const [recording, setRecording] = useState<TraceInfo | null>(null);
  const [recordProblem, setRecordProblem] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    setRecording(null);
    const load = () => client.call<{ traces: TraceInfo[] }>('system.trace.list', { limit: 200 })
      .then((list) => { if (!stopped) setRecording(list?.traces.find((t) => t.pid === pid && t.source !== 'run' && t.ended == null) ?? null); })
      .catch(() => undefined);
    void load();
    const timer = setInterval(load, 5000);
    return () => { stopped = true; clearInterval(timer); };
  }, [pid, client]);
  const record = () => client.call<TraceInfo>('system.trace.run', { pid })
    .then((trace) => { setRecordProblem(null); if (trace) { setRecording(trace); onOpenTrace(trace.id); } })
    .catch((cause) => setRecordProblem(errorMessage(cause)));

  const history = detail?.history ?? [];
  const to = history.length ? history[history.length - 1]!.at : Date.now();
  const from = Math.max(to - RANGES[range], history[0]?.at ?? to - RANGES[range]);
  const shown = useMemo(() => history.filter((s) => s.at >= from), [history, from]);
  const inWindow = useMemo(() => runs.filter((run) => (run.ended ?? Date.now()) >= from && run.started <= to + 5000).sort((a, b) => a.started - b.started), [runs, from, to]);
  const impact = useMemo(() => impactOf(history, inWindow), [history, inWindow]);

  if (gone && !detail) return <div className="ct-inv"><InvHead name={`pid ${pid}`} pid={pid} state="ended" onClose={onClose} /><p className="ct-hint">This process has ended.</p></div>;
  if (!detail) return <div className="ct-inv"><InvHead name={`pid ${pid}`} pid={pid} state="" onClose={onClose} /><p className="ct-hint">{problem ?? 'Reading the process…'}</p></div>;

  const proc = detail.process;
  const stats = summary(shown);
  const paused = detail.state === 'stopped';
  const pinnedRuns = pinned == null ? [] : inWindow.filter((run) => run.started <= pinned + 2000 && (run.ended ?? Date.now()) >= pinned - 2000);
  const pickedRun = picked ? inWindow.find((run) => run.id === picked) ?? runs.find((run) => run.id === picked) ?? null : null;

  return (
    <div className="ct-inv" aria-label={`Investigate ${proc.name}`}>
      <InvHead name={proc.name} pid={proc.pid} state={gone ? 'ended' : detail.state} onClose={onClose} />
      <div className="ct-inv-meta ct-label ct-faint">
        {[proc.user && `USER ${proc.user}`, proc.started && `UP ${seconds(Date.now() - proc.started * 1000)}`, signatureLabel(detail), detail.launchd_managed && 'LAUNCHD KEEPS IT ALIVE', detail.quarantined && 'QUARANTINED']
          .filter(Boolean).map((text, index) => <span key={index} className={text === 'UNSIGNED' || text === 'QUARANTINED' ? 'ct-warn' : ''}>{text}</span>)}
      </div>
      <code className="ct-inv-cmd ct-mono">{proc.command || detail.executable || proc.name}</code>
      <div className="ct-inv-lineage ct-mono">
        {[...detail.parents].reverse().map(([parentPid, name]) => (
          <span key={parentPid}><button type="button" className="ct-inv-link" onClick={() => onInvestigate(parentPid)} title={`Investigate ${name} (${parentPid})`}>{name}</button><span className="ct-faint"> › </span></span>
        ))}
        <span className="ct-inv-self">{proc.name}</span>
        {detail.children.length > 0 && <span className="ct-faint"> › {detail.children.length} child{detail.children.length > 1 ? 'ren' : ''}</span>}
      </div>
      {detail.cwd && <div className="ct-inv-cwd ct-label ct-faint">IN <span className="ct-mono">{shortPath(detail.cwd, home)}</span></div>}

      <div className="ct-inv-actions">
        <button type="button" className="detent sm warn" onClick={() => onAsk(explainQuestion(detail, stats, impact), 'explain')}>EXPLAIN</button>
        {recording ? (
          <button type="button" className="detent sm" title="It is being recorded: open its trace" onClick={() => onOpenTrace(recording.id)}><span className="ct-inv-pulse" aria-hidden />RECORDING</button>
        ) : !gone && (
          <button type="button" className="detent sm" title="Keep a week of what it and its children do: CPU, memory, GPU, disk, processes, files and hosts" onClick={() => void record()}><span className="ct-rec-dot" aria-hidden />RECORD</button>
        )}
        {!gone && <>
          <button type="button" className="detent sm" onClick={() => onSignal(proc, paused ? 'CONT' : 'STOP')}>{paused ? 'RESUME' : 'PAUSE'}</button>
          <button type="button" className="detent sm" onClick={() => onSignal(proc, 'TERM')}>TERMINATE</button>
          <button type="button" className="detent sm" onClick={() => onSignal(proc, 'KILL')}>KILL</button>
          <button type="button" className="detent sm" title="Where its threads are, three seconds of stacks (macOS sample)" onClick={() => onShell(`sample ${proc.pid} 3`)}>SAMPLE STACKS</button>
          {detail.cwd && <button type="button" className="detent sm" onClick={() => onShell(`cd ${quote(detail.cwd)}`)}>CD THERE</button>}
        </>}
        <button type="button" className="detent sm" onClick={() => void navigator.clipboard?.writeText(proc.command || detail.executable)}>COPY COMMAND</button>
      </div>
      {gone && <p className="ct-hint ct-warn">It has ended; this is what was last read.</p>}
      {recordProblem && <p className="ct-hint ct-warn">{recordProblem}</p>}
      {problem && <p className="ct-hint ct-warn">{problem}</p>}

      <div className="ct-inv-tiles">
        <Stat label="CPU" value={`${Math.round(proc.cpu)}%`} note={stats.n ? `avg ${Math.round(stats.cpuAvg)} · peak ${Math.round(stats.cpuPeak)}` : ''} hot={proc.cpu > 80} />
        <Stat label="MEM" value={size(proc.memory)} note={detail.peak_memory ? `peak ever ${size(detail.peak_memory)}` : stats.n ? `peak ${size(stats.memPeak)}` : ''} />
        <Stat label="GPU" value={proc.gpu != null ? `${Math.round(proc.gpu)}%` : '–'} note={stats.gpuPeak != null ? `peak ${Math.round(stats.gpuPeak)}` : ''} />
        <Stat label="THREADS" value={String(detail.threads || detail.thread_list.length)} note={`${detail.thread_list.filter((t) => t.state === 'running').length} running`} />
        <Stat label="FILES" value={String(detail.open_files || detail.files.length)} note={`${detail.files.filter((f) => f.kind === 'tcp' || f.kind === 'udp').length} sockets`} />
        <Stat label="CPU TIME" value={seconds(detail.cpu_time_ms)} note={`disk r ${size(detail.disk_read_total)} · w ${size(detail.disk_written_total)}`} />
      </div>

      <section className="ct-inv-sec">
        <div className="ct-side-head">
          <span className="ct-label ct-faint">OVER TIME</span>
          <span className="ct-inv-key ct-label"><span className="cpu">CPU</span><span className="gpu">GPU</span><span className="mem">MEM</span><span className="k-run">RUNS</span></span>
          <span className="grow" />
          {(Object.keys(RANGES) as Range[]).map((name) => <button key={name} type="button" className={`ct-seg${range === name ? ' on' : ''}`} onClick={() => setRange(name)}>{name}</button>)}
        </div>
        {shown.length < 2 ? <p className="ct-hint">The chart fills in as the process is read (every 4 s).</p> : (
          <Timeline samples={shown} from={from} to={to} runs={inWindow} pinned={pinned} picked={picked}
            onPin={(at) => { setPinned(at); setPicked(null); }} onPick={(id) => { setPicked(id); setPinned(null); }} />
        )}
        <p className="ct-inv-hint ct-label ct-faint">{pinned == null && !picked ? 'CLICK THE CHART FOR THE OUTPUT AT THAT MOMENT' : ''}</p>
      </section>

      {(pinned != null || pickedRun) && (
        <OutputAt at={pinned} runs={pickedRun ? [pickedRun] : pinnedRuns} home={home} onOpenRun={onOpenRun} onClear={() => { setPinned(null); setPicked(null); }} />
      )}

      <section className="ct-inv-sec">
        <div className="ct-side-head"><span className="ct-label ct-faint">WHAT MOVED IT</span><span className="grow" /><span className="ct-label ct-faint">RUNS IN THIS WINDOW · {inWindow.length}</span></div>
        {impact.length === 0 ? <p className="ct-hint">{inWindow.length ? 'No Run in this window changed its CPU or memory much.' : 'No command ran in a terminal in this window.'}</p> : (
          <div className="ct-inv-impact">
            {impact.slice(0, 6).map((entry) => (
              <button key={entry.run.id} type="button" className={`ct-inv-impact-row${picked === entry.run.id ? ' on' : ''}`} onClick={() => { setPicked(entry.run.id); setPinned(null); }}>
                <span className="cmd ct-mono">{entry.run.command}</span>
                <span className={`d ct-mono${entry.cpu >= 10 ? ' ct-warn' : entry.cpu <= -10 ? ' ct-blue' : ''}`}>{signed(entry.cpu)}% CPU</span>
                <span className={`d ct-mono${entry.mem >= 200e6 ? ' ct-warn' : ''}`}>{entry.mem >= 0 ? '+' : '−'}{size(Math.abs(entry.mem))}</span>
                <span className="when ct-label ct-faint">{ago(entry.run.started).toUpperCase()}</span>
              </button>
            ))}
          </div>
        )}
      </section>

      <Monitor pid={proc.pid} report={detail.monitor ?? null} name={proc.name} ended={gone} onChanged={() => read.current()} onAsk={onAsk} onOpenFile={onOpenFile} home={home} />

      <Threads detail={detail} />
      <Files files={detail.files} home={home} onOpenFile={onOpenFile} />
      {detail.children.length > 0 && (
        <section className="ct-inv-sec">
          <div className="ct-side-head"><span className="ct-label ct-faint">CHILDREN · {detail.children.length}</span></div>
          <div className="ct-inv-list ct-mono">
            {detail.children.slice(0, 20).map((child) => (
              <button key={child.pid} type="button" className="ct-inv-item" onClick={() => onInvestigate(child.pid)}>
                <span className="name">{child.name} <span className="ct-faint">{child.pid}</span></span>
                <span className="num">{size(child.memory)}</span><span className="num">{child.cpu.toFixed(0)}%</span>
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function InvHead({ name, pid, state, onClose }: { name: string; pid: number; state: string; onClose: () => void }) {
  return (
    <header className="ct-inv-head">
      <span className="ct-inv-name ct-mono">{name}</span>
      <span className="ct-mono ct-faint">{pid}</span>
      {state && <span className={`ct-inv-state ct-label ${state}`}>{state === 'stopped' ? 'PAUSED' : state.toUpperCase()}</span>}
      <span className="grow" />
      <button type="button" className="detent sm" onClick={onClose}>CLOSE</button>
    </header>
  );
}

function Stat({ label, value, note, hot }: { label: string; value: string; note?: string; hot?: boolean }) {
  return (
    <div className="ct-tile">
      <div className="ct-tile-head"><span className="ct-faint">{label}</span><span className="grow" /><span className={hot ? 'ct-warn' : ''}>{value}</span></div>
      {note && <div className="ct-faint ct-tile-note">{note}</div>}
    </div>
  );
}

// --- the timeline -------------------------------------------------------------------------------

const LANE = 44;
const GAP = 8;
const TOP = 14;

/** CPU, GPU and memory lanes on one time axis; each Run a band from its start to its end, with a
 *  tick at the start. Hover reads every lane at one moment; a click pins it (or picks a Run). */
function Timeline({ samples, from, to, runs, pinned, picked, onPin, onPick }: {
  samples: ProcSample[]; from: number; to: number; runs: Run[]; pinned: number | null; picked: string | null;
  onPin: (at: number) => void; onPick: (id: string) => void;
}) {
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

  const span = Math.max(1, to - from);
  const x = (at: number) => ((Math.min(Math.max(at, from), to) - from) / span) * width;
  const atOf = (px: number) => from + (px / width) * span;
  const cpuTop = Math.max(100, ...samples.map((s) => s.cpu)) * 1.08;
  const memTop = Math.max(1, ...samples.map((s) => s.memory)) * 1.12;
  const hasGpu = samples.some((s) => s.gpu != null);
  const lanes = [
    { key: 'cpu', label: 'CPU', top: cpuTop, value: (s: ProcSample) => s.cpu, scale: `${Math.round(cpuTop)}%` },
    ...(hasGpu ? [{ key: 'gpu', label: 'GPU', top: 100, value: (s: ProcSample) => s.gpu ?? 0, scale: '100%' }] : []),
    { key: 'mem', label: 'MEM', top: memTop, value: (s: ProcSample) => s.memory, scale: size(memTop) },
  ];
  const height = TOP + lanes.length * (LANE + GAP);
  const laneY = (index: number) => TOP + index * (LANE + GAP);

  const nearest = (at: number) => samples.reduce((best, s) => (Math.abs(s.at - at) < Math.abs(best.at - at) ? s : best), samples[0]!);
  const focus = hover ?? pinned;
  const reading = focus != null ? nearest(focus) : null;
  const during = focus != null ? runs.filter((run) => run.started <= focus && (run.ended ?? Date.now()) >= focus) : [];

  const ticks = useMemo(() => {
    const minutes = span / 60_000;
    const step = (minutes > 10 ? 5 : minutes > 4 ? 1 : 0.5) * 60_000;
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
          {reading.gpu != null && <span className="gpu">GPU {Math.round(reading.gpu)}%</span>}
          <span className="mem">MEM {size(reading.memory)}</span>
          {during.length > 0 && <span className="k-run">during {during.map((run) => run.command).join(', ')}</span>}
        </> : <span className="ct-faint">Hover to read a moment · Runs are the orange bands</span>}
      </div>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="ct-inv-svg"
        onMouseMove={(event) => { const rect = event.currentTarget.getBoundingClientRect(); setHover(atOf(event.clientX - rect.left)); }}
        onMouseLeave={() => setHover(null)}
        onClick={(event) => { const rect = event.currentTarget.getBoundingClientRect(); onPin(atOf(event.clientX - rect.left)); }}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={TOP - 2} y2={height - GAP} stroke="var(--rule)" />
            <text x={x(t) + 3} y={9} className="ct-inv-tick">{clock(t, true)}</text>
          </g>
        ))}
        {runs.map((run) => {
          const x1 = x(run.started);
          const x2 = Math.max(x1 + 2, x(run.ended ?? to));
          const on = run.id === picked;
          return (
            <g key={run.id} className="ct-inv-run" onClick={(event) => { event.stopPropagation(); onPick(run.id); }}>
              <title>{`${run.command}\n${clock(run.started)}${run.ended ? ` – ${clock(run.ended)}` : ' – running'}${run.exit_code != null && run.exit_code !== 0 ? ` · exit ${run.exit_code}` : ''}`}</title>
              <rect x={x1} y={TOP - 2} width={x2 - x1} height={height - TOP - GAP + 2} fill={`color-mix(in srgb, var(--rubric) ${on ? 22 : 9}%, transparent)`} />
              <line x1={x1} x2={x1} y1={TOP - 4} y2={height - GAP} stroke="var(--rubric)" strokeWidth={on ? 1.5 : 1} />
              <path d={`M${x1 - 3.5},${TOP - 6} L${x1 + 3.5},${TOP - 6} L${x1},${TOP - 1} Z`} fill={run.exit_code != null && run.exit_code !== 0 ? 'var(--rubric-lift)' : 'var(--rubric)'} />
            </g>
          );
        })}
        {lanes.map((lane, index) => {
          const y0 = laneY(index);
          const y = (value: number) => y0 + LANE - (Math.min(value, lane.top) / lane.top) * LANE;
          const points = samples.map((s) => `${x(s.at).toFixed(1)},${y(lane.value(s)).toFixed(1)}`).join(' ');
          const area = `${x(samples[0]!.at)},${y0 + LANE} ${points} ${x(samples[samples.length - 1]!.at)},${y0 + LANE}`;
          const colour = lane.key === 'cpu' ? 'var(--counter)' : lane.key === 'gpu' ? 'var(--rubric-lift)' : 'var(--ink-2)';
          return (
            <g key={lane.key}>
              <line x1={0} x2={width} y1={y0 + LANE} y2={y0 + LANE} stroke="var(--rule-2)" />
              <polygon points={area} fill={`color-mix(in srgb, ${colour} 14%, transparent)`} />
              <polyline points={points} fill="none" stroke={colour} strokeWidth={1.5} strokeLinejoin="round" />
              <text x={3} y={y0 + 10} className="ct-inv-lane">{lane.label}</text>
              <text x={width - 3} y={y0 + 10} className="ct-inv-lane end">{lane.scale}</text>
              {reading && <circle cx={x(reading.at)} cy={y(lane.value(reading))} r={2.5} fill={colour} />}
            </g>
          );
        })}
        {focus != null && <line x1={x(focus)} x2={x(focus)} y1={TOP - 2} y2={height - GAP} stroke="var(--ink)" strokeDasharray={hover != null ? '2 2' : undefined} />}
      </svg>
    </div>
  );
}

// --- the output at a moment ----------------------------------------------------------------------

function OutputAt({ at, runs, home, onOpenRun, onClear }: { at: number | null; runs: Run[]; home: string; onOpenRun: (runId: string) => void; onClear: () => void }) {
  const client = runtime().client;
  const [outputs, setOutputs] = useState<Record<string, RunOutput>>({});
  const key = runs.map((run) => run.id).join(',');
  useEffect(() => {
    let stopped = false;
    setOutputs({});
    for (const run of runs) {
      client.call<RunOutput>('terminal.run.output', { run_id: run.id, from: -2000, count: 2000 })
        .then((output) => { if (!stopped && output) setOutputs((all) => ({ ...all, [run.id]: output })); }).catch(() => undefined);
    }
    return () => { stopped = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, client]);

  return (
    <section className="ct-inv-sec ct-inv-output">
      <div className="ct-side-head">
        <span className="ct-label ct-faint">{at != null ? `OUTPUT AT ${clock(at)}` : 'OUTPUT OF THE RUN'}</span>
        <span className="grow" />
        <button type="button" className="ct-seg" onClick={onClear}>CLEAR</button>
      </div>
      {runs.length === 0 && <p className="ct-hint">No terminal command was running at that moment.</p>}
      {runs.map((run) => {
        const output = outputs[run.id];
        const lines = output?.lines ?? [];
        // Around the moment: the lines from 20 s before it to 10 s after, else the last ones.
        const near = at != null ? lines.filter((line) => line.at >= at - 20_000 && line.at <= at + 10_000) : lines;
        const show = (near.length ? near : lines).slice(-40);
        const closest = at != null && show.length ? show.reduce((best, line) => (Math.abs(line.at - at) < Math.abs(best.at - at) ? line : best), show[0]!) : null;
        return (
          <div key={run.id} className="ct-inv-run-out">
            <div className="ct-inv-run-head">
              <code className="ct-mono">{run.command}</code>
              <span className="grow" />
              <span className="ct-label ct-faint">{shortPath(run.cwd, home)}</span>
              <button type="button" className="ct-seg" onClick={() => onOpenRun(run.id)}>FULL LOG</button>
            </div>
            {!output ? <p className="ct-hint">Reading…</p> : show.length === 0 ? <p className="ct-hint">It printed nothing.</p> : (
              <div className="ct-inv-lines ct-mono">
                {at != null && near.length === 0 && <div className="ct-faint">Nothing printed near that moment; its last lines:</div>}
                {show.map((line) => (
                  <div key={line.n} className={`ct-inv-line ${line.level}${closest?.n === line.n ? ' at' : ''}`}>
                    <span className="t ct-faint">{line.at ? clock(line.at) : ''}</span>
                    <span className="x">{line.text || ' '}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}

// --- threads and files -----------------------------------------------------------------------------

function Threads({ detail }: { detail: ProcessDetail }) {
  const [all, setAll] = useState(false);
  const list = detail.thread_list;
  const top = Math.max(1, ...list.map((t) => t.cpu));
  return (
    <section className="ct-inv-sec">
      <div className="ct-side-head">
        <span className="ct-label ct-faint">THREADS · {detail.threads || list.length}</span>
        <span className="grow" />
        {list.length > 12 && <button type="button" className="ct-seg" onClick={() => setAll(!all)}>{all ? 'BUSIEST' : `ALL ${list.length}`}</button>}
      </div>
      {list.length === 0 ? <p className="ct-hint">Its threads cannot be read without admin (another user owns it).</p> : (
        <div className="ct-inv-list ct-mono">
          <div className="ct-inv-item head ct-label"><span className="name">NAME</span><span className="bar">CPU</span><span className="num">TIME</span></div>
          {(all ? list : list.slice(0, 12)).map((thread) => (
            <div key={thread.id} className="ct-inv-item">
              <span className="name"><span className={`ct-inv-dot ${thread.state}`} title={thread.state} />{thread.name || <span className="ct-faint">thread {thread.id.toString(16).slice(-5)}</span>}</span>
              <span className="bar"><span style={{ width: `${(thread.cpu / top) * 100}%` }} /><em>{thread.cpu.toFixed(0)}%</em></span>
              <span className="num">{seconds(thread.user_ms + thread.system_ms)}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

const KINDS = [['all', 'ALL'], ['file', 'FILES'], ['net', 'NETWORK'], ['pipe', 'PIPES'], ['other', 'OTHER']] as const;
type Kind = (typeof KINDS)[number][0];

function kindOf(file: OpenFile): Kind {
  if (file.kind === 'file' || file.kind === 'dir') return 'file';
  if (file.kind === 'tcp' || file.kind === 'udp') return 'net';
  if (file.kind === 'pipe' || file.kind === 'unix') return 'pipe';
  return 'other';
}

function Files({ files, home, onOpenFile }: { files: OpenFile[]; home: string; onOpenFile: (path: string) => void }) {
  const [kind, setKind] = useState<Kind>('all');
  const [find, setFind] = useState('');
  const [all, setAll] = useState(false);
  const counts = useMemo(() => files.reduce((map, file) => map.set(kindOf(file), (map.get(kindOf(file)) ?? 0) + 1), new Map<Kind, number>()), [files]);
  const list = files.filter((file) => (kind === 'all' || kindOf(file) === kind) && (!find || file.name.toLowerCase().includes(find.toLowerCase())));
  return (
    <section className="ct-inv-sec">
      <div className="ct-side-head">
        <span className="ct-label ct-faint">OPEN FILES · {files.length}</span>
        <span className="grow" />
        {KINDS.map(([value, label]) => (value === 'all' || counts.get(value)) ? (
          <button key={value} type="button" className={`ct-seg${kind === value ? ' on' : ''}`} onClick={() => setKind(value)}>{label}{value !== 'all' ? ` ${counts.get(value)}` : ''}</button>
        ) : null)}
      </div>
      {files.length === 0 ? <p className="ct-hint">Its open files cannot be read without admin (another user owns it).</p> : <>
        {files.length > 12 && <label className="ct-find"><input type="text" value={find} placeholder="filter: a path, a host, :443" spellCheck={false} onChange={(event) => setFind(event.target.value)} /></label>}
        <div className="ct-inv-list ct-mono">
          {(all ? list : list.slice(0, 30)).map((file, index) => {
            const path = file.kind === 'file' || file.kind === 'dir';
            return (
              <div key={`${file.fd}:${file.name}:${index}`} className={`ct-inv-item file${path && file.kind === 'file' ? ' open' : ''}`}
                onClick={path && file.kind === 'file' ? () => onOpenFile(file.name) : undefined} title={file.name}>
                <span className="fd ct-faint">{file.fd}{file.mode}</span>
                <span className={`kind k-${kindOf(file)}`}>{file.kind}</span>
                <span className="name">{path ? shortPath(file.name, home) : file.name || '–'}</span>
                {file.state && <span className={`st${file.state === 'LISTEN' ? ' ct-blue' : ''}`}>{file.state}</span>}
              </div>
            );
          })}
        </div>
        {list.length > 30 && <button type="button" className="ct-seg ct-inv-more" onClick={() => setAll(!all)}>{all ? 'FEWER' : `ALL ${list.length}`}</button>}
      </>}
    </section>
  );
}

// --- monitor mode -----------------------------------------------------------------------------------

function Monitor({ pid, name, report, ended, home, onChanged, onAsk, onOpenFile }: {
  pid: number; name: string; report: MonitorReport | null; ended: boolean; home: string; onChanged: () => void; onAsk: Ask; onOpenFile: (path: string) => void;
}) {
  const client = runtime().client;
  const [children, setChildren] = useState(true);
  const [problem, setProblem] = useState<string | null>(null);
  const [tab, setTab] = useState<'hosts' | 'folders' | 'log'>('hosts');
  const set = (on: boolean) => client.call<MonitorReport>('system.monitor', { pid, on, children })
    .then(() => { setProblem(null); onChanged(); }).catch((cause) => setProblem(errorMessage(cause)));
  const on = report?.on ?? false;
  const events = report?.events ?? [];

  return (
    <section className={`ct-inv-sec ct-inv-monitor${on ? ' live' : ''}`}>
      <div className="ct-side-head">
        <span className="ct-label">{on && <span className="ct-inv-pulse" aria-hidden />}MONITOR</span>
        {report && <span className="ct-label ct-faint">{on ? `ON ${seconds(Date.now() - report.started)}` : `RAN ${seconds((report.stopped ?? Date.now()) - report.started)}`} · {report.polls} READS · {report.total_events} CHANGES</span>}
        <span className="grow" />
        {!on && !ended && <span className="ct-inv-switch ct-label ct-faint">CHILDREN<button type="button" className="sw" aria-pressed={children} aria-label="Also watch its children" onClick={() => setChildren(!children)} /></span>}
        {!ended && <button type="button" className={`detent sm${on ? '' : ' warn'}`} onClick={() => void set(!on)}>{on ? 'STOP' : report ? 'START AGAIN' : 'START'}</button>}
      </div>
      {!report && <p className="ct-hint">Logs every file it opens and every host it talks to, read every 2 s, for up to an hour. Then the model can look the log over for anything worth a worry. Without admin a file opened and closed between two reads is not seen.</p>}
      {problem && <p className="ct-hint ct-warn">{problem}</p>}
      {report && <>
        <div className="ct-inv-flags">
          {report.flags.length === 0 ? <p className="ct-hint">{on ? 'Nothing the rules note so far.' : 'The rules noted nothing.'}</p> : report.flags.map((flag) => <div key={flag} className="ct-inv-flag">{flag}</div>)}
        </div>
        <div className="ct-inv-actions">
          <button type="button" className="detent sm warn" disabled={report.polls === 0} onClick={() => onAsk(reviewQuestion(name, report, home), 'ask')}>REVIEW WITH THE MODEL</button>
          <span className="grow" />
          {(['hosts', 'folders', 'log'] as const).map((value) => (
            <button key={value} type="button" className={`ct-seg${tab === value ? ' on' : ''}`} onClick={() => setTab(value)}>
              {value === 'hosts' ? `HOSTS ${report.hosts.length}` : value === 'folders' ? `FOLDERS ${report.folders.length}` : `LOG ${report.total_events}`}
            </button>
          ))}
        </div>
        {report.listening.length > 0 && <div className="ct-label ct-faint">LISTENING <span className="ct-mono ct-blue">{report.listening.join('  ')}</span></div>}
        {tab === 'hosts' && (report.hosts.length === 0 ? <p className="ct-hint">No connection seen yet.</p> : (
          <div className="ct-inv-list ct-mono">
            {report.hosts.slice(0, 40).map((host) => (
              <div key={host.address} className="ct-inv-item">
                <span className="name">{host.address} <span className="ct-faint">{host.kind}</span></span>
                <span className="num">{host.connections}×</span>
                <span className="num ct-faint">{clock(host.last, true)}</span>
              </div>
            ))}
          </div>
        ))}
        {tab === 'folders' && (report.folders.length === 0 ? <p className="ct-hint">No file seen open yet.</p> : (
          <div className="ct-inv-list ct-mono">
            {report.folders.slice(0, 40).map((folder) => (
              <div key={folder.folder} className="ct-inv-item" title={folder.sample.join('\n')}>
                <span className="name">{shortPath(folder.folder, home)}</span>
                {folder.written && <span className="st ct-warn">WRITE</span>}
                <span className="num">{folder.files}</span>
              </div>
            ))}
          </div>
        ))}
        {tab === 'log' && (events.length === 0 ? <p className="ct-hint">Nothing has changed yet.</p> : (
          <div className="ct-inv-list ct-mono ct-inv-log">
            {events.slice(-120).reverse().map((event, index) => (
              <div key={`${event.at}:${index}`} className={`ct-inv-item ${event.change}`}
                onClick={event.file.kind === 'file' ? () => onOpenFile(event.file.name) : undefined}>
                <span className="t ct-faint">{clock(event.at)}</span>
                <span className="chg">{event.change === 'open' ? '+' : '−'}</span>
                <span className={`kind k-${kindOf(event.file)}`}>{event.file.kind}</span>
                <span className="name">{event.file.kind === 'file' || event.file.kind === 'dir' ? shortPath(event.file.name, home) : event.file.name}</span>
                {event.pid !== pid && <span className="ct-faint">{event.pid}</span>}
              </div>
            ))}
          </div>
        ))}
      </>}
    </section>
  );
}

// --- what is said to the model, and the arithmetic ----------------------------------------------------

interface Stats { n: number; cpuAvg: number; cpuPeak: number; memPeak: number; gpuPeak: number | null }

function summary(samples: ProcSample[]): Stats {
  const n = samples.length;
  const gpus = samples.map((s) => s.gpu).filter((g): g is number => g != null);
  return {
    n,
    cpuAvg: n ? samples.reduce((sum, s) => sum + s.cpu, 0) / n : 0,
    cpuPeak: Math.max(0, ...samples.map((s) => s.cpu)),
    memPeak: Math.max(0, ...samples.map((s) => s.memory)),
    gpuPeak: gpus.length ? Math.max(...gpus) : null,
  };
}

interface Impact { run: Run; cpu: number; mem: number }

/** For each Run: the process's average CPU while it ran against the minute before it, and how far
 *  its memory rose above where it was. The biggest change first; small ones are left out. */
function impactOf(history: ProcSample[], runs: Run[]): Impact[] {
  const out: Impact[] = [];
  for (const run of runs) {
    const end = run.ended ?? Date.now();
    const during = history.filter((s) => s.at >= run.started && s.at <= end + 4000);
    const before = history.filter((s) => s.at >= run.started - 60_000 && s.at < run.started);
    if (!during.length || !before.length) continue;
    const avg = (list: ProcSample[], value: (s: ProcSample) => number) => list.reduce((sum, s) => sum + value(s), 0) / list.length;
    const cpu = avg(during, (s) => s.cpu) - avg(before, (s) => s.cpu);
    const mem = Math.max(...during.map((s) => s.memory)) - avg(before, (s) => s.memory);
    if (Math.abs(cpu) >= 5 || Math.abs(mem) >= 50e6) out.push({ run, cpu, mem });
  }
  return out.sort((a, b) => Math.abs(b.cpu) + Math.abs(b.mem) / 50e6 - (Math.abs(a.cpu) + Math.abs(a.mem) / 50e6));
}

function explainQuestion(detail: ProcessDetail, stats: Stats, impact: Impact[]): string {
  const p = detail.process;
  const busy = detail.thread_list.filter((t) => t.cpu >= 1).slice(0, 4).map((t) => `${t.name || 'unnamed'} ${t.cpu.toFixed(0)}%`);
  const net = detail.files.filter((f) => f.kind === 'tcp' || f.kind === 'udp');
  const facts = [
    `Command: \`${p.command || detail.executable}\``,
    `State ${detail.state || 'unknown'}; user ${p.user || 'me'}; started ${p.started ? new Date(p.started * 1000).toLocaleString() : 'unknown'}; signature ${detail.signature || 'unknown'}${detail.launchd_managed ? '; kept alive by launchd' : ''}.`,
    `Parents: ${[...detail.parents].reverse().map(([, name]) => name).join(' > ') || 'none'}; ${detail.children.length} children.`,
    `Now: CPU ${p.cpu.toFixed(0)}%, memory ${size(p.memory)}${p.gpu != null ? `, GPU ${p.gpu.toFixed(0)}%` : ''}. Over the last ${Math.round((stats.n * 4) / 60)} min: CPU average ${stats.cpuAvg.toFixed(0)}%, peak ${stats.cpuPeak.toFixed(0)}%; memory peak ${size(stats.memPeak)}${detail.peak_memory ? ` (highest ever ${size(detail.peak_memory)})` : ''}.`,
    `${detail.threads} threads${busy.length ? `, busiest: ${busy.join(', ')}` : ''}. ${detail.open_files} open files, ${net.length} sockets${p.ports.length ? `, listening on ${p.ports.map((port) => `:${port}`).join(' ')}` : ''}.`,
    impact.length ? `Terminal commands that coincided with changes: ${impact.slice(0, 3).map((i) => `\`${i.run.command}\` (${signed(i.cpu)}% CPU, ${i.mem >= 0 ? '+' : '-'}${size(Math.abs(i.mem))})`).join('; ')}.` : '',
  ].filter(Boolean);
  return `What is the process "${p.name}" (pid ${p.pid}) doing, and why does it use what it uses?\n${facts.join('\n')}`;
}

function reviewQuestion(name: string, report: MonitorReport, home: string): string {
  const minutes = Math.max(1, Math.round(((report.stopped ?? Date.now()) - report.started) / 60_000));
  const hosts = report.hosts.slice(0, 15).map((h) => `${h.address} (${h.kind}, ${h.connections}×)`);
  const folders = report.folders.slice(0, 15).map((f) => `${shortPath(f.folder, home)} (${f.files} files${f.written ? ', written' : ''})`);
  return [
    `Review what "${name}" (pid ${report.pid}) did while I watched it for ${minutes} min. Is anything here a security or privacy worry, or a sign of a problem? Say what looks normal for this program, what is worth a look and why, and what I could check next.`,
    `It was read every 2 s (${report.polls} reads, ${report.total_events} changes); a file opened and closed between two reads is not in it.`,
    report.flags.length ? `The rules noted:\n- ${report.flags.join('\n- ')}` : 'The rules noted nothing.',
    `Hosts: ${hosts.join('; ') || 'none'}.`,
    `Listening: ${report.listening.join(', ') || 'nothing'}.`,
    `Folders: ${folders.join('; ') || 'none'}.`,
  ].join('\n');
}

function signatureLabel(detail: ProcessDetail): string {
  switch (detail.signature) {
    case 'signed': return detail.team_id ? `SIGNED · ${detail.team_id}` : 'SIGNED BY APPLE';
    case 'adhoc': return 'AD-HOC SIGNED';
    case 'unsigned': return 'UNSIGNED';
    default: return '';
  }
}

function signed(value: number): string {
  return `${value >= 0 ? '+' : '−'}${Math.abs(Math.round(value))}`;
}

function clock(at: number, short?: boolean): string {
  return new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', ...(short ? {} : { second: '2-digit' }), hour12: false });
}
