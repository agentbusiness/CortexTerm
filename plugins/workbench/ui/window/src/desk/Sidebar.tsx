/**
 * The right sidebar: this machine's resources on top (`system.sample`), the process list below
 * (`system.processes`), every row explainable. The find box filters; a question goes to the flow.
 */

import { useEffect, useMemo, useState } from 'react';
import { errorMessage, useRuntime, useEvent } from '@cortex/sdk';
import type { Metrics, ModelInfo, Proc, ProcessGroup } from './api';
import { GB, rate, size } from './api';

const HISTORY = 60;

export function Spark({ values, max, warn }: { values: number[]; max?: number; warn?: boolean }) {
  if (values.length < 2) return <svg className="ct-spark" viewBox="0 0 120 22" preserveAspectRatio="none" aria-hidden />;
  const top = max ?? Math.max(1, ...values);
  const points = values.map((value, index) => `${(index / (values.length - 1)) * 120},${21 - (Math.min(value, top) / top) * 19}`).join(' ');
  return (
    <svg className="ct-spark" viewBox="0 0 120 22" preserveAspectRatio="none" aria-hidden>
      <polyline points={points} fill="none" stroke={warn ? 'var(--rubric-lift)' : 'var(--counter)'} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Memory over time, stacked: what apps hold, then what is compressed, up to all the RAM; swap
 *  (on disk) as a dashed line on the same scale. */
function MemChart({ history, total }: { history: Metrics[]; total: number }) {
  if (history.length < 2 || !total) return <svg className="ct-memchart" viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden />;
  const x = (index: number) => (index / (history.length - 1)) * 120;
  const y = (bytes: number) => 33 - (Math.min(bytes, total) / total) * 32;
  const line = (value: (m: Metrics) => number) => history.map((m, index) => `${x(index)},${y(value(m))}`).join(' ');
  const app = (m: Metrics) => m.memory_used - m.memory_compressed;
  const area = (top: (m: Metrics) => number, bottom: (m: Metrics) => number) =>
    `${line(top)} ${history.map((m, index) => `${x(index)},${y(bottom(m))}`).reverse().join(' ')}`;
  return (
    <svg className="ct-memchart" viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden>
      <polygon points={area(app, () => 0)} fill="color-mix(in srgb, var(--counter) 22%, transparent)" />
      <polygon points={area((m) => m.memory_used, app)} fill="color-mix(in srgb, var(--rubric) 26%, transparent)" />
      <polyline points={line(app)} fill="none" stroke="var(--counter)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      <polyline points={line((m) => m.memory_used)} fill="none" stroke="var(--rubric)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      <polyline points={line((m) => m.swap_used)} fill="none" stroke="var(--ink-3)" strokeWidth="1" strokeDasharray="3 2" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** CPU (blue) and GPU (orange) temperature over time, on a 30–100 °C scale. */
function TempChart({ history }: { history: Metrics[] }) {
  if (history.length < 2) return <svg className="ct-memchart" viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden />;
  const x = (index: number) => (index / (history.length - 1)) * 120;
  const y = (celsius: number) => 33 - ((Math.min(Math.max(celsius, 30), 100) - 30) / 70) * 32;
  const line = (value: (m: Metrics) => number | null | undefined) => history.filter((m) => value(m) != null).length < 2 ? '' :
    history.map((m, index) => (value(m) != null ? `${x(index)},${y(value(m)!)}` : '')).filter(Boolean).join(' ');
  const cpu = line((m) => m.cpu_temp);
  const gpu = line((m) => m.gpu_temp);
  return (
    <svg className="ct-memchart" viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden>
      <line x1="0" x2="120" y1={y(90)} y2={y(90)} stroke="var(--rule-2)" strokeDasharray="2 3" vectorEffect="non-scaling-stroke" />
      {gpu && <polyline points={gpu} fill="none" stroke="var(--rubric)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />}
      {cpu && <polyline points={cpu} fill="none" stroke="var(--counter)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />}
    </svg>
  );
}

/** Samples kept across mounts, per computer, so switching the side pane away and back keeps the curves. */
const kept = new Map<string, Metrics[]>();

export function useMetrics() {
  const { client, node } = useRuntime();
  const key = node ?? '';
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [history, setHistory] = useState<Metrics[]>([]);
  useEffect(() => {
    const samples = kept.get(key) ?? [];
    setHistory(samples);
    setMetrics(samples[samples.length - 1] ?? null);
    client.call<Metrics>('system.metrics', {}).then((sample) => sample && setMetrics(sample)).catch(() => undefined);
  }, [client, key]);
  useEvent('system.sample', (_topic, data) => {
    const sample = data as Metrics;
    if (!sample?.at) return;
    setMetrics(sample);
    const samples = [...(kept.get(key) ?? []).slice(-(HISTORY - 1)), sample];
    kept.set(key, samples);
    setHistory(samples);
  });
  return { metrics, history };
}

export function useModel() {
  const client = useRuntime().client;
  const [info, setInfo] = useState<ModelInfo | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  useEffect(() => {
    let stopped = false;
    const read = () => client.call<ModelInfo>('model.info', {}, { signal: AbortSignal.timeout(4000) })
      .then((value) => { if (!stopped) { setInfo(value); setProblem(null); } })
      .catch((cause) => { if (!stopped) setProblem(errorMessage(cause)); });
    void read();
    const timer = setInterval(read, 10_000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [client]);
  return { info, problem };
}

/** `OFFICE · GEMMA 4 E4B · LOCAL`, `CODING · QWEN3.8 27B · VIA CORTEXCODE`. */
export function modelLabel(info: ModelInfo | null, problem: string | null): string {
  if (!info) return problem ? 'NO MODEL YET' : 'MODEL …';
  const tag = (info.tags?.[0] ?? 'office').toUpperCase();
  const name = (info.variant || info.model_id || info.family).replace(/[-_]/g, ' ').toUpperCase();
  const source = info.extra?.source;
  const where = source === 'borrowed' ? `VIA ${(info.extra?.holder ?? 'MESH').toString().toUpperCase()}` : source === 'none' ? 'NOT LOADED' : 'LOCAL';
  return `${tag} · ${name} · ${where}`;
}

/** `computer`: the joined computer the focused shell runs on, named in blue (none: this Mac). */
export function Sidebar({ computer, onAsk, onSignal, onInvestigate }: { computer?: string; onAsk: (text: string, intent: 'ask' | 'explain') => void; onSignal: (proc: Proc, signal: string) => void; onInvestigate: (pid: number) => void }) {
  const { metrics, history } = useMetrics();
  return (
    <div className="ct-machine" aria-label={computer ?? 'This machine'}>
      <div className="ct-side-head">
        {computer ? <span className="ct-label ct-blue">{computer.toUpperCase()}</span> : <span className="ct-label ct-faint">THIS MAC</span>}
        <span className="grow" />
        <span className="ct-label ct-blue">{metrics ? `${(metrics.machine || '').replace('Apple ', '').toUpperCase()} · ${Math.round(metrics.memory_total / GB)} GB · ${(metrics.thermal || 'nominal').toUpperCase()}` : '…'}</span>
      </div>
      <div className="ct-tiles three">
        <Tile label="CPU" value={metrics ? `${Math.round(metrics.cpu)}%` : '–'} values={history.map((m) => m.cpu)} max={100}
          note={metrics && metrics.p_cores ? `P ${metrics.p_cores} · E ${metrics.e_cores} · load ${metrics.load[0].toFixed(1)}` : metrics ? `load ${metrics.load[0].toFixed(1)}` : ''} />
        <div className="ct-tile">
          <div className="ct-tile-head"><span className="ct-faint">MEM</span><span className="grow" /><span>{metrics ? `${(metrics.memory_used / GB).toFixed(1)}/${Math.round(metrics.memory_total / GB)} GB` : '–'}</span></div>
          <MemChart history={history} total={metrics?.memory_total ?? 0} />
          <div className="ct-tile-note ct-memkey">{metrics ? <>
            <span className="app">apps {size(metrics.memory_used - metrics.memory_compressed)}</span>
            <span className="comp">compressed {size(metrics.memory_compressed)}</span>
            {metrics.swap_used > 0 && <span className="swap">swap {size(metrics.swap_used)}</span>}
            <span className={metrics.pressure === 'normal' ? 'ct-faint' : 'ct-warn'}>{metrics.pressure}</span>
          </> : ''}</div>
        </div>
        <Tile label="GPU" value={metrics?.gpu != null ? `${Math.round(metrics.gpu)}%` : '–'} values={history.map((m) => m.gpu ?? 0)} max={100}
          note={metrics ? [metrics.gpu_active != null ? `awake ${Math.round(metrics.gpu_active)}%` : '', metrics.gpu_power != null ? `${metrics.gpu_power.toFixed(1)} W` : '', metrics.ane_power ? `ANE ${metrics.ane_power.toFixed(1)} W` : ''].filter(Boolean).join(' · ') : ''} />
      </div>
      <div className="ct-tiles three">
        <Tile label="NET" value={metrics ? `↓${rate(metrics.net_rx)}` : '–'} values={history.map((m) => m.net_rx + m.net_tx)} note={metrics ? `↑${rate(metrics.net_tx)}` : ''} />
        <Tile label="DISK" value={metrics ? `${Math.round(metrics.disk_free / GB)} GB free` : '–'} values={history.map((m) => m.disk_write)}
          note={metrics ? `r ${rate(metrics.disk_read)} · w ${rate(metrics.disk_write)}` : ''} />
        <div className="ct-tile">
          <div className="ct-tile-head"><span className="ct-faint">TEMP</span><span className="grow" /><span className={(metrics?.cpu_temp ?? 0) >= 90 ? 'ct-warn' : ''}>{metrics?.cpu_temp != null ? `${Math.round(metrics.cpu_temp)}°C` : '–'}</span></div>
          <TempChart history={history} />
          <div className="ct-tile-note ct-memkey">{metrics ? <>
            {metrics.cpu_temp != null && <span className="app">cpu {Math.round(metrics.cpu_temp)}°</span>}
            {metrics.gpu_temp != null && <span className="comp">gpu {Math.round(metrics.gpu_temp)}°</span>}
            <span className="swap">{metrics.fan_rpm ? `fan ${metrics.fan_rpm} rpm` : 'no fan'}</span>
          </> : ''}</div>
        </div>
      </div>
      <Processes onAsk={onAsk} onSignal={onSignal} onInvestigate={onInvestigate} />
    </div>
  );
}

function Tile({ label, value, values, max, note }: { label: string; value: string; values: number[]; max?: number; note?: string }) {
  return (
    <div className="ct-tile">
      <div className="ct-tile-head"><span className="ct-faint">{label}</span><span className="grow" /><span>{value}</span></div>
      <Spark values={values} max={max} />
      {note && <div className="ct-faint ct-tile-note">{note}</div>}
    </div>
  );
}

const QUESTION = /\?$|^(who|what|why|which|how|is|are|does|can)\b/i;

export function Processes({ onAsk, onSignal, onInvestigate, wide }: { onAsk: (text: string, intent: 'ask' | 'explain') => void; onSignal: (proc: Proc, signal: string) => void; onInvestigate: (pid: number) => void; wide?: boolean }) {
  const client = useRuntime().client;
  const [group, setGroup] = useState<'flat' | 'app' | 'tree'>(wide ? 'app' : 'flat');
  const [sort, setSort] = useState<'cpu' | 'memory' | 'gpu'>('memory');
  const [filter, setFilter] = useState('');
  const [groups, setGroups] = useState<ProcessGroup[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const asking = QUESTION.test(filter.trim());

  useEffect(() => {
    let stopped = false;
    const read = () => client.call<{ groups: ProcessGroup[] }>('system.processes', { group, sort, filter: asking ? '' : filter, limit: wide ? 200 : 40 })
      .then((list) => { if (!stopped) { setGroups(list?.groups ?? []); setProblem(null); } })
      .catch((cause) => { if (!stopped) setProblem(errorMessage(cause)); });
    void read();
    const timer = setInterval(read, 3000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [group, sort, filter, asking, wide, client]);

  const rows = useMemo(() => {
    if (group !== 'app') return (groups[0]?.processes ?? []).map((proc) => ({ proc, depth: 0 }));
    return groups.flatMap((entry) => [{ proc: { pid: -1, ppid: 0, name: entry.name, command: `${entry.processes.length} processes`, user: '', cpu: entry.cpu, memory: entry.memory, disk_write: entry.disk_write, ports: entry.ports, gpu: entry.gpu, app: entry.name, started: 0, pgid: 0 } as Proc, depth: 0 }]);
  }, [groups, group]);

  const depthOf = useMemo(() => {
    if (group !== 'tree') return new Map<number, number>();
    const parent = new Map<number, number>();
    for (const { proc } of rows) parent.set(proc.pid, proc.ppid);
    const depth = new Map<number, number>();
    for (const { proc } of rows) {
      let d = 0;
      let at = proc.ppid;
      while (parent.has(at) && d < 12) { d++; at = parent.get(at)!; }
      depth.set(proc.pid, d);
    }
    return depth;
  }, [rows, group]);

  return (
    <div className="ct-procs">
      <div className="ct-side-head">
        <span className="ct-label ct-faint">PROCESSES</span>
        <span className="grow" />
        {(['flat', 'app', 'tree'] as const).map((name) => (
          <button key={name} type="button" className={`ct-seg${group === name ? ' on' : ''}`} onClick={() => setGroup(name)}>{name === 'flat' ? 'ALL' : name.toUpperCase()}</button>
        ))}
      </div>
      <label className="ct-find">
        <span className="ct-label ct-faint">FIND OR ASK</span>
        <input type="text" value={filter} placeholder="name, :port, or a question" spellCheck={false}
          onChange={(event) => setFilter(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && asking) {
              onAsk(filter.trim(), 'ask');
              setFilter('');
            }
          }} />
      </label>
      {asking && <p className="ct-hint">↵ asks the terminal flow about the machine.</p>}
      {problem && <p className="ct-hint ct-warn">{problem}</p>}
      <div className="ct-proc-table ct-mono" role="table" aria-label="Processes">
        <div className="ct-proc-row head" role="row">
          <span className="name">NAME</span>
          <button type="button" className={`num ${sort === 'memory' ? 'on' : ''}`} onClick={() => setSort('memory')}>MEM</button>
          <button type="button" className={`num ${sort === 'cpu' ? 'on' : ''}`} onClick={() => setSort('cpu')}>CPU</button>
          <button type="button" className={`num ${sort === 'gpu' ? 'on' : ''}`} onClick={() => setSort('gpu')}>GPU</button>
          <span className="port">PORT</span>
        </div>
        {rows.map(({ proc }) => (
          <div key={`${proc.pid}:${proc.name}`} className={`ct-proc${open === proc.pid ? ' open' : ''}${proc.cpu > 50 ? ' hot' : ''}`} role="row">
            <button type="button" className="ct-proc-row" onClick={() => setOpen(open === proc.pid ? null : proc.pid)}>
              <span className="name" style={{ paddingLeft: `${(depthOf.get(proc.pid) ?? 0) * 10}px` }}>
                {proc.name} <span className="ct-faint">{proc.pid > 0 ? proc.pid : proc.command}</span>
              </span>
              <span className="num">{size(proc.memory)}</span>
              <span className={`num${proc.cpu > 50 ? ' ct-warn' : ''}`}>{proc.cpu.toFixed(0)}%</span>
              <span className={`num${(proc.gpu ?? 0) > 50 ? ' ct-warn' : ''}`}>{proc.gpu != null ? `${proc.gpu.toFixed(0)}%` : '–'}</span>
              <span className="port ct-blue">{proc.ports.slice(0, 2).join(' ') || '–'}</span>
            </button>
            {open === proc.pid && (
              <div className="ct-proc-more">
                {proc.command && proc.pid > 0 && <div className="ct-faint ct-proc-cmd">{proc.command}</div>}
                <div className="ct-proc-actions">
                  <button type="button" className="detent sm warn" onClick={() => onAsk(processQuestion(proc), 'explain')}>EXPLAIN</button>
                  {proc.pid > 0 && <>
                    <button type="button" className="detent sm blue" onClick={() => onInvestigate(proc.pid)}>INVESTIGATE</button>
                    <button type="button" className="detent sm" onClick={() => onSignal(proc, 'TERM')}>TERMINATE</button>
                    <button type="button" className="detent sm" onClick={() => onSignal(proc, 'KILL')}>KILL</button>
                    <button type="button" className="detent sm" onClick={() => onSignal(proc, 'STOP')}>PAUSE</button>
                    <button type="button" className="detent sm" onClick={() => onSignal(proc, 'CONT')}>RESUME</button>
                  </>}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function processQuestion(proc: Proc): string {
  if (proc.pid < 0) return `What is the app "${proc.name}" (${proc.command}), using ${proc.cpu.toFixed(0)}% CPU and ${size(proc.memory)}?`;
  const ports = proc.ports.length ? `, listening on ${proc.ports.map((port) => `:${port}`).join(' ')}` : '';
  return `What is the process "${proc.name}" (pid ${proc.pid}, command \`${proc.command || proc.name}\`, user ${proc.user || 'me'}), using ${proc.cpu.toFixed(0)}% CPU and ${size(proc.memory)}${ports}? Is it safe to stop?`;
}
