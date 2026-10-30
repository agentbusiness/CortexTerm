/**
 * A shell, shown as a stream: every command is a block (what ran, where, how it ended, its output
 * in its own colours) and every question to the terminal flow is a block in the same timeline,
 * like a conversation. You type in the Line, never at a prompt here. The live terminal (xterm.js
 * over `terminal.*`) is underneath all along: it takes the pane when a program needs the keyboard
 * (a full-screen tool, a password, a question it asks), and the TERMINAL toggle shows it any time.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebglAddon } from '@xterm/addon-webgl';
import '@xterm/xterm/css/xterm.css';
import { activeTheme, currentGround, useRuntime, subscribeTheme, useEvent, useJournal, type TermSnapshot } from '@cortex/sdk';
import type { Ask, Assessment, OutputLine, Run, RunOutput, Threat } from './api';
import { quote, seconds, shortPath } from './api';
import { live, useLive, type PaneRec } from './store';
import { LineActions, RunPane } from './Views';

function palette() {
  return activeTheme()?.xterm[currentGround()];
}

function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export interface TermActions {
  runCommand: (termId: string, command: string) => void;
  editCommand: (command: string) => void;
  openRun: (run: Run) => void;
  fix: (pane: PaneRec, run: Run) => void;
  explain: (pane: PaneRec, text: string) => void;
}

/** Lines a finished block shows before "N more lines". */
const SHOWN_LINES = 24;
/** Lines fetched per block (the full output is the LOG view's). */
const FETCHED_LINES = 400;
/** Blocks kept in the stream (older ones stay in the Run ledger). */
const KEPT_RUNS = 60;

export function TermPane({ pane, focused, sessionId, computer, home, onFocus, actions }: {
  pane: PaneRec;
  focused: boolean;
  sessionId?: string;
  /** The joined computer the shell runs on, by name (none: this one). */
  computer?: string;
  home: string;
  slot: number;
  onFocus: () => void;
  onShelf: () => void;
  onClose: () => void;
  actions: TermActions;
}) {
  useLive();
  const termId = pane.termId ?? '';
  useEffect(() => {
    if (termId) live.ensure(termId, pane.node);
  }, [termId, pane.node]);
  const state = live.states.get(termId);
  const [raw, setRaw] = useState(false);
  // A program that needs the keyboard gets the live terminal; it goes back to the stream after.
  // Only a full-screen program (vim, htop) takes the live terminal; a quiet command never does.
  const needsKeys = Boolean(state?.alternate_screen);
  const showTerminal = raw || needsKeys;

  return (
    <section className={`ct-pane ct-term${focused ? ' focused' : ''}`} onMouseDown={onFocus} aria-label={`Shell ${pane.title}`}>
      <div className="ct-term-float">
        {computer && <span className="ct-label ct-blue">{computer.toUpperCase()}</span>}
        <Crumbs cwd={state?.cwd || pane.cwd} home={home} branch={state?.git_branch ?? null} onGo={(path) => actions.runCommand(termId, `cd ${quote(path)}`)} />
        <span className="grow" />
        {state?.running && <span className="ct-label ct-blue">RUNNING</span>}
        {needsKeys && <span className="ct-label ct-lift">THE PROGRAM HAS THE KEYBOARD</span>}
        <button type="button" className="ct-act" disabled={needsKeys} onClick={() => setRaw((value) => !value)}
          title="The live terminal, as the shell draws it">{showTerminal ? 'blocks' : 'terminal'}</button>
      </div>
      {termId && !showTerminal && <Stream pane={pane} termId={termId} sessionId={sessionId} home={home} actions={actions} />}
      {termId ? <XTerm termId={termId} visible={showTerminal} focused={focused} /> : <p className="ct-empty">This pane has no shell.</p>}
    </section>
  );
}

// --- the stream --------------------------------------------------------------------------------

interface Exchange {
  runId: string;
  at: number;
  question: string;
  intent: string;
  answer: string;
  streaming: boolean;
  /** What the turn is doing until the answer's text streams (`reading the skills`, `waiting for a free model`). */
  phase?: string;
  command?: string;
  assessment?: Assessment | null;
  error?: string;
  state?: string;
  /** Read-only checks the flow ran to answer, in order. */
  steps: Step[];
}

interface Step { command: string; output: string; exitCode: number | null; running: boolean }

type Item = { kind: 'run'; at: number; run: Run } | { kind: 'ask'; at: number; exchange: Exchange };

function useRuns(termIds: string[]): Run[] {
  const client = useRuntime().client;
  const [runs, setRuns] = useState<Run[]>([]);
  const key = termIds.join(',');
  useEffect(() => {
    let stopped = false;
    Promise.all(termIds.map((id) => client.call<{ runs: Run[] }>('terminal.runs', { term_id: id, limit: KEPT_RUNS }).catch(() => ({ runs: [] as Run[] }))))
      .then((lists) => {
        if (stopped) return;
        const all = lists.flatMap((list) => list?.runs ?? []).sort((a, b) => a.started - b.started);
        setRuns(all.slice(-KEPT_RUNS));
      });
    return () => { stopped = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, client]);
  const upsert = (run: Run) => {
    if (!run || !termIds.includes(run.term_id)) return;
    setRuns((all) => {
      const at = all.findIndex((entry) => entry.id === run.id);
      const next = at >= 0 ? all.map((entry, index) => (index === at ? run : entry)) : [...all, run];
      return next.slice(-KEPT_RUNS);
    });
  };
  useEvent('terminal.run.started', (_topic, data) => upsert(data as Run));
  useEvent('terminal.run.finished', (_topic, data) => upsert(data as Run));
  return runs;
}

function useExchanges(sessionId: string | undefined, termId: string): { exchanges: Exchange[]; loaded: boolean } {
  const journal = useJournal(sessionId ?? null);
  const exchanges = useMemo(() => {
    const byRun = new Map<string, Exchange>();
    const order: Exchange[] = [];
    for (const entry of journal.entries) {
      const data = (entry.data ?? {}) as Record<string, unknown>;
      const runId = String(data.run_id ?? '');
      if (entry.kind === 'user_message') {
        if (data.term_id !== termId) continue;
        const exchange: Exchange = { runId, at: entry.ts_ms, question: String(data.text ?? ''), intent: String(data.intent ?? 'ask'), answer: '', streaming: false, steps: [] };
        byRun.set(runId, exchange);
        order.push(exchange);
        continue;
      }
      const exchange = byRun.get(runId);
      if (!exchange) continue;
      if (entry.kind === 'assistant_message') {
        exchange.answer = String(data.text ?? '');
        exchange.streaming = Boolean(data.streaming);
        exchange.phase = typeof data.phase === 'string' ? data.phase : undefined;
      } else if (entry.kind === 'command_step') {
        exchange.steps.push({ command: String(data.command ?? ''), output: String(data.output ?? ''), exitCode: typeof data.exit_code === 'number' ? data.exit_code : null, running: Boolean(data.running) });
      } else if (entry.kind === 'command_proposal') {
        exchange.command = String(data.command ?? '');
        exchange.assessment = (data.assessment as Assessment | null) ?? null;
      } else if (entry.kind === 'error') {
        exchange.error = String(data.message ?? 'The answer failed.');
      } else if (entry.kind === 'status') {
        exchange.state = String(data.state ?? '');
      }
    }
    return order.map((exchange) => ({ ...exchange, steps: [...exchange.steps] }));
  }, [journal.entries, termId]);
  return { exchanges, loaded: journal.status !== 'loading' };
}

function Stream({ pane, termId, sessionId, home, actions }: { pane: PaneRec; termId: string; sessionId?: string; home: string; actions: TermActions }) {
  const runs = useRuns([termId, ...(pane.workers ?? [])]);
  const { exchanges, loaded } = useExchanges(sessionId, termId);
  const scroller = useRef<HTMLDivElement>(null);
  const known = useRef<Set<string> | null>(null);
  if (known.current === null && loaded) known.current = new Set(exchanges.map((exchange) => exchange.runId));

  const items = useMemo<Item[]>(() => {
    const all: Item[] = [
      ...runs.map((run) => ({ kind: 'run' as const, at: run.started, run })),
      ...exchanges.map((exchange) => ({ kind: 'ask' as const, at: exchange.at, exchange })),
    ];
    return all.sort((a, b) => a.at - b.at);
  }, [runs, exchanges]);

  // A fresh answer with a command waiting is the pane's attention until it is seen.
  const lastAsk = exchanges.at(-1);
  useEffect(() => {
    const fresh = lastAsk && !known.current?.has(lastAsk.runId) && lastAsk.command && !lastAsk.streaming;
    if (fresh) live.unseen.add(pane.id);
    else live.unseen.delete(pane.id);
    live.changed();
  }, [lastAsk, pane.id]);

  // Follow the end while the reader is there (cards grow after they are drawn: their output loads
  // and streams in, so the content's size is watched); scrolled up, they keep their place and
  // "Latest" brings them back. A new command or question follows the end again.
  const content = useRef<HTMLDivElement>(null);
  const atEnd = useRef(true);
  const [away, setAway] = useState(false);
  useEffect(() => {
    const element = scroller.current;
    const inner = content.current;
    if (!element || !inner) return;
    const follow = () => { if (atEnd.current) element.scrollTop = element.scrollHeight; };
    const observer = new ResizeObserver(follow);
    observer.observe(inner);
    follow();
    return () => observer.disconnect();
  }, []);
  const latestAt = items.at(-1)?.at ?? 0;
  useEffect(() => {
    atEnd.current = true;
    setAway(false);
    const element = scroller.current;
    if (element) element.scrollTop = element.scrollHeight;
  }, [latestAt]);
  const toEnd = () => {
    const element = scroller.current;
    if (!element) return;
    element.scrollTo({ top: element.scrollHeight, behavior: 'smooth' });
    atEnd.current = true;
    setAway(false);
  };

  return (
    <div className="ct-stream-wrap">
      <div className="ct-stream" ref={scroller} onScroll={(event) => {
        const element = event.currentTarget;
        const end = element.scrollHeight - element.scrollTop - element.clientHeight < 48;
        atEnd.current = end;
        setAway(!end);
      }}>
        <div className="ct-stream-inner" ref={content}>
          {items.map((item) => item.kind === 'run'
            ? <RunBlock key={item.run.id} run={item.run} pane={pane} home={home} actions={actions} latest={item.run.id === runs.at(-1)?.id} />
            : <AskBlock key={`ask:${item.exchange.runId}`} exchange={item.exchange} pane={pane} termId={termId} actions={actions} fromHistory={Boolean(known.current?.has(item.exchange.runId))} />)}
        </div>
      </div>
      <div className="conversation-end">
        <button type="button" className="detent conversation-toend" data-shown={away} onClick={toEnd}>
          Latest
          <svg viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 5 6.5 8 3.5" /></svg>
        </button>
      </div>
    </div>
  );
}

function RunBlock({ run, pane, home, actions, latest }: { run: Run; pane: PaneRec; home: string; actions: TermActions; latest: boolean }) {
  const client = useRuntime().client;
  const [output, setOutput] = useState<RunOutput | null>(null);
  // Open by default: a card shows its output; folding one is the person's choice.
  const [open, setOpen] = useState(true);
  void latest;
  const [all, setAll] = useState(false);
  const [view, setView] = useState<'out' | 'table' | 'log' | 'errors'>('out');
  const running = run.ended == null;
  const failed = run.exit_code != null && run.exit_code !== 0;

  useEffect(() => {
    if (!open || run.fullscreen) return;
    let stopped = false;
    const read = () => client.call<RunOutput>('terminal.run.output', { run_id: run.id, from: -FETCHED_LINES, count: FETCHED_LINES })
      .then((result) => { if (!stopped) setOutput(result); })
      .catch(() => undefined);
    void read();
    if (!running) return () => { stopped = true; };
    const timer = setInterval(read, 500);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [open, run.id, running, run.fullscreen, run.lines, client]);

  // Progress bars and spinners redraw the same line many times; the card shows each one's latest frame.
  const lines = useMemo(() => collapseProgress(output?.lines ?? []), [output]);
  const hidden = all || running ? 0 : Math.max(0, lines.length - SHOWN_LINES);
  const shown = hidden ? lines.slice(-SHOWN_LINES) : lines;
  const more = (output ? output.total : run.lines) - shown.length;
  const table = useMemo(() => toTable(lines.map((line) => line.text), run.format), [lines, run.format]);
  const views: ['out' | 'table' | 'log' | 'errors', string][] = [['out', 'output']];
  if (table) views.push(['table', 'table']);
  if (run.lines > 20 || run.format === 'log' || run.format === 'json' || run.format === 'logfmt') views.push(['log', 'log']);
  if (run.errors + run.warnings > 0) views.push(['errors', `errors ${run.errors + run.warnings}`]);
  const copy = () => void navigator.clipboard?.writeText(lines.map((line) => line.text).join('\n')).catch(() => undefined);

  return (
    <article className={`ct-block${failed ? ' failed' : ''}${running ? ' running' : ''}`}>
      <header className="ct-block-head">
        <button type="button" className="ct-block-toggle" aria-expanded={open} title={open ? 'Fold' : 'Show the output'} onClick={() => setOpen((value) => !value)}>
          <code className="ct-mono ct-block-cmd" title={run.command}>{run.command}</code>
        </button>
        <span className="grow" />
        <span className="ct-block-meta">
          {running ? <span className="ct-blue">running</span> : failed ? <span className="ct-warn">✗ exit {run.exit_code}</span> : <span className="ct-ok">✓</span>}
          {!running && <span className="ct-faint">{seconds(run.duration_ms)}</span>}
          {run.usual_ms > 0 && run.duration_ms > run.usual_ms * 2 && !running && <span className="ct-warn">{Math.round(run.duration_ms / run.usual_ms)}× usual</span>}
          {run.errors > 0 && <span className="ct-warn">{run.errors} errors</span>}
          <span className="ct-faint" title={run.cwd}>{shortPath(run.cwd, home)}</span>
        </span>
        {open && !run.fullscreen && views.length > 1 && (
          <span className="ct-views-switch" role="tablist">
            {views.map(([name, label]) => <button key={name} type="button" role="tab" aria-selected={view === name} className={`ct-act${view === name ? ' on' : ''}`} onClick={() => setView(name)}>{label}</button>)}
          </span>
        )}
      </header>
      {open && view === 'table' && table && <TableView table={table} />}
      {open && view === 'log' && <div className="ct-block-log"><RunPane pane={{ id: `log-${run.id}`, kind: 'run', title: run.command, cwd: run.cwd, runId: run.id }} focused={false} bare inCard home={home} onRun={(command) => actions.runCommand(run.term_id, command)} onFocus={() => undefined} onShelf={() => undefined} onClose={() => setView('out')} onAsk={(text, intent, runId) => intent === 'fix' ? actions.fix(pane, run) : actions.explain(pane, runId ? text : text)} /></div>}
      {open && view === 'errors' && (
        <div className="ct-block-out ct-mono">
          {lines.filter((line) => line.level === 'error' || line.level === 'warn').map((line) => <Ansi key={line.n} line={line} />)}
        </div>
      )}
      {open && view === 'out' && !run.fullscreen && shown.length > 0 && (
        <div className="ct-block-out ct-mono">
          {hidden > 0 && <button type="button" className="ct-more" onClick={() => setAll(true)}>{hidden} earlier lines</button>}
          {shown.map((line) => (
            <div key={line.n} className="ct-line-wrap">
              <Ansi line={line} />
              {(line as Collapsed).frames ? <span className="ct-frames">↻ {(line as Collapsed).frames}</span> : null}
              {line.hidden ? <span className="ct-frames ct-warn" title="Invisible characters or terminal codes were removed from this line; you and the assistant read the same text">hidden text removed</span> : null}
              <LineActions text={line.text} cwd={run.cwd} command={run.command} onExplain={(text) => actions.explain(pane, text)} onRun={(command) => actions.runCommand(run.term_id, command)} />
            </div>
          ))}
          {more > 0 && !running && all && lines.length < (output?.total ?? 0) && <button type="button" className="ct-more" onClick={() => actions.openRun(run)}>{(output?.total ?? 0) - lines.length} more in the log view</button>}
        </div>
      )}
      {open && run.fullscreen && <p className="ct-block-note ct-faint">full-screen program</p>}
      {running && !run.fullscreen && <AskRow run={run} />}
      {open && !running && (
        <footer className="ct-block-acts">
          {failed && <button type="button" className="detent sm warn" onClick={() => actions.fix(pane, run)}>EXPLAIN · FIX</button>}
          <button type="button" className="ct-act" onClick={() => actions.explain(pane, run.command)}>explain</button>
          <button type="button" className="ct-act" onClick={() => actions.openRun(run)}>log</button>
          <button type="button" className="ct-act" onClick={copy}>copy</button>
          <button type="button" className="ct-act" onClick={() => actions.runCommand(pane.termId ?? '', run.command)}>run again</button>
          <button type="button" className="ct-act" onClick={() => actions.editCommand(run.command)}>edit</button>
        </footer>
      )}
    </article>
  );
}

/** Where the shell is: each folder from home (or /) down, each one a cd there; then the git branch. */
function Crumbs({ cwd, home, branch, onGo }: { cwd: string; home: string; branch: string | null; onGo: (path: string) => void }) {
  if (!cwd) return null;
  const underHome = home && (cwd === home || cwd.startsWith(`${home}/`));
  const rest = underHome ? cwd.slice(home.length) : cwd;
  const parts = rest.split('/').filter(Boolean);
  const root = underHome ? home : '';
  const crumbs = [{ name: underHome ? '~' : '/', path: root || '/' }, ...parts.map((name, index) => ({ name, path: `${root}/${parts.slice(0, index + 1).join('/')}` }))];
  return (
    <nav className="ct-crumbs" aria-label="Where this shell is">
      {crumbs.map((crumb, index) => (
        <span key={crumb.path} className="ct-crumb">
          {index > 0 && <span className="ct-crumb-sep" aria-hidden>›</span>}
          <button type="button" className={index === crumbs.length - 1 ? 'here' : ''} title={`cd ${crumb.path}`} onClick={() => onGo(crumb.path)} disabled={index === crumbs.length - 1}>{crumb.name}</button>
        </span>
      ))}
      {branch && <span className="ct-crumb-branch" title="git branch"><span aria-hidden>⎇ </span>{branch}</span>}
    </nav>
  );
}

type Collapsed = OutputLine & { frames?: number };

/** A redrawn line's shape without what changes between frames: numbers, bars, spinner glyphs. */
function frameKey(text: string): string {
  return text.replace(/[\d.,:%/]+/g, '0').replace(/[#=>\-─━█▓▒░|*·⠁-⣿⢀-⣿\s]+/g, ' ').replace(/[^\x20-\x7e]/g, '').trim();
}

/** Consecutive frames of the same redrawn line (within a few lines, for several bars at once) become one. */
function collapseProgress(lines: OutputLine[]): Collapsed[] {
  const out: Collapsed[] = [];
  const recent = new Map<string, number>();
  for (const line of lines) {
    const key = frameKey(line.text);
    const at = key.length > 3 ? recent.get(key) : undefined;
    if (at !== undefined && out.length - at <= 8 && /\d/.test(line.text)) {
      out[at] = { ...line, frames: (out[at]!.frames ?? 1) + 1 };
      continue;
    }
    if (key.length > 3) recent.set(key, out.length);
    out.push(line);
  }
  return out;
}

interface Table { head: string[]; rows: string[][] }

/** Output that is a table (`df`, `ps`, `ls -l`, JSON lines) as columns; None when it is not one. */
function toTable(lines: string[], format: string): Table | null {
  const text = lines.filter((line) => line.trim());
  if (text.length < 2) return null;
  if (format === 'json') {
    const rows = text.map((line) => { try { return JSON.parse(line) as Record<string, unknown>; } catch { return null; } }).filter(Boolean) as Record<string, unknown>[];
    if (rows.length < 2) return null;
    const head = [...new Set(rows.flatMap((row) => Object.keys(row)))].slice(0, 12);
    return { head, rows: rows.map((row) => head.map((key) => { const value = row[key]; return value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value); })) };
  }
  const split = (line: string) => line.trim().split(/\s+/);
  const counts = text.slice(1).map((line) => split(line).length);
  const width = Math.min(...counts);
  if (width < 3 || text.length < 3 || counts.filter((count) => count === width).length < counts.length * 0.6) return null;
  let head = split(text[0]!);
  if (head.length > width) head = [...head.slice(0, width - 1), head.slice(width - 1).join(' ')];
  if (head.length < width) return null;
  const rows = text.slice(1).map((line) => { const cells = split(line); return [...cells.slice(0, width - 1), cells.slice(width - 1).join(' ')]; });
  return { head, rows };
}

function TableView({ table }: { table: Table }) {
  const [sort, setSort] = useState<{ col: number; down: boolean } | null>(null);
  const [filter, setFilter] = useState('');
  const value = (cell: string) => { const n = parseFloat(cell.replace(/[%,]/g, '')); return Number.isNaN(n) ? cell.toLowerCase() : n * (/[0-9.]+Ti?$/i.test(cell) ? 1e12 : /[0-9.]+Gi?$/i.test(cell) ? 1e9 : /[0-9.]+Mi?$/i.test(cell) ? 1e6 : /[0-9.]+Ki?$/i.test(cell) ? 1e3 : 1); };
  const rows = table.rows.filter((row) => !filter || row.join(' ').toLowerCase().includes(filter.toLowerCase()));
  if (sort) rows.sort((a, b) => { const x = value(a[sort.col] ?? ''), y = value(b[sort.col] ?? ''); const order = x < y ? -1 : x > y ? 1 : 0; return sort.down ? -order : order; });
  return (
    <div className="ct-table-wrap">
      <input className="ct-table-filter" value={filter} placeholder="filter rows" onChange={(event) => setFilter(event.target.value)} />
      <table className="ct-table ct-mono">
        <thead><tr>{table.head.map((name, col) => (
          <th key={col}><button type="button" className="ct-act" onClick={() => setSort((current) => ({ col, down: current?.col === col ? !current.down : true }))}>{name}{sort?.col === col ? (sort.down ? ' ↓' : ' ↑') : ''}</button></th>
        ))}</tr></thead>
        <tbody>{rows.map((row, index) => <tr key={index}>{row.map((cell, col) => <td key={col}>{cell}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

/**
 * What a running command asks, answered in its card: yes/no, a line of text, or a password (the
 * terminal stopped echoing). A password can be remembered in the Keychain; the next time the same
 * program asks the same thing the terminal plugin fills it in, and this row says so.
 */
function AskRow({ run }: { run: Run }) {
  const client = useRuntime().client;
  useLive();
  const state = live.states.get(run.term_id);
  const mine = state?.running?.id === run.id;
  const ask = mine ? state?.ask ?? null : null;
  const keychain = mine ? state?.keychain ?? null : null;
  const quiet = mine && state?.attention === 'input';
  if (ask) return <AskForm key={`${ask.kind}:${ask.key || ask.text}:${ask.refused}`} termId={run.term_id} ask={ask} />;
  if (keychain) {
    return (
      <div className="ct-asks quiet">
        <div className="ct-asks-head">
          <span className="ct-label ct-blue">FROM KEYCHAIN</span>
          <code className="ct-mono ct-asks-prompt dim">{keychain}</code>
          <span className="grow" />
          <button type="button" className="ct-act" title="Remove it from the Keychain"
            onClick={() => void client.call('terminal.ask.forget', { key: keychain }).catch(() => undefined)}>forget</button>
        </div>
      </div>
    );
  }
  // Quiet with no prompt line: it may still be reading input.
  if (quiet) return <AskForm termId={run.term_id} ask={null} />;
  return null;
}

function AskForm({ termId, ask }: { termId: string; ask: Ask | null }) {
  const [text, setText] = useState('');
  const [typing, setTyping] = useState(false);
  const [remember, setRemember] = useState(Boolean(ask?.refused));
  const [error, setError] = useState('');
  const client = useRuntime().client;
  const answer = (value: string) => {
    setError('');
    client.call('terminal.ask.answer', { term_id: termId, text: value, remember: ask?.kind === 'secret' && remember })
      .then(() => setText(''))
      .catch((failure: unknown) => setError(failure instanceof Error ? failure.message : String(failure)));
  };
  const stop = () => void client.call('terminal.write', { term_id: termId, data: '\x03' }).catch(() => undefined);
  const kind = ask?.kind ?? 'text';
  const secret = kind === 'secret';
  const confirm = kind === 'confirm' && !typing;
  const [yes, no] = ask?.options ?? ['y', 'n'];
  const label = secret ? 'PASSWORD' : ask ? 'ASKS' : 'INPUT';
  const stopButton = <button type="button" className="ct-act" onClick={stop} title="Ctrl-C">stop ⌃C</button>;

  return (
    <div className="ct-asks" onKeyDown={(event) => {
      if (!confirm || event.metaKey || event.ctrlKey || event.altKey) return;
      const key = event.key.toLowerCase();
      if (key === 'y') { event.preventDefault(); answer(yes!); }
      else if (key === 'n') { event.preventDefault(); answer(no!); }
    }}>
      <div className="ct-asks-head">
        <span className="ct-label ct-lift">{label}</span>
        {ask?.refused
          ? <span className="ct-asks-note ct-warn">The saved password was refused. Type it; it replaces the saved one.</span>
          : ask?.text ? <code className="ct-mono ct-asks-prompt">{ask.text}</code> : !ask && <span className="ct-asks-note">The command is quiet; it may be reading input.</span>}
        <span className="grow" />
        {ask?.program && !ask.refused && <span className="ct-label ct-faint">{ask.program}</span>}
      </div>
      {confirm ? (
        <div className="ct-asks-row">
          {[[yes!, 'YES', 'Y'], [no!, 'NO', 'N']].map(([value, word, key]) => {
            const isDefault = ask?.default === value;
            return (
              <button key={value} type="button" className={`detent${isDefault ? ' solid' : ''}`} autoFocus={isDefault} onClick={() => answer(value!)}>
                {word} <span className="k">{key}{isDefault ? ' ↵' : ''}</span>
              </button>
            );
          })}
          <span className="grow" />
          <button type="button" className="ct-act" onClick={() => setTyping(true)}>type answer</button>
          {stopButton}
        </div>
      ) : (
        <form className="ct-asks-row" onSubmit={(event) => { event.preventDefault(); answer(text); }}>
          <input type={secret ? 'password' : 'text'} value={text} autoFocus spellCheck={false} autoComplete="off"
            placeholder={secret ? '' : ask?.default ? `↵ keeps ${ask.default}` : 'answer ↵'}
            onChange={(event) => setText(event.target.value)} aria-label={secret ? 'Password for the running command' : 'Answer for the running command'} />
          <button type="submit" className="detent" aria-pressed="true">SEND <span className="k">↵</span></button>
          {stopButton}
        </form>
      )}
      {secret && (
        <div className="ct-asks-keep">
          <button type="button" className="sw" aria-pressed={remember} aria-label="Remember in Keychain" onClick={() => setRemember((value) => !value)} />
          <span>Remember in Keychain for <code className="ct-mono">{ask!.key}</code></span>
        </div>
      )}
      {error && <p className="ct-asks-note ct-warn">{error}</p>}
    </div>
  );
}

function AskBlock({ exchange, pane, termId, actions, fromHistory }: { exchange: Exchange; pane: PaneRec; termId: string; actions: TermActions; fromHistory: boolean }) {
  const [open, setOpen] = useState(true);
  void fromHistory;
  const [done, setDone] = useState(false);
  // The command block is shown on its own below; the gap it leaves in the text closes up.
  const prose = exchange.answer.replace(/```[\s\S]*?(```|$)/g, '').replace(/\n{3,}/g, '\n\n').trim();
  const checking = exchange.steps.find((step) => step.running);
  const thinking = exchange.state === 'running' && !exchange.answer && !checking;
  const risk = exchange.assessment;
  const seen = () => {
    setDone(true);
    live.unseen.delete(pane.id);
    live.changed();
  };
  return (
    <article className="ct-block ask">
      <header className="ct-block-head">
        <button type="button" className="ct-block-toggle" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        <span className="ct-ask-q" data-intent={exchange.intent}>{exchange.intent !== 'ask' && <span className="ct-ask-label">{exchange.intent === 'fix' ? 'FIX' : 'EXPLAIN'}</span>}{exchange.question}</span>
        </button>
        {thinking && <span className="ct-act static">{exchange.phase ? `${exchange.phase}…` : exchange.steps.length ? 'reading the output…' : 'reading the shell…'}</span>}
        {checking && <span className="ct-act static">checking…</span>}
      </header>
      {open && (
        <div className="ct-ask-body">
          {exchange.steps.map((step, index) => <CheckStep key={index} step={step} />)}
          {prose && <p className="ct-reading"><Prose text={prose} />{exchange.streaming ? ' ▍' : ''}</p>}
          {exchange.error && <p className="ct-reading ct-warn">{exchange.error}</p>}
          {exchange.command && !exchange.streaming && (
            <div className="ct-proposal">
              <code className="ct-mono">{exchange.command}</code>
              <div className="ct-proposal-row">
                {risk && <span className={`ct-label ${risk.safe ? 'ct-ok' : 'ct-warn'}`}>{riskLabel(risk)}</span>}
                {!done && <>
                  <button type="button" className="detent solid" onClick={() => { actions.runCommand(termId, exchange.command!); seen(); }}>{risk && !risk.safe ? 'RUN ANYWAY' : 'RUN'}</button>
                  <button type="button" className="detent" onClick={() => { actions.editCommand(exchange.command!); seen(); }}>EDIT</button>
                </>}
              </div>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

// --- colours -------------------------------------------------------------------------------------

const BASE = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'] as const;

function colour(index: number): string | undefined {
  const theme = palette() as unknown as Record<string, string> | undefined;
  if (index < 8) return theme?.[BASE[index]!];
  if (index < 16) {
    const name = BASE[index - 8]!;
    return theme?.[`bright${name[0]!.toUpperCase()}${name.slice(1)}`];
  }
  if (index < 232) {
    const n = index - 16;
    const step = (v: number) => (v === 0 ? 0 : 55 + v * 40);
    return `rgb(${step(Math.floor(n / 36))},${step(Math.floor(n / 6) % 6)},${step(n % 6)})`;
  }
  const grey = 8 + (index - 232) * 10;
  return `rgb(${grey},${grey},${grey})`;
}

/** One output line in the colours the program gave it (SGR codes only; the rest was removed). */
function Ansi({ line }: { line: OutputLine }) {
  const cls = `ct-outline${line.level ? ` ${line.level}` : ''}`;
  if (!line.ansi) return <div className={cls}>{line.text || ' '}</div>;
  const parts: { text: string; style: React.CSSProperties }[] = [];
  let style: React.CSSProperties = {};
  const pattern = /\x1b\[([0-9;]*)m/g;
  let at = 0;
  for (const match of line.ansi.matchAll(pattern)) {
    if (match.index! > at) parts.push({ text: line.ansi.slice(at, match.index), style });
    at = match.index! + match[0].length;
    const codes = (match[1] || '0').split(';').map(Number);
    style = { ...style };
    for (let i = 0; i < codes.length; i++) {
      const code = codes[i]!;
      if (code === 0) style = {};
      else if (code === 1) style.fontWeight = 600;
      else if (code === 2) style.opacity = 0.7;
      else if (code === 3) style.fontStyle = 'italic';
      else if (code === 4) style.textDecoration = 'underline';
      else if (code === 22) { delete style.fontWeight; delete style.opacity; }
      else if (code === 39) delete style.color;
      else if (code === 49) delete style.background;
      else if (code >= 30 && code <= 37) style.color = colour(code - 30);
      else if (code >= 90 && code <= 97) style.color = colour(code - 90 + 8);
      else if (code >= 40 && code <= 47) style.background = colour(code - 40);
      else if ((code === 38 || code === 48) && codes[i + 1] === 5) { const value = colour(codes[i + 2] ?? 0); if (code === 38) style.color = value; else style.background = value; i += 2; }
      else if ((code === 38 || code === 48) && codes[i + 1] === 2) { const value = `rgb(${codes[i + 2]},${codes[i + 3]},${codes[i + 4]})`; if (code === 38) style.color = value; else style.background = value; i += 4; }
    }
  }
  if (at < line.ansi.length) parts.push({ text: line.ansi.slice(at), style });
  return <div className={cls}>{parts.map((part, index) => <span key={index} style={part.style}>{part.text}</span>)}</div>;
}

/** The model's light markdown: **bold**, `code` and list bullets; nothing else is interpreted. */
export function Prose({ text }: { text: string }) {
  const parts = text.replace(/^\s*[-*]\s+/gm, '• ').split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return <>{parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) return <b key={index}>{part.slice(2, -2)}</b>;
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) return <code key={index} className="ct-mono ct-inline-code">{part.slice(1, -1)}</code>;
    return <span key={index}>{part.replace(/\*\*/g, '')}</span>;
  })}</>;
}

/** A read-only command the flow ran on its own: the command and how it ended; the output folded. */
function CheckStep({ step }: { step: Step }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="ct-check">
      <button type="button" className="ct-check-head" aria-expanded={open} title={open ? 'Fold' : 'Show the output'} onClick={() => setOpen((value) => !value)}>
        <code className="ct-mono">{step.command}</code>
        <span className="ct-block-meta">
          {step.running ? <span className="ct-blue">running</span> : step.exitCode === null ? <span className="ct-warn">stopped</span> : step.exitCode === 0 ? <span className="ct-ok">✓</span> : <span className="ct-warn">✗ exit {step.exitCode}</span>}
        </span>
      </button>
      {open && !step.running && <pre className="ct-check-out ct-mono">{step.output || '(no output)'}</pre>}
    </div>
  );
}

export function riskLabel(risk: Assessment): string {
  if (risk.safe) return 'READ ONLY';
  const words: Record<string, string> = { write: 'CHANGES FILES', network: 'USES THE NETWORK', delete: 'DELETES', admin: 'NEEDS ADMIN', unknown: "CAN'T PROVE SAFE", read: 'READ ONLY' };
  return words[risk.risk] ?? risk.risk.toUpperCase();
}

// --- the live terminal -----------------------------------------------------------------------------

/**
 * The live terminal. Text pasted straight into it goes through the paste guard first
 * (`terminal.scan`): a paste with a high finding is held until the person says to paste it.
 */
function XTerm({ termId, visible, focused }: { termId: string; visible: boolean; focused: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const [held, setHeld] = useState<{ text: string; threats: Threat[] } | null>(null);
  const client = useRuntime().client;

  useEffect(() => {
    const element = host.current;
    if (!element) return;
    const term = new Terminal({
      fontFamily: activeTheme()?.fonts.mono ?? 'ui-monospace, Menlo, monospace',
      fontSize: 13,
      lineHeight: 1.2,
      cursorBlink: true,
      cursorStyle: 'block',
      allowProposedApi: true,
      scrollback: 5_000,
      theme: palette(),
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(element);
    termRef.current = term;
    fitRef.current = fit;
    try {
      const webgl = new WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch {
      // DOM renderer.
    }
    let lastSize = '';
    const resize = () => {
      if (!element.offsetWidth || !element.offsetHeight) return;
      try {
        fit.fit();
      } catch {
        return;
      }
      const sizeKey = `${term.cols}x${term.rows}`;
      if (sizeKey === lastSize) return;
      lastSize = sizeKey;
      void client.call('terminal.resize', { term_id: termId, cols: term.cols, rows: term.rows }).catch(() => undefined);
    };
    let attached = false;
    const queued: Uint8Array[] = [];
    const offOutput = client.on('terminal.output', (_topic, data) => {
      const event = data as { term_id?: string; data?: string };
      if (event?.term_id !== termId || typeof event.data !== 'string') return;
      const bytes = decodeBase64(event.data);
      if (attached) term.write(bytes);
      else queued.push(bytes);
    });
    client.call<TermSnapshot>('terminal.snapshot', { term_id: termId })
      .then((snapshot) => {
        if (snapshot?.text) {
          term.write(snapshot.text.replace(/\n/g, '\r\n'));
          term.write(`\x1b[${snapshot.cursor_row + 1};${snapshot.cursor_col + 1}H`);
        }
      })
      .catch(() => undefined)
      .finally(() => {
        attached = true;
        for (const bytes of queued.splice(0)) term.write(bytes);
      });
    const input = term.onData((data) => void client.call('terminal.write', { term_id: termId, data }).catch(() => undefined));
    // Before xterm sees a paste: scan it, and hold it when the scan finds something grave.
    const onPaste = (event: ClipboardEvent) => {
      const text = event.clipboardData?.getData('text/plain') ?? '';
      if (!text) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      client.call<{ threats: Threat[] }>('terminal.scan', { text, pasted: true })
        .then((result) => {
          const high = (result?.threats ?? []).filter((threat) => threat.severity === 'high');
          if (high.length) setHeld({ text, threats: high });
          else term.paste(text);
        })
        .catch(() => term.paste(text));
    };
    element.addEventListener('paste', onPaste, true);
    const observer = new ResizeObserver(() => resize());
    observer.observe(element);
    requestAnimationFrame(resize);
    const restyle = () => {
      const colors = palette();
      if (colors) term.options.theme = colors;
    };
    const offTheme = subscribeTheme(restyle);
    return () => {
      offOutput();
      input.dispose();
      element.removeEventListener('paste', onPaste, true);
      observer.disconnect();
      offTheme();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [termId, client]);

  // Shown: fit to the pane and take the keyboard.
  useEffect(() => {
    if (!visible) return;
    requestAnimationFrame(() => {
      try {
        fitRef.current?.fit();
      } catch {
        // Not laid out yet.
      }
      if (focused) termRef.current?.focus();
    });
  }, [visible, focused]);

  const pasteAnyway = () => {
    if (held) termRef.current?.paste(held.text);
    setHeld(null);
    termRef.current?.focus();
  };

  return (
    <>
      {held && visible && (
        <div className="ct-asks" onKeyDown={(event) => { if (event.key === 'Escape') { event.preventDefault(); setHeld(null); termRef.current?.focus(); } }}>
          <div className="ct-asks-head">
            <span className="ct-label ct-warn">PASTE HELD</span>
            <span className="ct-asks-note ct-warn">This paste looks like the commands Mac malware arrives as. Nothing was sent to the shell.</span>
          </div>
          {held.threats.map((threat) => <p key={threat.rule} className="ct-asks-note"><span className="ct-label ct-warn">DANGER</span> {threat.text}</p>)}
          <code className="ct-mono ct-asks-prompt dim" title={held.text}>{held.text.slice(0, 200)}</code>
          <div className="ct-asks-row">
            <button type="button" className="detent solid" autoFocus onClick={() => { setHeld(null); termRef.current?.focus(); }}>DISCARD <span className="k">ESC</span></button>
            <button type="button" className="detent" onClick={pasteAnyway}>PASTE ANYWAY</button>
          </div>
        </div>
      )}
      <div className={`ct-xterm${visible ? '' : ' hidden'}`} ref={host} data-term-id={termId} />
    </>
  );
}

/** Focus the xterm of a pane (clicking into it, or a full-screen program). */
export function focusXterm(termId: string) {
  const element = document.querySelector<HTMLElement>(`.ct-xterm[data-term-id="${termId}"] textarea`);
  element?.focus();
}
