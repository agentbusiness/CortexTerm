/**
 * CortexTerm's built-in views: the explicit `edit` editor, a Run's log, the process view and
 * alerts with the security sweep. Standard shell tools keep their own terminal interfaces.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Compartment, EditorState } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap, undo, redo, deleteLine } from '@codemirror/commands';
import { search, openSearchPanel, replaceAll, searchKeymap } from '@codemirror/search';
import { LanguageDescription, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language';
import { languages } from '@codemirror/language-data';
import { ago, errorMessage, useRuntime } from '@cortex/sdk';
import type { FileText, Histogram, Proc, Run, RunOutput } from './api';
import { quote, seconds, shortPath, size } from './api';
import { Processes } from './Sidebar';
import type { PaneRec } from './store';
import { SecurityPane } from './SecurityProtection';

const languageSlot = new Compartment();

type Ask = (text: string, intent: 'ask' | 'explain' | 'fix', runId?: string) => void;

interface PaneControls { focused: boolean; onFocus: () => void; onShelf: () => void; onClose: () => void; bare?: boolean }

export function PaneFrame({ pane, focused, title, status, onFocus, onClose, children, tools, bare }: PaneControls & {
  pane: PaneRec; title: string; status?: string; children: React.ReactNode; tools?: React.ReactNode;
}) {
  // In the side pane a view has no frame of its own: the side pane's toggles name it.
  if (bare) return <div className="ct-sideview" data-kind={pane.kind}>{(status || tools) && <div className="ct-sideview-head">{status && <span className="ct-label ct-faint">{status}</span>}<span className="grow" />{tools}</div>}{children}</div>;
  return (
    <section className={`ct-pane ct-view${focused ? ' focused' : ''}`} onMouseDown={onFocus} aria-label={title} data-kind={pane.kind}>
      <header className="ct-pane-head">
        <span className="ct-dot idle" aria-hidden />
        <span className="ct-label">{title}</span>
        {status && <span className="ct-label ct-faint">{status}</span>}
        <span className="grow" />
        {tools}
        <button type="button" className="ct-icon" title="Close (⌘W)" aria-label="Close" onClick={(event) => { event.stopPropagation(); onClose(); }}>×</button>
      </header>
      {children}
    </section>
  );
}

// --- the editor -------------------------------------------------------------------------------

export function EditorPane({ pane, focused, bare, home, onFocus, onShelf, onClose, onRunReal }: PaneControls & {
  pane: PaneRec; home: string; onRunReal: (command: string) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const [file, setFile] = useState<FileText | null>(null);
  const [dirty, setDirty] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const client = useRuntime().client;
  const saveRef = useRef<() => void>(() => undefined);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    let cancelled = false;
    client.call<FileText>('terminal.file.read', { path: pane.path ?? '', cwd: pane.cwd })
      .then((text) => !cancelled && setFile(text))
      .catch((cause) => !cancelled && setProblem(errorMessage(cause)));
    return () => { cancelled = true; };
  }, [pane.path, pane.cwd, client]);

  useEffect(() => {
    if (!file || file.too_large || !host.current) return;
    const nano = keymap.of([
      { key: 'Ctrl-o', run: () => { saveRef.current(); return true; } },
      { key: 'Mod-s', run: () => { saveRef.current(); return true; } },
      { key: 'Ctrl-x', run: () => { closeRef.current(); return true; } },
      { key: 'Ctrl-w', run: openSearchPanel },
      { key: 'Ctrl-\\', run: (target) => { openSearchPanel(target); return replaceAll(target) || true; } },
      { key: 'Ctrl-k', run: deleteLine },
      { key: 'Alt-u', run: undo },
      { key: 'Alt-e', run: redo },
    ]);
    const state = EditorState.create({
      doc: file.text,
      extensions: [
        lineNumbers(), history(), drawSelection(), highlightActiveLine(), search({ top: true }),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }), languageSlot.of([]),
        nano, keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) setDirty(true);
        }),
        EditorView.theme({ '&': { height: '100%' }, '.cm-scroller': { fontFamily: 'var(--font-mono)' } }),
      ],
    });
    const editor = new EditorView({ state, parent: host.current });
    view.current = editor;
    // The language by the file's name (nginx.conf, Dockerfile, *.yaml, ...).
    const language = LanguageDescription.matchFilename(languages, file.path);
    if (language) {
      void language.load().then((support) => editor.dispatch({ effects: languageSlot.reconfigure(support) })).catch(() => undefined);
    }
    // The Line had the keyboard when the command was typed: hand it to the editor once it is drawn.
    const focusTimer = setTimeout(() => editor.focus(), 80);
    return () => {
      clearTimeout(focusTimer);
      editor.destroy();
      view.current = null;
    };
  }, [file]);

  saveRef.current = () => {
    const editor = view.current;
    if (!editor || !file) return;
    setProblem(null);
    client.call<{ modified: number }>('terminal.file.write', { path: file.path, text: editor.state.doc.toString(), expected_modified: file.modified || null })
      .then((result) => {
        setFile((current) => (current ? { ...current, modified: result.modified, exists: true } : current));
        setDirty(false);
        setSaved(new Date().toLocaleTimeString());
      })
      .catch((cause) => setProblem(errorMessage(cause)));
  };

  const name = (file?.path ?? pane.path ?? '').split('/').pop() ?? '';
  const status = dirty ? '● MODIFIED' : saved ? `SAVED ${saved}` : file && !file.exists ? 'NEW FILE' : '';
  return (
    <PaneFrame pane={pane} focused={focused} bare={bare} onFocus={onFocus} onShelf={onShelf} onClose={onClose} title={`EDIT · ${name.toUpperCase()}`} status={status}
      tools={<>
        <span className="ct-label ct-faint ct-clip" title={file?.path}>{file ? shortPath(file.path, home) : ''}{file && !file.writable ? ' · READ ONLY' : ''}</span>
        <button type="button" className="detent sm" onClick={() => onRunReal(`nano ${quote(pane.path ?? '')}`)}>OPEN IN NANO</button>
      </>}>
      {problem && <p className="ct-hint ct-warn">{problem}{/needs admin/i.test(problem) ? ' Use sudo nano to edit a file that needs admin rights.' : ''}</p>}
      {file?.too_large && <p className="ct-hint">This file is too large or not text for the editor ({size(file.bytes)}). View it with less {quote(pane.path ?? '')}.</p>}
      <div className="ct-editor" ref={host} />
      <footer className="ct-nano ct-mono">
        <span><b>^O</b> Save</span><span><b>^X</b> Close</span><span><b>^W</b> Find</span><span><b>^\</b> Replace</span><span><b>^K</b> Cut line</span><span><b>M-U</b> Undo</span><span><b>⌘S</b> Save</span>
      </footer>
    </PaneFrame>
  );
}

// --- a Run's log view -------------------------------------------------------------------------

/** One Run's output as a log: lines over time, a filter, the lines. `named` puts the command on top
 *  (the side pane's LOG, where nothing else says which Run it is). */
export function RunPane({ pane, focused, bare, home, named, inCard, onFocus, onShelf, onClose, onAsk, onRun }: PaneControls & { pane: PaneRec; home: string; named?: boolean; inCard?: boolean; onAsk: Ask; onRun?: (command: string) => void }) {
  const [run, setRun] = useState<Run | null>(null);
  const [histogram, setHistogram] = useState<Histogram | null>(null);
  const [output, setOutput] = useState<RunOutput | null>(null);
  const [filter, setFilter] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const client = useRuntime().client;
  const runId = pane.runId ?? '';

  useEffect(() => {
    client.call<{ runs: Run[] }>('terminal.runs', { limit: 200 }).then((list) => setRun(list?.runs?.find((entry) => entry.id === runId) ?? null)).catch(() => undefined);
    client.call<Histogram>('terminal.run.histogram', { run_id: runId, buckets: 40 }).then(setHistogram).catch(() => undefined);
  }, [runId, client]);

  useEffect(() => {
    const timer = setTimeout(() => {
      client.call<RunOutput>('terminal.run.output', { run_id: runId, from: -400, count: 400, filter })
        .then((result) => { setOutput(result); setProblem(null); })
        .catch((cause) => setProblem(errorMessage(cause)));
    }, 150);
    return () => clearTimeout(timer);
  }, [runId, filter, client]);

  const top = Math.max(1, ...(histogram?.buckets ?? []).map((bucket) => bucket.info + bucket.warn + bucket.error));
  const totals = (histogram?.buckets ?? []).reduce((all, bucket) => ({ info: all.info + bucket.info, warn: all.warn + bucket.warn, error: all.error + bucket.error }), { info: 0, warn: 0, error: 0 });
  const worst = useMemo(() => (output?.lines ?? []).filter((line) => line.level === 'error').slice(-12), [output]);
  // Over time only says something when the lines came at different times.
  const spread = (histogram?.buckets ?? []).filter((bucket) => bucket.info + bucket.warn + bucket.error > 0).length > 1;
  const leveled = (output?.lines ?? []).some((line) => line.level && line.level !== 'info');
  return (
    <PaneFrame pane={pane} focused={focused} bare={bare} onFocus={onFocus} onShelf={onShelf} onClose={onClose} title={`RUN · ${run?.command ?? pane.title}`.toUpperCase()}
      status={named || inCard ? undefined : run ? `${shortPath(run.cwd, home)} · ${seconds(run.duration_ms)} · ${run.lines} LINES · ${run.format.toUpperCase()}` : ''}>
      <div className="ct-runview">
        {named && (
          <header className="ct-runview-head">
            <div className="ct-runview-title"><span className="ct-label ct-faint">OUTPUT OF</span><span className="grow" /><button type="button" className="detent sm" onClick={onClose}>CLOSE</button></div>
            <code className="ct-block-cmd">{run?.command ?? pane.title}</code>
            {run && <span className="ct-label ct-faint">{`IN ${shortPath(run.cwd, home)} · ${run.exit_code === 0 ? 'OK' : run.ended == null ? 'RUNNING' : `EXIT ${run.exit_code}`} · ${seconds(run.duration_ms)} · ${run.lines} LINES · ${ago(run.started)}`.toUpperCase()}</span>}
          </header>
        )}
        {spread && <div className="ct-hist-legend ct-label">
          <span className="ct-faint">LINES OVER TIME</span><span>■ INFO {totals.info}</span><span className="ct-lift">■ WARN {totals.warn}</span><span className="ct-warn">■ ERROR {totals.error}</span>
        </div>}
        {spread && <div className="ct-hist" aria-hidden>
          {(histogram?.buckets ?? []).map((bucket) => (
            <div key={bucket.at} className="ct-hist-col" title={new Date(bucket.at).toLocaleTimeString()}>
              <span className="error" style={{ height: `${(bucket.error / top) * 100}%` }} />
              <span className="warn" style={{ height: `${(bucket.warn / top) * 100}%` }} />
              <span className="info" style={{ height: `${(bucket.info / top) * 100}%` }} />
            </div>
          ))}
        </div>}
        <label className="ct-find">
          <input type="text" value={filter} placeholder="Filter the lines: text, or level>=warn" spellCheck={false} onChange={(event) => setFilter(event.target.value)} />
          <span className="ct-label">{output ? `${output.matched} OF ${output.total}` : ''}</span>
        </label>
        {(totals.warn + totals.error > 0 || leveled) && <div className="ct-quick">
          {['', 'level>=warn', 'level>=error'].map((value) => (
            <button key={value || 'all'} type="button" className={`detent sm${filter === value ? ' warn' : ''}`} onClick={() => setFilter(value)}>{value ? value.replace('level>=', '').toUpperCase() + '+' : 'ALL'}</button>
          ))}
          <span className="grow" />
          {worst.length > 0 && <button type="button" className="detent sm warn" onClick={() => onAsk(`These errors came from \`${run?.command ?? ''}\`. What is the cause?\n${worst.map((line) => line.text).join('\n')}`, 'explain', runId)}>EXPLAIN THE ERRORS</button>}
        </div>}
        {problem && <p className="ct-hint ct-warn">{problem}</p>}
        <div className="ct-loglines ct-mono">
          {(output?.lines ?? []).map((line) => (
            <div key={line.n} className={`ct-logline ${line.level}`}>
              <span className="ct-faint n">{line.n + 1}</span>
              {leveled && <span className={`lvl ${line.level}`}>{line.level && line.level !== 'info' ? line.level.toUpperCase() : ''}</span>}
              <span className="t">{line.text}</span>
              <LineActions text={line.text} cwd={run?.cwd ?? pane.cwd} command={run?.command ?? pane.title} onExplain={(text) => onAsk(text, 'explain')} onRun={onRun} onFilter={setFilter} />
            </div>
          ))}
          {output && output.lines.length === 0 && <p className="ct-hint">No lines{filter ? ' match' : ''}.</p>}
        </div>
      </div>
    </PaneFrame>
  );
}

/** What a line of output is about: a name in the Run's folder (one word, as `ls` prints it) is a
 *  file you can open or show in Finder; any line can be explained, copied or used to filter. */
export function LineActions({ text, cwd, command, onExplain, onRun, onFilter }: {
  text: string; cwd: string; command: string; onExplain: (text: string) => void; onRun?: (command: string) => void; onFilter?: (text: string) => void;
}) {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const name = /^[^\s:'"]+$/.test(trimmed) && trimmed.length < 200 ? trimmed : '';
  const path = name ? (name.startsWith('/') || name.startsWith('~') ? name : `${cwd}/${name}`) : '';
  return (
    <span className="ct-rowacts">
      {path && onRun && <button type="button" className="ct-act" title={`open ${path}`} onClick={() => onRun(`open ${quote(path)}`)}>open</button>}
      {path && onRun && <button type="button" className="ct-act" title="Show it in Finder" onClick={() => onRun(`open -R ${quote(path)}`)}>finder</button>}
      <button type="button" className="ct-act" onClick={() => onExplain(`this line of \`${command}\` output: ${trimmed}`)}>explain</button>
      <button type="button" className="ct-act" onClick={() => void navigator.clipboard?.writeText(text).catch(() => undefined)}>copy</button>
      {onFilter && <button type="button" className="ct-act" title="Only lines like this one" onClick={() => onFilter(trimmed.split(/\s+/).slice(0, 3).join(' '))}>only these</button>}
    </span>
  );
}

// --- the process view -------------------------------------------------------------------------

export function ProcessPane({ pane, focused, bare, onFocus, onShelf, onClose, onAsk, onSignal, onInvestigate }: PaneControls & { pane: PaneRec; onAsk: Ask; onSignal: (proc: Proc, signal: string) => void; onInvestigate: (pid: number) => void }) {
  return (
    <PaneFrame pane={pane} focused={focused} bare={bare} onFocus={onFocus} onShelf={onShelf} onClose={onClose} title="PROCESS VIEW" status="OPENED FOR TOP / HTOP · ! FOR THE REAL ONE">
      <div className="ct-processview"><Processes wide onAsk={(text, intent) => onAsk(text, intent)} onSignal={onSignal} onInvestigate={onInvestigate} /></div>
    </PaneFrame>
  );
}

// --- alerts and security ---------------------------------------------------------------------

export function AlertsPane({ pane, focused, bare, onFocus, onShelf, onClose, onAsk, onCommand }: PaneControls & { pane: PaneRec; onAsk: Ask; onCommand: (command: string) => void }) {
  return (
    <PaneFrame pane={pane} focused={focused} bare={bare} onFocus={onFocus} onShelf={onShelf} onClose={onClose} title="ALERTS & SECURITY">
      <div className="ct-alerts"><SecurityPane onAsk={onAsk} onCommand={onCommand} /></div>
    </PaneFrame>
  );
}
