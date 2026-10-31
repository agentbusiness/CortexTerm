/**
 * The Line: one input for shell commands and plain language. Before Enter it says what the input
 * is (SHELL / ASK, with AUTO when it decided), what would run, where, what its globs match and how
 * risky it is (`terminal.assess`: the risk engine is code, not the model). Tab completes
 * (`terminal.complete`), → takes the grey contextual suggestion, ⌘I switches shell / ask.
 *
 * The paste guard shows here too: what the scan found (a pasted command reads stronger), the
 * script a `curl … | sh` would run (CHECK SCRIPT FIRST: fetched, scanned, never run), known
 * malware among the packages an install names (OSV), and RUN SANDBOXED (no access to secrets).
 */

import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { useEvent, useJournal, useRuntime } from '@cortex/sdk';
import type { Assessment, Completion, Completions, PackageCheck, Run, Script } from './api';
import { size, shortPath } from './api';
import { riskLabel } from './TermPane';
import { byteCursor, contextualSuggestion, inputText, shellSuggestion, textCursor } from './suggestions';
import { EditFiles, EDIT_FILES_ID, editQuery, useEditFiles } from './EditFiles';

export interface LineHandle {
  focus: () => void;
  set: (text: string) => void;
}

export interface LineProps {
  termId?: string;
  sessionId?: string;
  home: string;
  disabled?: string | null;
  onShell: (command: string, how: 'here' | 'pane' | 'background' | 'watch') => void;
  onAsk: (text: string, intent: 'ask' | 'explain') => void;
  onEdit: (path: string) => void;
}

type Mode = 'shell' | 'ask' | 'unsure';
type Client = ReturnType<typeof useRuntime>['client'];

const DANGEROUS = new Set(['delete', 'admin', 'unknown']);
const NO_RUNS: Run[] = [];
/** Lines of a fetched script shown before it is explained or run. */
const SCRIPT_LINES = 40;
/** What the model is given of a script to explain. */
const SCRIPT_EXPLAINED = 8000;

export const Line = forwardRef<LineHandle, LineProps>(function Line({ termId, sessionId, home, disabled, onShell, onAsk, onEdit }, ref) {
  const [value, setValue] = useState('');
  const [forced, setForced] = useState<Mode | null>(null);
  const [assessed, setAssessed] = useState<{ termId: string; client: Client; result: Assessment } | null>(null);
  const [completions, setCompletions] = useState<Completions | null>(null);
  const [picked, setPicked] = useState(0);
  const [prediction, setPrediction] = useState<{ value: string; termId: string; client: Client; text: string } | null>(null);
  const [runContext, setRunContext] = useState<{ termId: string; client: Client; runs: Run[] } | null>(null);
  const [focused, setFocused] = useState(false);
  const [atEnd, setAtEnd] = useState(true);
  const [composing, setComposing] = useState(false);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [preview, setPreview] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [more, setMore] = useState(false);
  const [historyAt, setHistoryAt] = useState(-1);
  const [packages, setPackages] = useState<PackageCheck | null>(null);
  const [script, setScript] = useState<{ loading: boolean; script?: Script; error?: string } | null>(null);
  const [guardError, setGuardError] = useState('');
  const pasted = useRef(false);
  const input = useRef<HTMLTextAreaElement>(null);
  const client = useRuntime().client;
  const journal = useJournal(sessionId ?? null);
  const assessment = assessed?.termId === termId && assessed?.client === client ? assessed.result : null;
  const editActive = forced !== 'ask' && editQuery(value) !== null;
  const mode: Mode = forced ?? (editActive ? 'shell' : value.startsWith('?') ? 'ask' : value.startsWith('!') ? 'shell' : assessment?.kind ?? 'shell');
  const currentInput = useRef({ value, termId, client, mode });
  currentInput.current = { value, termId, client, mode };
  const runs = runContext?.termId === termId && runContext?.client === client ? runContext.runs : NO_RUNS;
  const cwd = assessment?.cwd ?? runs.at(-1)?.cwd ?? '';
  const contextual = useMemo(() => contextualSuggestion(value, mode, journal.entries, termId, runs, cwd), [value, mode, journal.entries, termId, runs, cwd]);
  const predicted = prediction?.value === value && prediction.termId === termId && prediction.client === client && mode === 'shell' ? prediction.text : null;
  const suggestion = focused && atEnd && !composing && !disabled && !editActive && !completions && dismissed !== value ? contextual ?? predicted : null;
  const filePicker = useEditFiles(value, termId, editActive && !disabled && !composing, (next) => {
    setValue(next);
    setCompletions(null);
    setHistoryAt(-1);
    requestAnimationFrame(() => {
      input.current?.focus();
      input.current?.setSelectionRange(next.length, next.length);
    });
  }, (path) => { onEdit(path); reset(); }, () => reset());

  useEffect(() => {
    setCompletions(null);
    setHistory([]);
    setHistoryAt(-1);
  }, [termId, client]);

  useImperativeHandle(ref, () => ({
    focus: () => input.current?.focus(),
    set: (text: string) => {
      pasted.current = false;
      setValue(text);
      setForced('shell');
      setDismissed(null);
      requestAnimationFrame(() => {
        input.current?.focus();
        input.current?.setSelectionRange(text.length, text.length);
      });
    },
  }), []);

  // What the input is and does, a moment after typing stops.
  useEffect(() => {
    setConfirm(false);
    setScript(null);
    setGuardError('');
    if (!value.trim()) pasted.current = false;
    if (!value.trim() || !termId) {
      setAssessed(null);
      return;
    }
    let stopped = false;
    const timer = setTimeout(() => {
      client.call<Assessment>('terminal.assess', { term_id: termId, input: value, pasted: pasted.current })
        .then((result) => { if (!stopped) setAssessed({ termId, client, result }); })
        .catch(() => { if (!stopped) setAssessed(null); });
    }, 120);
    return () => { stopped = true; clearTimeout(timer); };
  }, [value, termId, client]);

  // Only shell mode asks the completion broker. Conversation predictions are local and instant.
  useEffect(() => {
    setPrediction(null);
    if (!termId || !focused || !atEnd || composing || disabled || editActive || mode !== 'shell' || dismissed === value) return;
    const { text } = inputText(value);
    if (text.trim().length < 2 || /[\r\n]/.test(text)) return;
    let stopped = false;
    const timer = setTimeout(() => {
      client.call<Completions>('terminal.complete', { term_id: termId, line: text, cursor: byteCursor(text) })
        .then((result) => {
          if (stopped || !result) return;
          const next = shellSuggestion(value, result);
          if (next) setPrediction({ value, termId, client, text: next });
        })
        .catch(() => undefined);
    }, 160);
    return () => { stopped = true; clearTimeout(timer); };
  }, [value, termId, client, mode, focused, atEnd, composing, disabled, editActive, dismissed]);

  // Refresh context on focus and live Run events, not on every keystroke.
  useEffect(() => {
    if (!termId || !focused) return;
    let stopped = false;
    client.call<{ runs: Run[] }>('terminal.runs', { term_id: termId, limit: 100 })
      .then((list) => {
        if (stopped) return;
        setRunContext((context) => {
          const all = new Map((list?.runs ?? []).map((run) => [run.id, run]));
          if (context?.termId === termId && context.client === client) context.runs.forEach((run) => {
            const fetched = all.get(run.id);
            if (!fetched || (fetched.ended == null && run.ended != null)) all.set(run.id, run);
          });
          return { termId, client, runs: [...all.values()].sort((a, b) => a.started - b.started).slice(-100) };
        });
      }).catch(() => undefined);
    return () => { stopped = true; };
  }, [termId, client, focused]);
  useEvent('terminal.run.', (topic, data) => {
    if (topic !== 'terminal.run.started' && topic !== 'terminal.run.finished') return;
    const run = data as Run;
    if (!run || run.term_id !== termId || !termId) return;
    setRunContext((context) => ({ termId, client, runs: [...(context?.termId === termId && context.client === client ? context.runs : [])
      .filter((entry) => entry.id !== run.id), run].sort((a, b) => a.started - b.started).slice(-100) }));
  });

  // The packages an install names, looked up in OSV (the network; never in assess itself).
  const installs = assessment && assessment.kind !== 'ask' && assessment.risk !== 'read' ? assessment.text : '';
  useEffect(() => {
    setPackages(null);
    if (!installs) return;
    let stopped = false;
    const timer = setTimeout(() => {
      client.call<PackageCheck>('terminal.packages.check', { text: installs })
        .then((result) => { if (!stopped && result?.packages.length) setPackages(result); })
        .catch(() => undefined);
    }, 400);
    return () => { stopped = true; clearTimeout(timer); };
  }, [installs, client]);

  // The field grows with what is typed (a long line wraps), up to six lines.
  useEffect(() => {
    const field = input.current;
    if (!field) return;
    field.style.height = 'auto';
    field.style.height = `${Math.min(field.scrollHeight, 120)}px`;
  }, [value]);

  const loadHistory = () => {
    client.call<{ runs: Run[] }>('terminal.runs', { limit: 100 })
      .then((list) => {
        if (currentInput.current.client !== client || currentInput.current.termId !== termId) return;
        const seen = new Set<string>();
        setHistory((list?.runs ?? []).map((run) => run.command).filter((command) => command && !seen.has(command) && (seen.add(command), true)));
      })
      .catch(() => undefined);
  };

  const text = value.replace(/^[?!]\s*/, '');
  const threats = assessment?.threats ?? [];
  const malware = packages?.packages.filter((p) => p.malicious.length > 0) ?? [];
  const vulnerable = packages?.packages.filter((p) => p.vulns.length > 0) ?? [];
  const scriptUrl = threats.some((t) => t.rule === 'pipe-to-shell') ? text.match(/https?:\/\/[^\s'"|;)`]+/)?.[0] ?? null : null;

  const reset = () => {
    setValue('');
    setForced(null);
    setAssessed(null);
    setCompletions(null);
    setPrediction(null);
    setDismissed(null);
    setConfirm(false);
    setPreview(false);
    setHistoryAt(-1);
    setPackages(null);
    setScript(null);
    setGuardError('');
    pasted.current = false;
  };

  const submit = (how: 'here' | 'pane' | 'background' | 'watch' = 'here') => {
    if (editActive) { filePicker.accept(); return; }
    if (!text.trim()) return;
    if (mode !== 'shell') {
      onAsk(text, 'ask');
      reset();
      return;
    }
    const risky = (assessment && !assessment.safe && DANGEROUS.has(assessment.risk)) || Boolean(malware.length);
    if (risky && !confirm) {
      setConfirm(true);
      return;
    }
    onShell(text, how);
    reset();
  };

  const complete = () => {
    if (!termId) return;
    const cursor = input.current?.selectionStart ?? value.length;
    const field = input.current;
    client.call<Completions>('terminal.complete', { term_id: termId, line: value, cursor: byteCursor(value, cursor) })
      .then((result) => {
        if (currentInput.current.client !== client || currentInput.current.termId !== termId || currentInput.current.mode !== mode) return;
        if (!field || input.current !== field || field.value !== value || field.selectionStart !== cursor) return;
        if (!result || result.items.length === 0) {
          setCompletions(null);
          return;
        }
        const normalized = { ...result, from: textCursor(value, result.from) };
        if (normalized.items.length === 1) {
          accept(normalized, normalized.items[0]!);
          return;
        }
        setCompletions(normalized);
        setPicked(0);
      })
      .catch(() => undefined);
  };

  const accept = (result: Completions, item: Completion) => {
    const cursor = input.current?.selectionStart ?? value.length;
    const before = value.slice(0, result.from);
    const after = value.slice(cursor);
    const tail = item.kind === 'dir' && !item.value.endsWith('/') ? '/' : item.kind === 'dir' ? '' : ' ';
    const next = `${before}${item.value}${tail}${after}`;
    setValue(next);
    setCompletions(null);
    setDismissed(null);
    requestAnimationFrame(() => {
      const at = before.length + item.value.length + tail.length;
      input.current?.setSelectionRange(at, at);
    });
  };

  const onKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (composing || event.nativeEvent.isComposing) return;
    if (filePicker.onKey(event)) return;
    const meta = event.metaKey || event.ctrlKey;
    if (completions) {
      if (event.key === 'ArrowDown') { event.preventDefault(); setPicked((at) => (at + 1) % completions.items.length); return; }
      if (event.key === 'ArrowUp') { event.preventDefault(); setPicked((at) => (at - 1 + completions.items.length) % completions.items.length); return; }
      if (event.key === 'Tab' || (event.key === 'Enter' && !meta)) { event.preventDefault(); { const item = completions.items[picked]; if (item) accept(completions, item); } return; }
      if (event.key === 'Escape') { event.preventDefault(); setCompletions(null); return; }
    }
    if (event.key === 'Tab') {
      event.preventDefault();
      complete();
      return;
    }
    if (event.key === 'ArrowRight' && !meta && !event.altKey && !event.shiftKey && suggestion?.startsWith(value)
      && input.current?.selectionStart === value.length && input.current.selectionEnd === value.length) {
      event.preventDefault();
      setValue(suggestion);
      setHistoryAt(-1);
      requestAnimationFrame(() => input.current?.setSelectionRange(suggestion.length, suggestion.length));
      return;
    }
    if (meta && event.key.toLowerCase() === 'i') {
      event.preventDefault();
      setForced(mode === 'shell' ? 'ask' : 'shell');
      return;
    }
    if (meta && event.key.toLowerCase() === 'e') {
      event.preventDefault();
      if (text.trim()) onAsk(text, 'explain');
      return;
    }
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      if (event.altKey) setPreview((shown) => !shown);
      else submit(meta ? 'pane' : 'here');
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      if (confirm) setConfirm(false);
      else if (suggestion) setDismissed(value);
      else reset();
      return;
    }
    if ((event.key === 'ArrowUp' || event.key === 'ArrowDown') && !value.includes('\n') && (value === '' || historyAt >= 0)) {
      event.preventDefault();
      if (history.length === 0) return;
      const next = event.key === 'ArrowUp' ? Math.min(historyAt + 1, history.length - 1) : historyAt - 1;
      setHistoryAt(next);
      setValue(next >= 0 ? history[next] ?? '' : '');
    }
  };

  const checkScript = () => {
    if (!scriptUrl) return;
    setScript({ loading: true });
    client.call<Script>('terminal.script.fetch', { url: scriptUrl })
      .then((fetched) => setScript({ loading: false, script: fetched }))
      .catch((failure: unknown) => setScript({ loading: false, error: failure instanceof Error ? failure.message : String(failure) }));
  };
  const runSandboxed = () => {
    if (!termId) return;
    setGuardError('');
    client.call<{ command: string }>('terminal.sandbox.wrap', { term_id: termId, command: text })
      .then((wrapped) => { onShell(wrapped.command, 'here'); reset(); })
      .catch((failure: unknown) => setGuardError(failure instanceof Error ? failure.message : String(failure)));
  };
  const explainScript = (fetched: Script) => {
    const shown = fetched.text.slice(0, SCRIPT_EXPLAINED);
    onAsk(`Explain what this script from ${fetched.url} does before I run \`${text}\`${fetched.text.length > shown.length ? ' (its beginning)' : ''}:\n\n${shown}`, 'explain');
  };

  const auto = forced === null && !value.startsWith('?') && !value.startsWith('!');
  const matches = assessment?.matches;
  const ghost = suggestion ? suggestion.slice(value.length) : '';

  return (
    <div className={`composer flush ct-line${disabled ? ' off' : ''}`} data-mode={editActive ? 'edit' : mode}>
      {editActive && focused && !disabled && <EditFiles picker={filePicker} cwd={shortPath(cwd, home)} termId={termId} />}
      {!editActive && completions && (
        <ul className="ct-complete" role="listbox" aria-label="Completions">
          {completions.items.slice(0, 12).map((item, index) => (
            <li key={`${item.kind}:${item.value}`} role="option" aria-selected={index === picked} className={index === picked ? 'on' : ''}
              onMouseDown={(event) => { event.preventDefault(); accept(completions, item); }}>
              <span className="ct-label ct-kind">{item.kind.toUpperCase()}</span>
              <span className="ct-mono">{item.value}</span>
              <span className="grow" />
              <span className="ct-faint">{item.description}</span>
            </li>
          ))}
          <li className="ct-complete-foot ct-label ct-faint">⇥ ACCEPT · ↑↓ CHOOSE · ESC CLOSE</li>
        </ul>
      )}
      <div className={`ct-write${editActive ? ' edit' : mode === 'shell' ? ' shell' : ' ask'}`} onMouseDown={(event) => { if (event.target === event.currentTarget) { event.preventDefault(); input.current?.focus(); } }}>
        <button type="button" className="ct-mode" onClick={() => setForced(mode === 'shell' ? 'ask' : 'shell')}
          title={editActive ? 'Find a file · Escape to cancel · click or ⌘I to ask about this text' : auto ? 'Decided from what you type · click or ⌘I to switch' : 'Click or ⌘I to switch'}>{editActive ? 'EDIT' : mode === 'shell' ? 'SHELL' : 'ASK'}</button>
        <div className="ct-write-field">
          <div className="ct-line-mirror" aria-hidden>
            {mode === 'shell' && !editActive ? highlight(value) : <span>{value}</span>}
            <span className="ct-ghost">{ghost}</span>
          </div>
          <textarea
            ref={input}
            className="ct-line-input"
            aria-label={editActive ? 'Find a file to edit' : 'Command or question'}
            role={editActive ? 'combobox' : undefined}
            aria-expanded={editActive ? focused : undefined}
            aria-controls={editActive && focused ? EDIT_FILES_ID : undefined}
            aria-activedescendant={editActive && focused && filePicker.items[filePicker.picked] ? `${EDIT_FILES_ID}-${filePicker.picked}` : undefined}
            rows={1}
            spellCheck={false}
            aria-autocomplete={editActive ? 'list' : 'inline'}
            value={value}
            disabled={Boolean(disabled)}
            placeholder={disabled ?? (termId ? 'Type a command, ask in plain words, or edit to find a file…' : 'Open a shell to run commands (⌘T), or ask in plain words…')}
            onFocus={() => { setFocused(true); loadHistory(); }}
            onBlur={() => setFocused(false)}
            onSelect={(event) => setAtEnd(event.currentTarget.selectionStart === value.length && event.currentTarget.selectionEnd === value.length)}
            onChange={(event) => { setValue(event.target.value); setHistoryAt(-1); setCompletions(null); setDismissed(null);
              setAtEnd(event.target.selectionStart === event.target.value.length && event.target.selectionEnd === event.target.value.length); }}
            onCompositionStart={() => setComposing(true)}
            onCompositionEnd={() => setComposing(false)}
            onPaste={() => { pasted.current = true; }}
            onKeyDown={onKey}
          />
        </div>
        <div className="ct-line-acts">
          {value.trim() && !editActive && <button type="button" className="ct-more-btn" aria-expanded={more} onClick={() => setMore((open) => !open)} title="More ways to run it">⋯</button>}
          {more && !editActive && (
            <div className="ct-line-menu" role="menu" onMouseLeave={() => setMore(false)}>
              {mode === 'shell' ? (<>
                <button type="button" role="menuitem" onClick={() => { setMore(false); setPreview((shown) => !shown); }}>Preview what it touches <span className="k">⌥↵</span></button>
                <button type="button" role="menuitem" onClick={() => { setMore(false); submit('pane'); }}>Run in a new shell <span className="k">⌘↵</span></button>
                <button type="button" role="menuitem" onClick={() => { setMore(false); submit('background'); }}>Run in the background</button>
                <button type="button" role="menuitem" onClick={() => { setMore(false); submit('watch'); }}>Run and tell me when it ends</button>
                <button type="button" role="menuitem" onClick={() => { setMore(false); onAsk(text, 'explain'); }}>Explain it <span className="k">⌘E</span></button>
              </>) : (
                <button type="button" role="menuitem" onClick={() => { setMore(false); setForced('shell'); }}>It's a command <span className="k">⌘I</span></button>
              )}
            </div>
          )}
          <button type="button" className={`ct-send${confirm && !editActive ? ' confirm' : ''}`}
            disabled={editActive ? filePicker.busy || filePicker.opening || !termId || (filePicker.picked < 0 && !editQuery(value)?.trim()) : !value.trim()}
            onClick={() => submit('here')}>
            {editActive ? (filePicker.opening ? 'OPENING' : filePicker.items[filePicker.picked]?.kind === 'dir' ? 'BROWSE' : filePicker.items[filePicker.picked]?.kind === 'new' ? 'CREATE' : 'OPEN') : mode === 'shell' ? (confirm ? 'CONFIRM' : 'RUN') : 'ASK'} <span aria-hidden>↵</span>
          </button>
        </div>
      </div>
      {value.trim() && !editActive && mode === 'shell' && assessment && (confirm || !assessment.safe || (assessment.matches && assessment.matches.files + assessment.matches.dirs > 0)) && (
        <div className={`ct-preview${confirm ? ' confirm' : ''}`}>
          {assessment.program && <span><span className="ct-faint">RUNS</span> {assessment.program}</span>}
          <span><span className="ct-faint">IN</span> {shortPath(assessment.cwd, home)}</span>
          {matches && (matches.files + matches.dirs > 0) && (
            <span><span className="ct-faint">MATCHES</span> {matches.dirs > 0 ? `${matches.dirs} folders + ` : ''}{matches.files} files · {size(matches.bytes)}</span>
          )}
          <span className={`ct-label ${assessment.safe ? 'ct-ok' : 'ct-warn'}`}>{riskLabel(assessment)}{!assessment.safe && DANGEROUS.has(assessment.risk) ? ' · ASKS FIRST' : ''}</span>
          {assessment.reasons.length > 0 && <span className="ct-faint">{assessment.reasons.join(' · ')}</span>}
          {confirm && <span className="ct-label ct-warn">PRESS ↵ AGAIN TO RUN · ESC TO STOP</span>}
        </div>
      )}
      {value.trim() && !editActive && mode === 'shell' && (threats.length > 0 || malware.length > 0 || vulnerable.length > 0) && (
        <div className="ct-preview-list">
          {threats.map((threat) => (
            <div key={threat.rule}><span className="ct-label ct-warn">{threat.severity === 'high' ? 'DANGER' : 'CAUTION'}</span> {threat.text}</div>
          ))}
          {malware.map((p) => (
            <div key={`mal:${p.name}`}><span className="ct-label ct-warn">KNOWN MALWARE</span> {p.name} is a malicious {p.ecosystem} package ({p.malicious.slice(0, 3).join(', ')}).</div>
          ))}
          {vulnerable.map((p) => (
            <div key={`vuln:${p.name}`} className="ct-faint">{p.name} {p.version} has {p.vulns.length === 1 ? 'a known vulnerability' : `${p.vulns.length} known vulnerabilities`} ({p.vulns.slice(0, 3).join(', ')}{p.vulns.length > 3 ? ', …' : ''}).</div>
          ))}
          {threats.length > 0 && (
            <div className="ct-asks-row">
              {pasted.current && <span className="ct-label ct-warn">PASTED</span>}
              {scriptUrl && !script && <button type="button" className="detent sm solid" onClick={checkScript}>CHECK SCRIPT FIRST</button>}
              <button type="button" className="detent sm" onClick={() => onAsk(`The paste guard flagged this command: ${text}`, 'explain')}>EXPLAIN</button>
              <button type="button" className="detent sm" onClick={runSandboxed} title="Writes only in this folder, temp and caches; no access to SSH and cloud keys, keychains or browser data">RUN SANDBOXED</button>
              {guardError && <span className="ct-warn">{guardError}</span>}
            </div>
          )}
        </div>
      )}
      {script && (
        <div className="ct-preview-list">
          {script.loading && <div className="ct-faint">Fetching {scriptUrl}… (it is not run)</div>}
          {script.error && <div className="ct-warn">{script.error}</div>}
          {script.script && (<>
            <div>
              <span className="ct-label ct-faint">SCRIPT</span> {script.script.url} · {size(script.script.bytes)}{' '}
              <span className={`ct-label ${script.script.threats.length ? 'ct-warn' : 'ct-ok'}`}>{script.script.threats.length ? `${script.script.threats.length} FINDINGS` : 'NOTHING FOUND'}</span>
            </div>
            {script.script.threats.map((threat) => (
              <div key={threat.rule}><span className="ct-label ct-warn">{threat.severity === 'high' ? 'DANGER' : 'CAUTION'}</span> {threat.text}</div>
            ))}
            <pre className="ct-mono">{script.script.text.split('\n').slice(0, SCRIPT_LINES).join('\n')}</pre>
            {script.script.text.split('\n').length > SCRIPT_LINES && <div className="ct-faint">… {script.script.text.split('\n').length - SCRIPT_LINES} more lines{script.script.truncated ? ' (and more not fetched)' : ''}</div>}
            <div className="ct-asks-row">
              <button type="button" className="detent sm solid" onClick={() => explainScript(script.script!)}>EXPLAIN</button>
              <button type="button" className="detent sm" onClick={() => { onShell(text, 'here'); reset(); }}>RUN</button>
            </div>
          </>)}
        </div>
      )}
      {preview && matches && matches.sample.length > 0 && (
        <div className="ct-preview-list ct-mono">
          {matches.sample.map((path) => <div key={path}>{shortPath(path, home)}</div>)}
          {matches.files + matches.dirs > matches.sample.length && <div className="ct-faint">… and {matches.files + matches.dirs - matches.sample.length} more</div>}
        </div>
      )}
    </div>
  );
});

/** Colour a command line: the program, flags, globs and strings. */
function highlight(line: string) {
  const parts: { text: string; cls: string }[] = [];
  const pattern = /("[^"]*"?|'[^']*'?|\s+|[|&;<>()]+|[^\s|&;<>()"']+)/g;
  let first = true;
  for (const match of line.matchAll(pattern)) {
    const token = match[0];
    let cls = '';
    if (/^\s+$/.test(token)) cls = '';
    else if (/^[|&;<>()]+$/.test(token)) { cls = 'op'; first = true; parts.push({ text: token, cls }); continue; }
    else if (first && !/^\w+=/.test(token)) { cls = 'prog'; first = false; }
    else if (token.startsWith('-')) cls = 'flag';
    else if (/[*?[\]{}]/.test(token)) cls = 'glob';
    else if (/^["']/.test(token)) cls = 'str';
    else if (token.startsWith('$')) cls = 'var';
    parts.push({ text: token, cls });
  }
  return parts.map((part, index) => <span key={index} className={part.cls ? `hl-${part.cls}` : undefined}>{part.text}</span>);
}
