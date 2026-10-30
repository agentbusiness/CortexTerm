/**
 * The Line: one input for shell commands and plain language. Before Enter it says what the input
 * is (SHELL / ASK, with AUTO when it decided), what would run, where, what its globs match and how
 * risky it is (`terminal.assess`: the risk engine is code, not the model). Tab completes
 * (`terminal.complete`), → takes the grey history suggestion, ⌘I switches shell / ask.
 *
 * The paste guard shows here too: what the scan found (a pasted command reads stronger), the
 * script a `curl … | sh` would run (CHECK SCRIPT FIRST: fetched, scanned, never run), known
 * malware among the packages an install names (OSV), and RUN SANDBOXED (no access to secrets).
 */

import { forwardRef, useEffect, useImperativeHandle, useRef, useState, type KeyboardEvent } from 'react';
import { useRuntime } from '@cortex/sdk';
import type { Assessment, Completion, Completions, PackageCheck, Run, Script } from './api';
import { size, shortPath } from './api';
import { riskLabel } from './TermPane';

export interface LineHandle {
  focus: () => void;
  set: (text: string) => void;
}

export interface LineProps {
  termId?: string;
  home: string;
  disabled?: string | null;
  onShell: (command: string, how: 'here' | 'pane' | 'background' | 'watch') => void;
  onAsk: (text: string, intent: 'ask' | 'explain') => void;
  onNative: (view: string, target: string | null | undefined, command: string) => boolean;
}

type Mode = 'shell' | 'ask' | 'unsure';

const DANGEROUS = new Set(['delete', 'admin', 'unknown']);
/** Lines of a fetched script shown before it is explained or run. */
const SCRIPT_LINES = 40;
/** What the model is given of a script to explain. */
const SCRIPT_EXPLAINED = 8000;

export const Line = forwardRef<LineHandle, LineProps>(function Line({ termId, home, disabled, onShell, onAsk, onNative }, ref) {
  const [value, setValue] = useState('');
  const [forced, setForced] = useState<Mode | null>(null);
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [completions, setCompletions] = useState<Completions | null>(null);
  const [picked, setPicked] = useState(0);
  const [suggestion, setSuggestion] = useState<string | null>(null);
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

  useImperativeHandle(ref, () => ({
    focus: () => input.current?.focus(),
    set: (text: string) => {
      pasted.current = false;
      setValue(text);
      setForced('shell');
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
      setAssessment(null);
      setSuggestion(null);
      return;
    }
    const timer = setTimeout(() => {
      client.call<Assessment>('terminal.assess', { term_id: termId, input: value, pasted: pasted.current }).then(setAssessment).catch(() => setAssessment(null));
      if (!value.includes('\n')) {
        client.call<Completions>('terminal.complete', { term_id: termId, line: value, cursor: value.length })
          .then((result) => setSuggestion(result?.suggestion && result.suggestion.startsWith(value) && result.suggestion !== value ? result.suggestion : null))
          .catch(() => setSuggestion(null));
      }
    }, 120);
    return () => clearTimeout(timer);
  }, [value, termId, client]);

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
        const seen = new Set<string>();
        setHistory((list?.runs ?? []).map((run) => run.command).filter((command) => command && !seen.has(command) && (seen.add(command), true)));
      })
      .catch(() => undefined);
  };

  const mode: Mode = forced ?? (value.startsWith('?') ? 'ask' : value.startsWith('!') ? 'shell' : assessment?.kind ?? 'shell');
  const text = value.replace(/^[?!]\s*/, '');
  const threats = assessment?.threats ?? [];
  const malware = packages?.packages.filter((p) => p.malicious.length > 0) ?? [];
  const vulnerable = packages?.packages.filter((p) => p.vulns.length > 0) ?? [];
  const scriptUrl = threats.some((t) => t.rule === 'pipe-to-shell') ? text.match(/https?:\/\/[^\s'"|;)`]+/)?.[0] ?? null : null;

  const reset = () => {
    setValue('');
    setForced(null);
    setAssessment(null);
    setCompletions(null);
    setSuggestion(null);
    setConfirm(false);
    setPreview(false);
    setHistoryAt(-1);
    setPackages(null);
    setScript(null);
    setGuardError('');
    pasted.current = false;
  };

  const submit = (how: 'here' | 'pane' | 'background' | 'watch' = 'here') => {
    if (!text.trim()) return;
    if (mode !== 'shell') {
      onAsk(text, 'ask');
      reset();
      return;
    }
    // A tool CortexTerm has its own view for opens there (nothing runs, so nothing to confirm);
    // `!` in front runs the real one.
    if (how === 'here' && !value.startsWith('!') && assessment?.native_view && onNative(assessment.native_view, assessment.native_target, text)) {
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
    client.call<Completions>('terminal.complete', { term_id: termId, line: value, cursor })
      .then((result) => {
        if (!result || result.items.length === 0) {
          setCompletions(null);
          return;
        }
        if (result.items.length === 1) {
          accept(result, result.items[0]!);
          return;
        }
        setCompletions(result);
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
    requestAnimationFrame(() => {
      const at = before.length + item.value.length + tail.length;
      input.current?.setSelectionRange(at, at);
    });
  };

  const onKey = (event: KeyboardEvent<HTMLTextAreaElement>) => {
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
    if (event.key === 'ArrowRight' && suggestion && input.current?.selectionStart === value.length) {
      event.preventDefault();
      setValue(suggestion);
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
    <div className={`composer flush ct-line${disabled ? ' off' : ''}`} data-mode={mode}>
      {completions && (
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
      <div className={`ct-write${mode === 'shell' ? ' shell' : ' ask'}`} onMouseDown={(event) => { if (event.target === event.currentTarget) { event.preventDefault(); input.current?.focus(); } }}>
        <button type="button" className="ct-mode" onClick={() => setForced(mode === 'shell' ? 'ask' : 'shell')}
          title={auto ? 'Decided from what you type · click or ⌘I to switch' : 'Click or ⌘I to switch'}>{mode === 'shell' ? 'SHELL' : 'ASK'}</button>
        <div className="ct-write-field">
          <div className="ct-line-mirror" aria-hidden>
            {mode === 'shell' ? highlight(value) : <span>{value}</span>}
            <span className="ct-ghost">{ghost}</span>
          </div>
          <textarea
            ref={input}
            className="ct-line-input"
            aria-label="Command or question"
            rows={1}
            spellCheck={false}
            value={value}
            disabled={Boolean(disabled)}
            placeholder={disabled ?? (termId ? 'Type a command, or ask in plain words…   ⇥ complete · ↑ history' : 'Open a shell to run commands (⌘T), or ask in plain words…')}
            onFocus={loadHistory}
            onChange={(event) => { setValue(event.target.value); setHistoryAt(-1); setCompletions(null); }}
            onPaste={() => { pasted.current = true; }}
            onKeyDown={onKey}
          />
        </div>
        <div className="ct-line-acts">
          {value.trim() && <button type="button" className="ct-more-btn" aria-expanded={more} onClick={() => setMore((open) => !open)} title="More ways to run it">⋯</button>}
          {more && (
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
          <button type="button" className={`ct-send${confirm ? ' confirm' : ''}`} disabled={!value.trim()} onClick={() => submit('here')}>
            {mode === 'shell' ? (confirm ? 'CONFIRM' : 'RUN') : 'ASK'} <span aria-hidden>↵</span>
          </button>
        </div>
      </div>
      {value.trim() && mode === 'shell' && assessment && (confirm || !assessment.safe || (assessment.matches && assessment.matches.files + assessment.matches.dirs > 0) || (assessment.native_view && !value.startsWith('!'))) && (
        <div className={`ct-preview${confirm ? ' confirm' : ''}`}>
          {assessment.program && <span><span className="ct-faint">RUNS</span> {assessment.program}</span>}
          <span><span className="ct-faint">IN</span> {shortPath(assessment.cwd, home)}</span>
          {matches && (matches.files + matches.dirs > 0) && (
            <span><span className="ct-faint">MATCHES</span> {matches.dirs > 0 ? `${matches.dirs} folders + ` : ''}{matches.files} files · {size(matches.bytes)}</span>
          )}
          {!(assessment.native_view && !value.startsWith('!')) && <span className={`ct-label ${assessment.safe ? 'ct-ok' : 'ct-warn'}`}>{riskLabel(assessment)}{!assessment.safe && DANGEROUS.has(assessment.risk) ? ' · ASKS FIRST' : ''}</span>}
          {assessment.reasons.length > 0 && <span className="ct-faint">{assessment.reasons.join(' · ')}</span>}
          {assessment.native_view && !value.startsWith('!') && <span className="ct-label ct-blue">OPENS IN CORTEXTERM · ! FOR THE REAL ONE</span>}
          {confirm && <span className="ct-label ct-warn">PRESS ↵ AGAIN TO RUN · ESC TO STOP</span>}
        </div>
      )}
      {value.trim() && mode === 'shell' && (threats.length > 0 || malware.length > 0 || vulnerable.length > 0) && (
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
