/** The `edit` picker belongs to the existing Line: it never mounts another text input. */
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { errorMessage, useRuntime } from '@cortex/sdk';
import type { Assessment, Completion, Completions } from './api';
import { byteCursor } from './suggestions';

export const EDIT_FILES_ID = 'ct-edit-files';

export function editQuery(value: string): string | null {
  if (/[\r\n\0]/.test(value)) return null;
  return /^[ \t]*edit(?:[ \t]+([^\r\n\0]*))?$/.exec(value)?.[1] ?? (/^[ \t]*edit$/.test(value) ? '' : null);
}

export function useEditFiles(value: string, termId: string | undefined, active: boolean, onChange: (value: string) => void, onOpen: (path: string) => void, onExit: () => void) {
  const client = useRuntime().client;
  type Result = { value: string; termId: string; client: typeof client; items: Completion[]; error?: string };
  const [result, setResult] = useState<Result | null>(null);
  const [picked, setPicked] = useState(-1);
  const [opening, setOpening] = useState(false);
  const [retry, setRetry] = useState(0);
  const current = useRef({ value, termId, client, active });
  current.current = { value, termId, client, active };
  const matches = result?.value === value && result.termId === termId && result.client === client;
  const items = matches ? result.items : [];
  const busy = active && Boolean(termId) && !matches;
  const error = matches ? result.error : undefined;

  useEffect(() => {
    setResult(null);
    setOpening(false);
    setPicked(editQuery(value)?.trim() ? 0 : -1);
    if (!active || !termId) return;
    const cancel = new AbortController();
    const timer = setTimeout(() => {
      client.call<Completions>('terminal.complete', { term_id: termId, line: value, cursor: byteCursor(value) }, { signal: cancel.signal })
        .then((response) => {
          if (!cancel.signal.aborted) setResult({ value, termId, client, items: (response?.items ?? []).slice(0, 12) });
        }).catch((failure) => {
          if (!cancel.signal.aborted) setResult({ value, termId, client, items: [], error: errorMessage(failure) });
        });
    }, 100);
    return () => { cancel.abort(); clearTimeout(timer); };
  }, [value, termId, client, active, retry]);

  const open = (line = value) => {
    if (!active || !termId || opening || !editQuery(line)?.trim()) return;
    const source = current.current;
    setOpening(true);
    // Resolve on the focused machine, using its cwd and the same literal-path rules as browsing.
    client.call<Assessment>('terminal.assess', { term_id: termId, input: line })
      .then((assessment) => {
        const latest = current.current;
        if (!latest.active || latest.value !== source.value || latest.termId !== source.termId || latest.client !== source.client) return;
        if (assessment.native_view !== 'editor' || !assessment.native_target) throw new Error('Choose a file or enter its path.');
        setOpening(false);
        onOpen(assessment.native_target);
      }).catch((failure) => {
        const latest = current.current;
        if (!latest.active || latest.value !== source.value || latest.termId !== source.termId || latest.client !== source.client || !termId) return;
        setOpening(false);
        setResult({ value, termId, client, items, error: errorMessage(failure) });
      });
  };

  const choose = (item: Completion, openFile: boolean) => {
    if (opening) return;
    const line = `edit ${item.value}`;
    if (item.kind === 'dir' || !openFile) onChange(line);
    else open(line);
  };
  const accept = () => {
    if (busy || opening) return;
    const item = items[picked];
    if (item) choose(item, true);
    else if (editQuery(value)?.trim()) open();
  };
  const onKey = (event: KeyboardEvent<HTMLTextAreaElement>): boolean => {
    if (!active) return false;
    if (event.key === 'Escape') { event.preventDefault(); onExit(); return true; }
    if (event.key === 'Tab') {
      if (!event.shiftKey) {
        event.preventDefault();
        const item = items[picked < 0 ? 0 : picked];
        if (item && !busy) choose(item, false);
      }
      return true;
    }
    if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey) {
      event.preventDefault();
      if (items.length) setPicked((at) => at < 0 ? (event.key === 'ArrowDown' ? 0 : items.length - 1) : (at + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length);
      return true;
    }
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); accept(); return true; }
    return false;
  };
  return { items, picked, busy, opening, error, onKey, choose, accept, retry: () => setRetry((attempt) => attempt + 1) };
}

export function EditFiles({ picker, cwd, termId }: { picker: ReturnType<typeof useEditFiles>; cwd: string; termId?: string }) {
  const { items, picked, busy, opening, error } = picker;
  const selected = useRef<HTMLLIElement>(null);
  useEffect(() => selected.current?.scrollIntoView({ block: 'nearest' }), [picked]);
  return (
    <div className="ct-edit-picker">
      <div className="ct-edit-head"><span className="ct-label">FILES</span><span className="ct-mono" title={cwd}>{cwd || 'Focused shell'}</span></div>
      {!termId && <p className="ct-edit-status">Open a shell (⌘T) to browse its files.</p>}
      {busy && <p className="ct-edit-status" role="status">Finding files…</p>}
      {error && <div className="ct-edit-status" role="alert">{error} <button type="button" onMouseDown={(event) => event.preventDefault()} onClick={picker.retry}>TRY AGAIN</button></div>}
      {!busy && !error && termId && items.length === 0 && <p className="ct-edit-status">No files here. Type a path, or ../ to go up.</p>}
      <ul id={EDIT_FILES_ID} role="listbox" aria-label="Files to edit" aria-busy={busy || opening}>
        {items.map((item, index) => (
          <li key={`${item.kind}:${item.value}`} id={`${EDIT_FILES_ID}-${index}`} role="option" aria-selected={index === picked}
            ref={index === picked ? selected : undefined} className={index === picked ? 'on' : ''}>
            <button type="button" tabIndex={-1} disabled={opening} onMouseDown={(event) => event.preventDefault()} onClick={() => picker.choose(item, true)}>
              <span className="ct-label ct-edit-kind">{item.kind === 'dir' ? 'FOLDER' : item.kind === 'new' ? 'NEW' : 'FILE'}</span>
              <span className="ct-mono ct-edit-name">{item.description || item.value}</span>
              <span className="ct-label ct-faint">{item.kind === 'dir' ? 'BROWSE' : item.kind === 'new' ? 'CREATE' : 'OPEN'}</span>
            </button>
          </li>
        ))}
      </ul>
      <div className="ct-edit-foot ct-label">{opening ? 'OPENING…' : '↑↓ CHOOSE · ⇥ COMPLETE · ↵ OPEN / BROWSE · ESC CANCEL'}</div>
    </div>
  );
}
