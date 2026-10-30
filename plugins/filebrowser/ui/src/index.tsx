/** Operate inside the existing machine pane: Archivo controls, mono paths, fine rules and the
 * theme's rubric/counter colours. The Files tab is hosted by Workbench; everything here belongs
 * to File Browser. Navigation stays on the scoped mesh machine; native transfers use this Mac. */
import { useCallback, useEffect, useRef, useState } from 'react';
import { definePlugin, errorMessage, runtimeFor, useHost, useRuntime, useSlotState } from '@cortex/sdk';
import './files.css';

interface Entry { name: string; path: string; kind: 'directory' | 'file' | 'symlink' | 'other'; symlink: boolean; bytes: number; modified: number; accessible: boolean }
interface Listing { home: string; path: string; parent: string | null; entries: Entry[] }
interface Location { path: string; hidden: boolean }
interface Transfer {
  id: string; node: string; direction: 'upload' | 'download'; directory: string; revision: number;
  state: 'choosing' | 'running' | 'done' | 'cancelled' | 'error';
  name: string; completed: number; files: number; bytes: number; total: number; error: string; saved: string;
}
const active = (transfer: Transfer | null) => transfer?.state === 'choosing' || transfer?.state === 'running';
function size(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024, unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}
function FileIcon({ folder, link }: { folder: boolean; link: boolean }) {
  return <svg className={`fb-icon${folder ? ' fb-icon-folder' : ''}`} viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round">
    {folder ? <path d="M1.5 4.5V3h5l1.5 1.5h6.5V13h-13V4.5Z" /> : <><path d="M4 1.5h5l3 3v10H4Z" /><path d="M9 1.5v3h3" /></>}
    {link && <path d="M1 11h5m-2-2 2 2-2 2" />}
  </svg>;
}

function Files() {
  const { client, node } = useRuntime();
  const host = useHost();
  const local = runtimeFor(null).client;
  const [locations, setLocations] = useSlotState<Record<string, Location>>('locations', {});
  const location = locations[node ?? ''] ?? { path: '~', hidden: false };
  const [listing, setListing] = useState<Listing | null>(null);
  const [loading, setLoading] = useState(true);
  const [problem, setProblem] = useState('');
  const [selected, setSelected] = useState('');
  const [transfer, setTransfer] = useState<Transfer | null>(null);
  const [starting, setStarting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [revision, refresh] = useState(0);
  const transferRef = useRef<Transfer | null>(null);
  const generation = useRef(0);
  const mounted = useRef(false);

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; }; }, []);
  useEffect(() => {
    if (!node) return;
    let disposed = false;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    setLoading(true); setProblem(''); setSelected(''); setListing(null);
    client.call<Listing>('filebrowser.list', { path: location.path, show_hidden: location.hidden }, { signal: controller.signal })
      .then((result) => { if (!disposed && !controller.signal.aborted) setListing(result); })
      .catch((error) => { if (!disposed) setProblem(errorMessage(error)); })
      .finally(() => { clearTimeout(timer); if (!disposed) setLoading(false); });
    return () => { disposed = true; clearTimeout(timer); controller.abort(); };
  }, [client, node, location.path, location.hidden, revision]);

  const acceptTransfer = useCallback((next: Transfer) => {
    if (next.node !== node || next.id !== transferRef.current?.id) return;
    const previous = transferRef.current;
    if (previous && next.revision < previous.revision) return;
    // A poll started before completion must not resurrect an active transfer.
    if (!active(previous) && active(next)) return;
    transferRef.current = next;
    setTransfer(next);
    if (!active(next)) {
      setCancelling(false);
      if (active(previous) && next.completed > 0 && next.direction === 'upload') refresh((value) => value + 1);
    }
  }, [node]);

  useEffect(() => {
    const off = local.on('filebrowser-native.progress', (_topic, data) => acceptTransfer(data as Transfer));
    return off;
  }, [local, acceptTransfer]);

  // Polling recovers missed events and keeps a remounted pane useful after switching tabs.
  const [transfers, setTransfers] = useSlotState<Record<string, string>>('transfers', {});
  const transferId = transfers[node ?? ''];
  useEffect(() => {
    if (!node || !transferId) return;
    let disposed = false, polling = false;
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const next = await local.call<Transfer>('filebrowser-native.status', { id: transferId }, { signal: AbortSignal.timeout(5000) });
        if (!disposed) {
          if (!transferRef.current) {
            transferRef.current = next; setTransfer(next);
            if (!active(next) && next.completed > 0 && next.direction === 'upload') refresh((value) => value + 1);
          }
          else acceptTransfer(next);
        }
      } catch (error) {
        if (!disposed && error && typeof error === 'object' && 'code' in error && error.code === 'not_found') {
          const previous = transferRef.current;
          if (previous?.id === transferId) acceptTransfer({ ...previous, revision: previous.revision + 1,
            state: 'error', error: 'This transfer ended when File Browser restarted. Start the transfer again.' });
          setTransfers((current) => {
            if (current[node] !== transferId) return current;
            const next = { ...current }; delete next[node]; return next;
          });
        }
        // A disconnected shell is transient; keep polling until it reconnects.
      }
      finally { polling = false; }
    };
    void poll();
    const timer = setInterval(() => { if (!transferRef.current || active(transferRef.current)) void poll(); }, 1000);
    return () => { disposed = true; clearInterval(timer); };
  }, [local, node, transferId, acceptTransfer, setTransfers]);

  const navigate = (path: string) => {
    if (!node) return;
    setLocations((current) => ({ ...current, [node]: { path, hidden: location.hidden } }));
  };
  const start = async (direction: 'upload' | 'download') => {
    if (!node || !listing || starting || active(transfer)) return;
    const file = listing.entries.find((entry) => entry.path === selected);
    if (direction === 'download' && (!file || file.kind !== 'file' || !file.accessible)) return;
    const requestGeneration = generation.current;
    const id = crypto.randomUUID();
    const pending: Transfer = { id, node, direction, directory: listing.path, revision: -1, state: 'choosing', name: file?.name ?? '',
      completed: 0, files: 0, bytes: 0, total: 0, error: '', saved: '' };
    transferRef.current = pending; setTransfer(pending); setStarting(true); setProblem('');
    setTransfers((current) => ({ ...current, [node]: id }));
    try {
      const next = await local.call<Transfer>('filebrowser-native.start', { id, node, direction, directory: listing.path, path: file?.path }, { signal: AbortSignal.timeout(15_000) });
      if (mounted.current && requestGeneration === generation.current) acceptTransfer(next);
    } catch (error) {
      // A lost response can still mean the shell accepted the start. Cancel this exact ID.
      void local.call('filebrowser-native.cancel', { id }, { signal: AbortSignal.timeout(5000) }).catch(() => {});
      if (mounted.current && requestGeneration === generation.current) {
        const failed: Transfer = { ...pending, state: 'error', error: errorMessage(error) };
        transferRef.current = failed; setTransfer(failed);
      }
    } finally { if (mounted.current && requestGeneration === generation.current) setStarting(false); }
  };
  const cancel = async () => {
    if (!transfer || cancelling) return;
    setCancelling(true);
    try { await local.call('filebrowser-native.cancel', { id: transfer.id }, { signal: AbortSignal.timeout(5000) }); }
    catch (error) { setProblem(errorMessage(error)); setCancelling(false); }
  };

  if (!node) return null;
  const file = listing?.entries.find((entry) => entry.path === selected);
  const relative = listing ? listing.path.slice(listing.home.length).split('/').filter(Boolean) : [];
  const busy = starting || active(transfer);
  const percent = transfer?.total ? Math.min(100, Math.round(transfer.bytes / transfer.total * 100)) : 0;
  return <section className="fb-files" aria-label="Files on mesh machine">
    <nav className="fb-path" aria-label="Folder path">
      <button type="button" onClick={() => navigate('~')} disabled={loading} title={listing?.home ?? 'Home folder'}>~</button>
      {relative.map((part, index) => <span key={index} className="fb-crumb"><span aria-hidden="true">/</span>
        <button type="button" disabled={loading} aria-current={index === relative.length - 1 ? 'location' : undefined}
          onClick={() => navigate(`${listing!.home}/${relative.slice(0, index + 1).join('/')}`)}>{part}</button>
      </span>)}
    </nav>
    <div className="fb-toolbar">
      <button type="button" className="detent sm" onClick={() => void start('upload')} disabled={busy || loading || !listing}>UPLOAD</button>
      <button type="button" className="detent sm" onClick={() => void start('download')} disabled={busy || loading || file?.kind !== 'file' || !file.accessible}>DOWNLOAD</button>
      <span className="fb-grow" />
      <button type="button" className="fb-text-control" onClick={() => refresh((value) => value + 1)} disabled={loading}>REFRESH</button>
    </div>
    <label className="fb-hidden"><input type="checkbox" checked={location.hidden}
      onChange={(event) => setLocations((current) => ({ ...current, [node]: { path: location.path, hidden: event.target.checked } }))} />SHOW HIDDEN FILES</label>
    {problem && <div className="fb-message fb-error" role="alert"><p>{problem}</p>
      <button type="button" className="fb-text-control" onClick={() => refresh((value) => value + 1)}>TRY AGAIN</button>
      {location.path !== '~' && <button type="button" className="fb-text-control" onClick={() => navigate('~')}>HOME</button>}
    </div>}
    <div className="fb-list" aria-busy={loading}>
      {loading && <p className="fb-message" role="status">Reading folder…</p>}
      {!loading && listing && <>
        <div className="fb-columns" aria-hidden="true"><span>NAME</span><span>SIZE</span><span>MODIFIED</span></div>
        <ul aria-label="Folder contents">
          {listing.parent && <li><button type="button" className="fb-row fb-parent" onClick={() => navigate(listing.parent!)}>
            <span className="fb-name"><svg className="fb-icon" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.2"><path d="m4 7 4-4 4 4M8 3v10" /></svg>Parent folder</span>
          </button></li>}
          {listing.entries.map((entry) => <li key={entry.path}>
            <button type="button" className={`fb-row${selected === entry.path ? ' fb-selected' : ''}`} disabled={!entry.accessible}
              aria-pressed={entry.kind === 'file' ? selected === entry.path : undefined}
              aria-label={`${entry.name}${entry.kind === 'directory' ? ', open folder' : entry.accessible ? ', select file' : ', unavailable'}`}
              title={entry.accessible ? `${entry.path}${entry.symlink ? ' · symbolic link' : ''}` : `${entry.path} · unavailable or outside home`}
              onClick={() => entry.kind === 'directory' ? navigate(entry.path) : setSelected(entry.path)}>
              <span className="fb-name"><FileIcon folder={entry.kind === 'directory'} link={entry.symlink} /><span>{entry.name}</span></span>
              <span className="fb-size">{entry.kind === 'file' ? size(entry.bytes) : ''}</span>
              <time className="fb-date" dateTime={entry.modified ? new Date(entry.modified).toISOString() : undefined}
                title={entry.modified ? new Date(entry.modified).toLocaleString() : undefined}>{entry.modified ? new Date(entry.modified).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : ''}</time>
            </button>
          </li>)}
        </ul>
        {listing.entries.length === 0 && <p className="fb-message">{location.hidden ? 'This folder is empty.' : 'No visible files. Turn on Show hidden files to include hidden items.'}</p>}
      </>}
    </div>
    {listing && !loading && <p className="fb-count">{listing.entries.length} ITEM{listing.entries.length === 1 ? '' : 'S'}<span className="fb-grow" />{file ? file.name : 'HOME-ROOTED'}</p>}
    {transfer && <div className={`fb-transfer${transfer.state === 'error' ? ' fb-error' : ''}`} aria-live="polite">
      <div className="fb-transfer-head"><span>{transfer.state === 'choosing' ? 'CHOOSE LOCAL FILE' : transfer.state === 'running' ? transfer.direction === 'upload' ? 'UPLOADING' : 'DOWNLOADING'
        : transfer.state === 'done' ? 'TRANSFER COMPLETE' : transfer.state === 'cancelled' ? 'TRANSFER CANCELLED' : 'TRANSFER FAILED'}</span>
        <span className="fb-grow" />{active(transfer) && <button type="button" className="fb-text-control" onClick={() => void cancel()} disabled={cancelling}>{cancelling ? 'CANCELLING…' : 'CANCEL'}</button>}</div>
      {transfer.name && <p className="fb-transfer-name">{transfer.name}</p>}
      {transfer.direction === 'upload' && <p className="fb-transfer-detail">TO {listing ? transfer.directory.replace(listing.home, '~') : transfer.directory}</p>}
      {transfer.state === 'running' && <><progress max={transfer.total || 1} value={transfer.bytes} aria-label="File transfer progress" />
        <p className="fb-transfer-detail">{size(transfer.bytes)} / {size(transfer.total)} · {percent}%{transfer.files > 1 ? ` · FILE ${Math.min(transfer.completed + 1, transfer.files)} OF ${transfer.files}` : ''}</p></>}
      {transfer.state === 'done' && <p className="fb-transfer-detail">{transfer.completed} FILE{transfer.completed === 1 ? '' : 'S'} {transfer.direction === 'upload' ? 'UPLOADED' : 'DOWNLOADED'}</p>}
      {transfer.error && <p className="fb-message" role="alert">{transfer.error}{transfer.completed ? ` ${transfer.completed} file(s) already transferred.` : ''}</p>}
      {transfer.saved && transfer.state === 'done' && host.shell && <button type="button" className="fb-text-control" onClick={() => void host.shell!.reveal(transfer.saved).then((error) => { if (error) setProblem(error); })}>SHOW IN FOLDER</button>}
    </div>}
  </section>;
}

export default definePlugin({ slot: 'machine.files@1', component: Files });
