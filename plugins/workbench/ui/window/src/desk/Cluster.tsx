/** Machine picker and the cluster page. Layout is this window's local, database-backed UI state. */
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent, PointerEvent, ReactNode } from 'react';
import { Caret, ComputerScope, useShared } from '@cortex/sdk';
import { GB } from './api';
import { MachineReadings, useMetrics } from './Sidebar';
import { useMachineAlerts } from './machine-data';
import './cluster.css';

export interface Computer { node: string; name: string; reachable: boolean; path: string }
export interface ClusterLayout { order: string[]; colors: Record<string, string> }
const EMPTY_LAYOUT: ClusterLayout = { order: [], colors: {} };
const SWATCHES = [
  { id: 'default', name: 'Default', value: 'var(--rule-2)' },
  { id: 'orange', name: 'Orange', value: 'var(--rubric-lift)' },
  { id: 'blue', name: 'Blue', value: 'var(--counter)' },
  { id: 'green', name: 'Green', value: '#79a88a' },
  { id: 'violet', name: 'Violet', value: '#a995c9' },
  { id: 'gold', name: 'Gold', value: '#c8ab6e' },
] as const;
const colorStyle = (color?: string) => ({ '--computer-color': (SWATCHES.find((swatch) => swatch.id === color) ?? SWATCHES[0]).value }) as CSSProperties;
export const LOCAL_COMPUTER: Computer = { node: '', name: 'This Mac', reachable: true, path: 'local' };

/** Discovery appends; it never sorts or replaces the person's arrangement. */
export function useClusterLayout(computers: Computer[]) {
  const [layout, setLayout] = useShared<ClusterLayout>('ct.cluster', EMPTY_LAYOUT);
  const discovered = computers.map((computer) => computer.node);
  const order = [...layout.order, ...discovered.filter((node) => !layout.order.includes(node))];
  const discoveryKey = JSON.stringify(discovered);
  useEffect(() => {
    setLayout((current) => {
      const added = discovered.filter((node) => !current.order.includes(node));
      return added.length ? { ...current, order: [...current.order, ...added] } : current;
    });
    // The key represents the discovered identities, independently of metric and name updates.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [discoveryKey, setLayout]);
  return { layout, setLayout, order };
}

export function ComputerPicker({ computers, node, colors, onSelect, onCluster }: {
  computers: Computer[]; node: string; colors: Record<string, string>;
  onSelect: (node: string) => void; onCluster: () => void;
}) {
  return <div className="ct-computer-controls">
    <label className="ct-computer-picker" style={colorStyle(colors[node])}>
      <span className="ct-computer-color" aria-hidden />
      <select aria-label="Machine for all side panes" value={node} onChange={(event) => onSelect(event.target.value)}>
        {computers.map((computer) => <option key={computer.node} value={computer.node}>
          {computer.name}{computer.node ? computer.reachable ? ' · MESH' : ' · OFFLINE' : ' · LOCAL'}
        </option>)}
      </select>
      <Caret dir="down" />
    </label>
    <button type="button" className="ct-cluster-toggle" aria-label="Open cluster overview" title="Cluster overview" onClick={onCluster}>
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden>
        <rect x="1.5" y="1.5" width="5" height="5" /><rect x="9.5" y="1.5" width="5" height="5" />
        <rect x="1.5" y="9.5" width="5" height="5" /><rect x="9.5" y="9.5" width="5" height="5" />
      </svg>
    </button>
  </div>;
}

interface Drag {
  node: string; rect: DOMRect; startX: number; startY: number;
  x: number; y: number; lifted: boolean; pointer: number | null;
}
function moveBefore(order: string[], from: string, target: string) {
  const next = order.filter((node) => node !== from);
  next.splice(order.indexOf(target), 0, from);
  return next;
}

export function Cluster({ open, computers, selected, layout, order, onLayout, onSelect, onClose }: {
  open: boolean; computers: Computer[]; selected: string; layout: ClusterLayout; order: string[];
  onLayout: (change: (current: ClusterLayout) => ClusterLayout) => void;
  onSelect: (node: string) => void; onClose: () => void;
}) {
  const [present, setPresent] = useState(open);
  const [draft, setDraft] = useState<string[] | null>(null);
  const [lift, setLift] = useState<{ node: string; style?: CSSProperties } | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const screen = useRef<HTMLElement>(null);
  const grid = useRef<HTMLDivElement>(null);
  const scroll = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const slots = useRef(new Map<string, HTMLDivElement>());
  const positions = useRef(new Map<string, DOMRect>());
  const drag = useRef<Drag | null>(null);
  const draftRef = useRef<string[]>(order);
  const openRef = useRef(open);
  openRef.current = open;
  const visibleOrder = [...(draft ?? order), ...order.filter((node) => !(draft ?? order).includes(node))];
  const ordered = visibleOrder.flatMap((node) => computers.filter((computer) => computer.node === node));
  const orderKey = JSON.stringify(ordered.map((computer) => computer.node));

  const finish = (save: boolean) => {
    const active = drag.current;
    if (!active) return;
    const card = slots.current.get(active.node)?.querySelector<HTMLElement>('.ct-cluster-card');
    const from = active.pointer !== null && active.lifted ? card?.getBoundingClientRect() : undefined;
    if (save && active.lifted) {
      const next = draftRef.current;
      onLayout((current) => ({ ...current, order: [...next, ...current.order.filter((node) => !next.includes(node))] }));
      setAnnouncement('Machine order saved.');
    } else if (active.lifted) setAnnouncement('Move cancelled.');
    drag.current = null;
    setDraft(null);
    setLift(null);
    requestAnimationFrame(() => {
      if (!openRef.current) return;
      (slots.current.get(active.node)?.querySelector<HTMLButtonElement>('.ct-cluster-grip') ?? closeButton.current)?.focus({ preventScroll: true });
      if (from && card?.isConnected && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const to = card.getBoundingClientRect();
        card.animate([{ transform: `translate(${from.left - to.left}px,${from.top - to.top}px)` }, { transform: 'none' }],
          { duration: 210, easing: 'cubic-bezier(.16,1,.3,1)' });
      }
    });
  };

  useEffect(() => {
    if (open) { setPresent(true); return; }
    const timer = setTimeout(() => setPresent(false), 220);
    return () => clearTimeout(timer);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const frame = requestAnimationFrame(() => closeButton.current?.focus());
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key === 'Escape') {
        if (screen.current?.querySelector(':popover-open')) return;
        event.preventDefault(); event.stopPropagation();
        if (drag.current) finish(false); else onClose();
      }
      if (event.key === 'Tab' && screen.current) {
        const focusable = [...screen.current.querySelectorAll<HTMLElement>('button:not(:disabled), [href], input, select, [tabindex="0"]')]
          .filter((element) => element.getClientRects().length && !element.closest('[popover]:not(:popover-open)'));
        const first = focusable[0], last = focusable.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    const onBlur = () => { if (drag.current) finish(false); };
    window.addEventListener('keydown', onKey);
    window.addEventListener('blur', onBlur);
    return () => {
      cancelAnimationFrame(frame); window.removeEventListener('keydown', onKey); window.removeEventListener('blur', onBlur);
      previous?.focus({ preventScroll: true });
    };
    // Keep the entry focus stable through discovery and reordering.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, onClose]);

  useEffect(() => {
    if (!open) { drag.current = null; setDraft(null); setLift(null); }
  }, [open]);

  useEffect(() => {
    if (drag.current && !computers.some((computer) => computer.node === drag.current?.node)) finish(false);
    // Membership can change during a move; never keep dragging a removed computer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orderKey]);

  useLayoutEffect(() => {
    const next = new Map<string, DOMRect>();
    for (const [node, element] of slots.current) {
      // A transformed slot would become the fixed dragged card's containing block.
      for (const animation of element.getAnimations()) animation.cancel();
      const rect = element.getBoundingClientRect();
      const before = positions.current.get(node);
      next.set(node, rect);
      if (before && !(drag.current?.node === node && drag.current.pointer !== null) && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const x = before.left - rect.left, y = before.top - rect.top;
        if (x || y) element.animate([{ transform: `translate(${x}px,${y}px)` }, { transform: 'none' }], { duration: 210, easing: 'cubic-bezier(.16,1,.3,1)' });
      }
    }
    positions.current = next;
    // Keyed DOM moves can drop focus; keep keyboard reordering on the lifted handle.
    const active = drag.current;
    if (active?.pointer === null) {
      const slot = slots.current.get(active.node);
      slot?.querySelector<HTMLButtonElement>('.ct-cluster-grip')?.focus({ preventScroll: true });
      slot?.scrollIntoView({ block: 'nearest' });
    }
  }, [orderKey, present]);

  const relocate = (target: string) => {
    const active = drag.current;
    if (!active || active.node === target || !draftRef.current.includes(target)) return;
    const next = moveBefore(draftRef.current, active.node, target);
    draftRef.current = next;
    setDraft(next);
    const position = next.filter((node) => computers.some((computer) => computer.node === node)).indexOf(active.node) + 1;
    setAnnouncement(`Position ${position} of ${computers.length}.`);
  };

  const trackPointer = (x: number, y: number) => {
    const active = drag.current;
    if (!active || active.pointer === null) return;
    active.x = x; active.y = y;
    if (!active.lifted && Math.hypot(x - active.startX, y - active.startY) < 5) return;
    active.lifted = true;
    setLift({ node: active.node, style: { position: 'fixed', left: active.rect.left, top: active.rect.top,
      width: active.rect.width, height: active.rect.height, transform: `translate3d(${x - active.startX}px,${y - active.startY}px,0)`, zIndex: 60 } });
    const bounds = grid.current?.getBoundingClientRect();
    if (!bounds || x < bounds.left || x > bounds.right) return;
    let closest: string | undefined, distance = Infinity;
    for (const [node, rect] of positions.current) {
      const d = Math.hypot(x - (rect.left + rect.width / 2), y - (rect.top + rect.height / 2));
      if (d < distance) { closest = node; distance = d; }
    }
    if (closest !== undefined) relocate(closest);
  };

  // Keep scrolling while a held card is near an edge, including when the pointer stops moving.
  useEffect(() => {
    if (!lift || drag.current?.pointer == null) return;
    let frame = 0;
    const tick = () => {
      const active = drag.current, field = scroll.current;
      if (!active || !field || !openRef.current) return;
      const bounds = field.getBoundingClientRect();
      const delta = active.y < bounds.top + 64 ? -10 : active.y > bounds.bottom - 64 ? 10 : 0;
      if (delta) { field.scrollTop += delta; trackPointer(active.x, active.y); }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
    // A single scrolling loop reads the current drag from its ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lift?.node]);

  const startPointer = (event: PointerEvent<HTMLButtonElement>, node: string) => {
    if (event.button !== 0 || drag.current) return;
    const slot = slots.current.get(node);
    if (!slot) return;
    event.preventDefault();
    event.currentTarget.focus();
    // Capture on the stationary page; moving a keyed card must not end pointer capture.
    screen.current?.setPointerCapture(event.pointerId);
    for (const animation of slot.getAnimations()) animation.cancel();
    draftRef.current = visibleOrder;
    drag.current = { node, rect: slot.getBoundingClientRect(), startX: event.clientX, startY: event.clientY,
      x: event.clientX, y: event.clientY, lifted: false, pointer: event.pointerId };
  };

  const onGripKey = (event: KeyboardEvent<HTMLButtonElement>, node: string) => {
    if (event.key === ' ' || event.key === 'Enter') {
      event.preventDefault();
      if (drag.current?.pointer === null) { finish(true); return; }
      if (drag.current) return;
      const rect = slots.current.get(node)?.getBoundingClientRect();
      if (!rect) return;
      draftRef.current = visibleOrder;
      drag.current = { node, rect, startX: 0, startY: 0, x: 0, y: 0, lifted: true, pointer: null };
      setLift({ node });
      setAnnouncement(`Picked up ${computers.find((computer) => computer.node === node)?.name}. Use arrow keys to move; Enter to save; Escape to cancel.`);
      return;
    }
    const active = drag.current;
    if (!active || active.pointer !== null || active.node !== node) return;
    const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'];
    if (!keys.includes(event.key)) return;
    event.preventDefault();
    const ids = draftRef.current.filter((id) => computers.some((computer) => computer.node === id));
    const first = positions.current.get(ids[0] ?? '');
    const columns = [...positions.current.values()].filter((rect) => first && Math.abs(rect.top - first.top) < 2).length || 1;
    const index = ids.indexOf(node);
    const offset = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : event.key === 'ArrowUp' ? -columns : columns;
    const target = event.key === 'Home' ? ids[0] : event.key === 'End' ? ids.at(-1) : ids[Math.max(0, Math.min(ids.length - 1, index + offset))];
    if (target !== undefined) relocate(target);
  };

  if (!present) return null;
  return <section ref={screen} className={`ct-cluster-screen${open ? ' is-open' : ''}`} aria-label="Cluster overview" inert={!open || undefined}
    onPointerMove={(event) => { if (drag.current?.pointer === event.pointerId) trackPointer(event.clientX, event.clientY); }}
    onPointerUp={(event) => { if (drag.current?.pointer === event.pointerId) finish(true); }}
    onPointerCancel={() => finish(false)} onLostPointerCapture={() => { if (drag.current?.pointer != null) finish(false); }}>
    <header className="ct-cluster-bar">
      <button ref={closeButton} type="button" className="detent" onClick={() => { finish(false); onClose(); }}>BACK TO TERMINAL <span className="k">ESC</span></button>
      <span className="ct-label ct-faint">{computers.filter((computer) => computer.reachable).length} ONLINE · {computers.length} COMPUTERS</span>
    </header>
    <div ref={scroll} className="ct-cluster-scroll" onScroll={() => {
      positions.current = new Map([...slots.current].map(([node, element]) => [node, element.getBoundingClientRect()]));
    }}>
      <p id="ct-cluster-move-help" className="ct-visually-hidden">Press Space on a move handle, use arrow keys to rearrange, and Enter to save. Escape cancels.</p>
      <div ref={grid} className="ct-cluster-grid">
        {ordered.map((computer) => <div key={computer.node} data-computer={computer.node}
          ref={(element) => { if (element) slots.current.set(computer.node, element); else slots.current.delete(computer.node); }}
          style={{ ...colorStyle(layout.colors[computer.node]), ...(lift?.node === computer.node && lift.style ? { height: drag.current?.rect.height } : {}) }}
          className={`ct-cluster-slot${lift?.node === computer.node ? ' is-placeholder' : ''}`}>
          <ComputerScope node={computer.node || null}>
            <ClusterCard computer={computer} color={layout.colors[computer.node]} selected={selected === computer.node}
              lifted={lift?.node === computer.node} dragStyle={lift?.node === computer.node ? lift.style : undefined}
              onColor={(color) => onLayout((current) => ({ ...current, colors: { ...current.colors, [computer.node]: color } }))}
              onSelect={() => { finish(false); onSelect(computer.node); }}
              grip={<button type="button" className="ct-cluster-grip" aria-label={`Move ${computer.name}`} aria-describedby="ct-cluster-move-help"
                aria-pressed={lift?.node === computer.node} onPointerDown={(event) => startPointer(event, computer.node)}
                onKeyDown={(event) => onGripKey(event, computer.node)}>
                <svg width="12" height="16" viewBox="0 0 12 16" fill="currentColor" aria-hidden>
                  {[4, 8, 12].flatMap((y) => [3, 8].map((x) => <circle key={`${x}-${y}`} cx={x} cy={y} r="1" />))}
                </svg>
              </button>} />
          </ComputerScope>
        </div>)}
      </div>
    </div>
    <span className="ct-visually-hidden" role="status" aria-live="polite">{announcement}</span>
  </section>;
}

function ClusterCard({ computer, selected, color, lifted, dragStyle, grip, onColor, onSelect }: {
  computer: Computer; selected: boolean; color?: string; lifted: boolean; dragStyle?: CSSProperties;
  grip: ReactNode; onColor: (color: string) => void; onSelect: () => void;
}) {
  const { metrics, history, problem } = useMetrics(computer.reachable);
  const popover = `ct-color-${computer.node || 'local'}`;
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 5000); return () => clearInterval(timer); }, []);
  const stale = !computer.reachable || !!problem || !!metrics && now - metrics.at > 15_000;
  return <article className={`ct-cluster-card${selected ? ' is-selected' : ''}${lifted ? ' is-lifted' : ''}${stale ? ' is-stale' : ''}`}
    style={{ ...colorStyle(color), ...dragStyle }} aria-label={computer.name}>
    <header className="ct-cluster-card-head">
      {grip}
      <span className="ct-computer-color" aria-hidden />
      <button type="button" className="ct-cluster-name" onClick={onSelect} title={`Show panes for ${computer.name}`}>{computer.name}</button>
      <span className="grow" />
      <button type="button" className="ct-cluster-color-button" popoverTarget={popover} aria-label={`Colour for ${computer.name}`} title="Choose colour">
        <span className="ct-computer-color" aria-hidden /><Caret dir="down" />
      </button>
      <div id={popover} popover="auto" className="ct-cluster-swatches" role="group" aria-label={`Colour for ${computer.name}`}>
        {SWATCHES.map((swatch) => <button key={swatch.id} type="button" style={colorStyle(swatch.id)} title={swatch.name}
          aria-label={swatch.name} aria-pressed={(color ?? 'default') === swatch.id} onClick={(event) => {
            onColor(swatch.id); event.currentTarget.closest<HTMLElement>('[popover]')?.hidePopover();
          }}><span aria-hidden />{(color ?? 'default') === swatch.id && <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="var(--ground)" strokeWidth="2" aria-hidden><path d="m3 8 3 3 7-7" /></svg>}</button>)}
      </div>
    </header>
    <div className="ct-cluster-meta ct-label">
      <span className={computer.reachable && !stale ? 'ct-ok' : 'ct-faint'}>{computer.reachable ? stale ? 'RECONNECTING' : computer.node ? 'MESH ONLINE' : 'LOCAL' : 'OFFLINE'}</span>
      <span className="ct-faint">{metrics ? `${metrics.machine} · ${Math.round(metrics.memory_total / GB)} GB` : computer.reachable ? 'READING METRICS…' : 'WAITING FOR COMPUTER'}</span>
    </div>
    {problem && <p className="ct-cluster-note ct-warn" role="status">Metrics unavailable. Retrying automatically.</p>}
    {stale && metrics && <p className="ct-cluster-note ct-faint">Last sample {new Date(metrics.at).toLocaleTimeString()} · readings below are paused.</p>}
    <div className="ct-cluster-readings"><MachineReadings metrics={metrics} history={history} /></div>
    <footer className="ct-cluster-card-foot">
      {computer.reachable ? <ClusterAlerts node={computer.node} /> : <span className="ct-label ct-faint">READINGS RESUME WHEN ONLINE</span>}
      <span className="grow" /><button type="button" className="ct-link" onClick={onSelect}>VIEW MACHINE <span aria-hidden>→</span></button>
    </footer>
  </article>;
}

function ClusterAlerts({ node }: { node: string }) {
  const { alerts, loading, problem } = useMachineAlerts(node);
  const count = alerts.filter((alert) => !alert.dismissed && alert.severity !== 'info').length;
  return <span className={`ct-label ${count ? 'ct-warn' : 'ct-faint'}`}>{loading ? 'ALERTS…' : problem ? 'ALERTS UNAVAILABLE' : count ? `${count} ALERT${count === 1 ? '' : 'S'}` : 'NO ALERTS'}</span>;
}
