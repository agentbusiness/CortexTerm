/**
 * The Desk's state. What a person arranged (Desks, their panes, which are on the Stage) is the
 * durable slot state the frame keeps (`useShared('ct.desks')`), so it is the same after a restart.
 * What the machines report (each shell's state, its last Run) is live and lives
 * here; a shell on a joined computer reports through that computer's frame (`runtimeFor(node)`).
 */

import { useSyncExternalStore } from 'react';
import { runtimeFor } from '@cortex/sdk';
import type { Run, TermState } from './api';

export type PaneKind = 'term' | 'editor' | 'run' | 'process' | 'alerts' | 'ssh' | 'schedules';

export interface PaneRec {
  id: string;
  kind: PaneKind;
  title: string;
  cwd: string;
  termId?: string;
  /** The joined computer the shell runs on (its mesh node); none: this one. */
  node?: string;
  path?: string;
  runId?: string;
  /** Helper shells that ran commands while this one was busy: their cards join this stream. */
  workers?: string[];
}

export interface DeskRec {
  id: string;
  name: string;
  sessionId?: string;
  /** The Desk's `terminal` session on each joined computer it asked on (node -> session). */
  sessions?: Record<string, string>;
  panes: PaneRec[];
  /** Pane ids on the Stage, at most three, left to right. */
  stage: string[];
  focus?: string;
}

export interface DeskDoc {
  desks: DeskRec[];
  current: string;
}

export const EMPTY_DOC: DeskDoc = { desks: [], current: '' };
/** One view at a time: the others are toggles in the tab row. */
export const STAGE_MAX = 1;

export function newId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

/** Attention of a pane, most urgent first. */
export type Attention = 'input' | 'failed' | 'proposal' | 'alert' | 'bell' | 'running' | 'idle' | 'ended';

export const NEEDS_YOU: ReadonlySet<Attention> = new Set(['input', 'failed', 'proposal', 'bell']);

class LiveStore {
  states = new Map<string, TermState>();
  lastRun = new Map<string, Run>();
  ended = new Map<string, number | null>();
  /** Panes with a proposed command or an answer the person has not looked at. */
  unseen = new Set<string>();
  private listeners = new Set<() => void>();
  private finished = new Set<(run: Run, node: string | null) => void>();
  private version = 0;
  private watching = new Set<string>();
  private started = false;

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  snapshot = () => this.version;

  changed() {
    this.version++;
    for (const listener of this.listeners) listener();
  }

  /** Called with every Run that ends, on this computer or a watched one. */
  onFinished(listener: (run: Run, node: string | null) => void) {
    this.finished.add(listener);
    return () => { this.finished.delete(listener); };
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.watch(null);
  }

  /** Listen to a computer's shells (null: this one's), once. */
  watch(node: string | null) {
    if (this.watching.has(node ?? '')) return;
    this.watching.add(node ?? '');
    const client = runtimeFor(node).client;
    client.on('terminal.state', (_topic, data) => {
      const state = data as TermState;
      if (!state?.term_id) return;
      this.states.set(state.term_id, state);
      this.changed();
    });
    client.on('terminal.run.finished', (_topic, data) => {
      const run = data as Run;
      if (!run?.term_id) return;
      this.lastRun.set(run.term_id, run);
      this.changed();
      for (const listener of this.finished) listener(run, node);
    });
    client.on('terminal.run.started', (_topic, data) => {
      const run = data as Run;
      if (!run?.term_id) return;
      const state = this.states.get(run.term_id);
      if (state) this.states.set(run.term_id, { ...state, running: run, at_prompt: false, attention: 'running' });
      this.changed();
    });
    client.on('terminal.exit', (_topic, data) => {
      const event = data as { term_id?: string; exit_code?: number | null };
      if (!event?.term_id) return;
      this.ended.set(event.term_id, event.exit_code ?? null);
      this.changed();
    });
  }

  /** The state of a shell, fetched once when nobody has reported it yet. */
  ensure(termId: string, node?: string | null) {
    this.watch(node ?? null);
    if (this.states.has(termId)) return;
    const client = runtimeFor(node).client;
    client.call<TermState>('terminal.state', { term_id: termId }).then((state) => {
      if (state && !this.states.has(termId)) {
        this.states.set(termId, state);
        this.changed();
      }
    }).catch(() => undefined);
    client.call<{ runs: Run[] }>('terminal.runs', { term_id: termId, limit: 1 }).then((list) => {
      const run = list?.runs?.[0];
      if (run && !this.lastRun.has(termId)) {
        this.lastRun.set(termId, run);
        this.changed();
      }
    }).catch(() => undefined);
  }

  attention(pane: PaneRec): Attention {
    if (pane.kind !== 'term' || !pane.termId) return pane.kind === 'alerts' && this.alerts.some((a) => !a.dismissed && a.severity !== 'info') ? 'alert' : 'idle';
    if (this.ended.has(pane.termId)) return 'ended';
    if (this.unseen.has(pane.id)) return 'proposal';
    const state = this.states.get(pane.termId);
    if (!state) return 'idle';
    if (state.attention === 'input') return 'input';
    if (state.attention === 'bell') return 'bell';
    if (state.running) return 'running';
    if (state.attention === 'failed' || (state.last_exit != null && state.last_exit !== 0)) return 'failed';
    return 'idle';
  }
}

export const live = new LiveStore();

export function useLive(): number {
  return useSyncExternalStore(live.subscribe, live.snapshot);
}
