import type { Terminal, IDisposable } from '@xterm/xterm';

export interface ProgressItem {
  label: string;
  percent: number | null;
  state: 'normal' | 'error' | 'paused' | 'indeterminate';
  source: 'reported' | 'redraw';
}

export interface RunProgress { runId: string | null; items: ProgressItem[] }
interface Frame { key: string; text: string; spinner?: string; item: ProgressItem }

// These labels come from the terminal, never HTML. Match the output reader's hidden-text policy.
function visible(text: string): string {
  return text.replace(/[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu, '').trim();
}

/** Recognize a measurement, not just a number. A redraw must independently confirm it. */
function frame(text: string): Frame | null {
  text = visible(text);
  const percentages = [...text.matchAll(/(?:^|[^\d.])(\d{1,3}(?:\.\d+)?)\s*%/g)];
  const counter = text.match(/\b(\d+(?:\.\d+)?)\s*\/\s*(\d+(?:\.\d+)?)\b/);
  const bar = /[━─═█▓▒░▉-▏#=]{3,}|\[[=># .-]{3,}\]/u.test(text);
  const spinner = text.match(/^(?:([|/\\-])\s+|([\u2801-\u28ff])\s*)|\s([\u2801-\u28ff])$/u);
  let percent: number | null = null;
  if (percentages.length === 1 && (bar || counter)) percent = Number(percentages[0]![1]);
  else if (counter && bar) {
    const done = Number(counter[1]), total = Number(counter[2]);
    if (total > 0 && done <= total) percent = done / total * 100;
  }
  if (percent !== null && (!Number.isFinite(percent) || percent < 0 || percent > 100)) return null;
  if (percent === null && !spinner) return null;
  const label = text
    .replace(/\[[=># .-]{3,}\]|[━─═█▓▒░▉-▏#=]{3,}/gu, ' ')
    .replace(/\b\d+(?:\.\d+)?\s*\/\s*\d+(?:\.\d+)?\b/g, ' ')
    .replace(/\b\d+(?:\.\d+)?\s*%/g, ' ')
    .replace(/^[|/\\-]\s+|[\u2801-\u28ff]/gu, ' ')
    .replace(/\[\s*\]|\(\s*\)/g, ' ')
    .replace(/\s+/g, ' ').trim().slice(0, 160) || 'Working';
  // Identity is only used for the same screen row after an actual terminal redraw.
  const key = label.replace(/\d+(?:[.,]\d+)*/g, '#');
  return { key, text, spinner: spinner?.[1] ?? spinner?.[2] ?? spinner?.[3], item: { label, percent, state: percent === null ? 'indeterminate' : 'normal', source: 'redraw' } };
}

/** Observe the existing emulator; do not emulate the terminal again or rewrite recorded logs. */
export class TerminalProgress {
  private runId: string | null = null;
  private previous = new Map<number, Frame>();
  private active = new Map<number, Frame>();
  private reported: ProgressItem | null = null;
  private redrawing = false;
  private carriageReturn = false;
  private last = '';
  private lastAt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private subscriptions: IDisposable[];

  constructor(private term: Terminal, private changed: (progress: RunProgress) => void) {
    this.subscriptions = [
      term.parser.registerOscHandler(9, (data) => this.osc(data)),
      term.onWriteParsed(() => this.parsed()),
      term.onResize(() => { this.previous.clear(); this.active.clear(); this.publish(); }),
      term.buffer.onBufferChange(() => { this.previous.clear(); this.active.clear(); this.publish(); }),
      term.onLineFeed(() => {
        // At the scrollback limit row indexes are reused. Require fresh evidence after rollover.
        if (term.buffer.active.baseY >= (term.options.scrollback ?? 5000)) {
          this.previous.clear();
          this.active.clear();
        }
      }),
      ...['A', 'F', 'G', 'H', 'f', 'K'].map((final) => term.parser.registerCsiHandler({ final }, () => {
        this.redrawing = true;
        return false; // The emulator must still execute the cursor/erase operation.
      })),
    ];
  }

  setRun(runId: string | null) {
    if (this.runId === runId) return;
    this.runId = runId;
    this.previous.clear();
    this.active.clear();
    this.reported = null;
    this.redrawing = false;
    this.carriageReturn = false;
    this.publish(true);
  }

  /** Distinguish CR redraws from ordinary CRLF, even when a chunk ends between the two. */
  observe(bytes: Uint8Array) {
    if (!this.runId) return;
    for (const byte of bytes) {
      if (this.carriageReturn && byte !== 10) this.redrawing = true;
      this.carriageReturn = byte === 13;
    }
  }

  private osc(data: string): boolean {
    if (!data.startsWith('4;') || !this.runId) return false;
    const parts = data.split(';');
    if (parts.length > 3 || !/^[0-4]$/.test(parts[1]!)) return false;
    const state = Number(parts[1]);
    const value = parts[2];
    if (state !== 0 && state !== 3 && value !== undefined && !/^\d+$/.test(value)) return false;
    const previous = this.reported?.percent ?? 0;
    const number = value === undefined ? 0 : Math.min(100, Number(value));
    this.reported = state === 0 ? null : {
      label: 'Program progress',
      percent: state === 3 ? null : ((state === 2 || state === 4) && number === 0 ? previous : number),
      state: state === 2 ? 'error' : state === 3 ? 'indeterminate' : state === 4 ? 'paused' : 'normal',
      source: 'reported',
    };
    // A clear must not resurrect a stale inferred bar from the previous phase.
    this.active.clear();
    this.previous.clear();
    this.publish(state !== 1);
    return true;
  }

  private parsed() {
    if (!this.runId || this.term.buffer.active.type !== 'normal') return;
    if (this.reported) { this.redrawing = false; return; }
    const buffer = this.term.buffer.active;
    const next = new Map<number, Frame>();
    for (let y = 0; y < this.term.rows; y++) {
      const row = buffer.baseY + y;
      const line = buffer.getLine(row);
      if (!line || line.isWrapped) continue;
      const current = frame(line.translateToString(true));
      if (!current) continue;
      next.set(row, current);
      const previous = this.previous.get(row);
      const animated = current.item.percent !== null || (previous?.spinner !== current.spinner);
      if (this.redrawing && previous?.key === current.key && previous.text !== current.text && animated) this.active.set(row, current);
      else if (this.active.get(row)?.key === current.key && previous?.text === current.text) this.active.set(row, current);
      else this.active.delete(row);
    }
    for (const row of this.active.keys()) if (!next.has(row)) this.active.delete(row);
    this.previous = next;
    this.redrawing = false;
    this.publish();
  }

  private publish(force = false) {
    const items = this.runId ? (this.reported ? [this.reported] : [...this.active.values()].slice(-4).map((entry) => entry.item)) : [];
    const key = JSON.stringify([this.runId, items]);
    if (key === this.last) return;
    const now = performance.now();
    if (!force && now - this.lastAt < 100) {
      this.timer ??= setTimeout(() => { this.timer = null; this.publish(); }, 100 - (now - this.lastAt));
      return;
    }
    if (this.timer !== null) { clearTimeout(this.timer); this.timer = null; }
    this.lastAt = now;
    this.last = key;
    this.changed({ runId: this.runId, items });
  }

  dispose() {
    if (this.timer !== null) clearTimeout(this.timer);
    for (const subscription of this.subscriptions) subscription.dispose();
  }
}
