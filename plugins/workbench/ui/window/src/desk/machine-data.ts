/** One alert subscription per computer, shared by its tab, pane and cluster card. Its count
 * (`needing`) is the Alerts & Security list's: open rows rated ACT NOW or SOON. */
import { useSyncExternalStore } from 'react';
import { errorMessage, runtimeFor } from '@cortex/sdk';
import type { Alert, SecurityIncident, SweepReport } from './api';
import { itemsOf, needingYou } from './security-items';

interface AlertSnapshot { alerts: Alert[]; needing: number; loading: boolean; problem: string | null }

class MachineAlerts {
  private snapshot: AlertSnapshot = { alerts: [], needing: 0, loading: true, problem: null };
  private report: SweepReport | null = null;
  private incidents: SecurityIncident[] = [];
  private listeners = new Set<() => void>();
  private stop: (() => void) | null = null;
  private generation = 0;
  private request = 0;

  constructor(private readonly node: string | null) {}

  get = () => this.snapshot;

  private update(snapshot: Omit<AlertSnapshot, 'needing'>) {
    this.snapshot = { ...snapshot, needing: needingYou(itemsOf(this.report, this.incidents, snapshot.alerts)) };
    for (const listener of this.listeners) listener();
  }

  reload = async () => {
    const generation = this.generation;
    const request = ++this.request;
    const before = new Set(this.snapshot.alerts.map((alert) => alert.id));
    const client = runtimeFor(this.node).client;
    // The sweep and the incidents only shape the count: without them it counts the alerts alone.
    const [report, status] = await Promise.allSettled([
      client.call<SweepReport>('system.sweep', {}, { signal: AbortSignal.timeout(20_000) }),
      client.call<{ incidents: SecurityIncident[] }>('system.protection.status', {}, { signal: AbortSignal.timeout(8000) }),
    ]);
    if (generation !== this.generation) return;
    if (report.status === 'fulfilled') this.report = report.value;
    if (status.status === 'fulfilled') this.incidents = status.value?.incidents ?? [];
    try {
      const list = await client.call<{ alerts: Alert[] }>('system.alerts', {}, { signal: AbortSignal.timeout(8000) });
      if (generation === this.generation && request === this.request) {
        const arrived = this.snapshot.alerts.filter((alert) => !before.has(alert.id));
        const ids = new Set(arrived.map((alert) => alert.id));
        this.update({ alerts: [...arrived, ...(list?.alerts ?? []).filter((alert) => !ids.has(alert.id))], loading: false, problem: null });
      }
    } catch (cause) {
      if (generation === this.generation && request === this.request) this.update({ ...this.snapshot, loading: false, problem: errorMessage(cause) });
    }
  };

  act = async (id: string, action: string) => {
    await runtimeFor(this.node).client.call('system.alert.act', { id, action });
    // Invalidate a read started before the action, then refresh all views of this computer.
    this.request++;
    this.update({ ...this.snapshot, alerts: this.snapshot.alerts.map((alert) => alert.id === id ? { ...alert, dismissed: true } : alert) });
    await this.reload();
  };

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    if (this.listeners.size === 1) {
      const off = runtimeFor(this.node).client.on('system.alert', (_topic, data) => {
        const alert = data as Alert;
        if (!alert?.id) return;
        this.update({ alerts: [alert, ...this.snapshot.alerts.filter((entry) => entry.id !== alert.id)].slice(0, 300), loading: false, problem: null });
      });
      void this.reload();
      const timer = setInterval(() => void this.reload(), 15_000);
      this.stop = () => { off(); clearInterval(timer); this.generation++; };
    }
    return () => {
      this.listeners.delete(listener);
      if (!this.listeners.size) { this.stop?.(); this.stop = null; }
    };
  };
}

const stores = new Map<string, MachineAlerts>();
export function useMachineAlerts(node?: string | null) {
  const key = node ?? '';
  let store = stores.get(key);
  if (!store) { store = new MachineAlerts(node ?? null); stores.set(key, store); }
  const snapshot = useSyncExternalStore(store.subscribe, store.get);
  return { ...snapshot, reload: store.reload, act: store.act };
}
