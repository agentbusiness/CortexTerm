import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { ComputerScope, Cross, HostContext, useSelection, useShared, useThemeData, type Host, type ShellBridge, type SlotListProps, type SlotRenderProps } from '@cortex/sdk';
import { SlotHost } from './SlotHost';
import { Desk } from '../desk/Desk';
import { isStateSettled, subscribeBoot } from './boot';
import { Splash } from './Splash';
import { WorkbenchContext, importPlugin, linkStyle, missingSdk, type WorkbenchServices } from './context';
import type { PluginRegistry } from './registry';
import type { SwapRecord } from './engine';

export type ThemePreference = 'dark' | 'light' | 'system';

const VIEW_ATTR: Record<ThemePreference, string> = { system: 'auto', dark: 'plate', light: 'page' };

/** Put the chosen ground on the document: `auto` follows the machine. */
export function applyTheme(preference: ThemePreference): void {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const resolved = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = resolved;
}


/**
 * The workbench core: the window frame (the plate with its brand mark), the regions,
 * and the slot machinery. Everything a person can press lives in a plugin: the band's items, the
 * sidebar, the conversation, the card, the right pane. The core holds no feature UI.
 */
export function Workbench({ registry, shell }: { registry: PluginRegistry; shell: ShellBridge | null }) {
  const [view] = useShared<ThemePreference>('view', 'dark');
  const [toast, setToast] = useState<{ text: string; more: number } | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    applyTheme(view);
    if (view !== 'system') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => applyTheme('system');
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [view]);

  const notify = useCallback((text: string) => {
    // One toast: the newest line, with a count standing in for the ones it replaced.
    setToast((current) => ({ text, more: current ? current.more + 1 : 0 }));
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 6000);
  }, []);

  const onSwap = useCallback((record: SwapRecord) => {
    const swaps = ((window as unknown as { __cortexSwaps?: SwapRecord[] }).__cortexSwaps ??= []);
    swaps.push(record);
    // A swap that worked is silent (the part simply shows its new version); only a swap that did
    // not take is told.
    if (record.outcome === 'rolled_back') notify(`Put back the previous ${slotLabel(record.slot)}`);
    else if (record.outcome === 'rejected') {
      console.error(`UI plugin for ${record.slot} rejected: ${record.reason ?? ''}`);
      notify(`Kept the running ${slotLabel(record.slot)}: the new build failed (${record.reason ?? 'no reason given'})`);
    } else if (record.outcome === 'waiting') {
      // Not a failure: the window that brings the names reloads the page, and the build mounts then.
      console.info(`UI plugin for ${record.slot} waits for the workbench update: ${record.reason ?? ''}`);
      notify(`The new ${slotLabel(record.slot)} waits for the workbench update`);
    }
  }, [notify]);

  const services = useMemo<WorkbenchServices>(() => ({ registry, loadModule: importPlugin, loadStyle: linkStyle, missingSdk, onSwap }), [registry, onSwap]);

  const host = useMemo<Host>(() => ({
    Slot: (props: SlotRenderProps) => <BoundSlot registry={registry} {...props} />,
    Slots: (props: SlotListProps) => <SlotList registry={registry} {...props} />,
    shell,
    notify,
    uiPlugins: () => registry.list(),
    subscribeUiPlugins: (listener) => registry.subscribe(listener),
    reloadPlugin: (id) => registry.reload(id),
  }), [registry, shell, notify]);

  // The window is drawn once a theme is active (or when the frame serves none: then unstyled).
  const theme = useThemeData();
  const themeAvailable = useSyncExternalStore((listener) => registry.subscribe(listener), () => !registry.isLoaded() || Boolean(registry.forSlot('theme@1')));
  const ready = Boolean(theme) || !themeAvailable;
  const settled = useSyncExternalStore(subscribeBoot, isStateSettled);

  return (
    <WorkbenchContext.Provider value={services}>
      <HostContext.Provider value={host}>
        <div id="cc" data-view={VIEW_ATTR[view]} className="drawn" data-theme-ready={ready ? 'true' : 'false'}>
          {/* The theme and the band are this computer's, whichever computer's project is shown. */}
          <ComputerScope node={null}>
            <BoundSlot registry={registry} name="theme@1" className="cx-theme-slot" />
          </ComputerScope>
          {ready && (<>
          <svg className="reg tl" viewBox="0 0 11 11" aria-hidden><path d="M5.5 0v11M0 5.5h11" stroke="currentColor" strokeWidth="1" /></svg>
          <svg className="reg tr" viewBox="0 0 11 11" aria-hidden><path d="M5.5 0v11M0 5.5h11" stroke="currentColor" strokeWidth="1" /></svg>
          <div className="band">
            <div className="mark">
              <b>CortexTerm</b>
              <Cross />
              <i>IronGraph</i>
            </div>
            {/* The Desk puts its own band items here: the Desk's name, the model, attention, Map. */}
            <div id="ct-band" className="ct-band-items" />
          </div>
          {settled && <Desk />}
          </>)}
          {/* One transient line; it leaves on its own, so the core frame has nothing to press. */}
          <div className={`toast${toast ? ' up' : ''}`} role="status" aria-live="polite">
            {toast && (
              <>
                <span className="ap">{toast.text}</span>
                {toast.more > 0 && <span className="ap faint">+{toast.more}</span>}
              </>
            )}
          </div>
        </div>
        {/* Over the window until it is drawn as the person left it. */}
        <Splash registry={registry} themeReady={ready} />
      </HostContext.Provider>
    </WorkbenchContext.Provider>
  );
}

/** A slot whose plugin can be mounted again from scratch (Reload in Settings). */
function BoundSlot({ registry, name, props, className }: SlotRenderProps & { registry: PluginRegistry }) {
  const byFlow = useSyncExternalStore((listener) => registry.subscribe(listener), () => registry.byFlow(name));
  return byFlow ? <FlowSlot registry={registry} name={name} props={props} className={className} /> : <PickedSlot registry={registry} name={name} props={props} className={className} />;
}

/** A slot whose plugins belong to flows (the conversation, its composer): the open session's. */
function FlowSlot(props: SlotRenderProps & { registry: PluginRegistry }) {
  const { session } = useSelection();
  return <PickedSlot {...props} flow={session?.flow ?? 'coding'} />;
}

function PickedSlot({ registry, name, props, className, flow }: SlotRenderProps & { registry: PluginRegistry; flow?: string }) {
  const picked = useSyncExternalStore(
    (listener) => registry.subscribe(listener),
    () => {
      const plugin = registry.forSlot(name, flow);
      return plugin ? `${plugin.id}\n${plugin.id}:${registry.reloadToken(plugin.id)}` : '';
    },
  );
  const [pluginId, token] = picked ? picked.split('\n') : [undefined, ''];
  return <SlotHost key={token} name={name} pluginId={pluginId} props={props} className={className} />;
}

/** Every plugin contributed to a slot, each in its own slot host (each hot-swaps on its own). */
function SlotList({ registry, name, props, className }: SlotListProps & { registry: PluginRegistry }) {
  const ids = useSyncExternalStore(
    (listener) => registry.subscribe(listener),
    () => registry.allForSlot(name).map((plugin) => `${plugin.id}:${registry.reloadToken(plugin.id)}`).join('\n'),
  );
  if (!ids) return null;
  return (
    <>
      {ids.split('\n').map((entry) => {
        const id = entry.slice(0, entry.lastIndexOf(':'));
        return <SlotHost key={entry} name={name} pluginId={id} props={props} className={className} />;
      })}
    </>
  );
}

function slotLabel(slot: string): string {
  const name = slot.replace(/@\d+$/, '').split('.').pop() ?? slot;
  return name.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
}

// ─── the split ─────────────────────────────────────────────────────────────────────────────
// The core owns the window's three columns: the sidebar, the conversation and the right pane.
