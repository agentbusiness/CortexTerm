import type { PluginInfo } from '@cortex/sdk';

export interface ServiceRow {
  category: string;
  plugin: PluginInfo | null;
}

/** A plugin as one unit (frame.plugins.list `units`); a disabled one's service is meant to be off. */
export interface PluginUnit { id: string; enabled: boolean; category?: string | null; version?: string; standby?: boolean }

/** One row per category: the active instance when there is one, else the newest; missing ones too. */
export function serviceRows(list: readonly PluginInfo[], units: readonly PluginUnit[] = []): ServiceRow[] {
  // Installed backends define what this app expects. Protocol categories also include services
  // other Cortex apps provide; their absence here is not a failure.
  const declared = units.filter((unit) => unit.enabled && !unit.standby && unit.category).map((unit) => unit.category as string);
  const categories = [...new Set([...declared, ...list.map((plugin) => plugin.category)])];
  return categories.map((category) => {
    const candidates = list.filter((plugin) => plugin.category === category);
    const plugin = candidates.find((p) => p.state === 'active') ?? [...candidates].sort((a, b) => b.started_ms - a.started_ms)[0] ?? null;
    return { category, plugin };
  });
}

/** The services that should run and do not: every row not active, minus those of disabled plugins. */
export function downServices(list: readonly PluginInfo[], units: readonly PluginUnit[]): ServiceRow[] {
  const off = new Set(units.filter((unit) => !unit.enabled && unit.category).map((unit) => unit.category as string));
  return serviceRows(list, units).filter((row) => row.plugin?.state !== 'active' && !off.has(row.category));
}
