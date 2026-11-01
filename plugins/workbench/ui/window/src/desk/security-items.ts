/** The Alerts & Security list's rows, shared by the page and every count of what needs the
 * person: sweep groups, live incidents and machine alerts, each listed once. */
import type { Alert, Decision, Finding, SecurityIncident, SweepReport } from './api';

/** One row of the list: a group of sweep findings, a live incident or a machine alert. */
export interface Item {
  key: string;
  kind: 'sweep' | 'incident' | 'alert';
  title: string;
  /** The group's full name when the title is its last part. */
  where: string;
  text: string;
  severity: string;
  open: boolean;
  last: number;
  count: number;
  findings: Finding[];
  incident?: SecurityIncident;
  alert?: Alert;
  decision?: Decision;
}

const PRIORITY: Record<string, string> = { critical: 'ACT NOW', high: 'ACT NOW', medium: 'SOON', warn: 'SOON', low: 'WATCH', info: 'NOTED' };
export const priority = (severity: string) => PRIORITY[severity] ?? 'NOTED';
export const rank = (severity: string) => (({ high: 0, warn: 1, medium: 1, low: 2, info: 3 } as Record<string, number>)[severity] ?? 4);
export const nameOf = (group: string) => (group.includes('/') ? group.split('/').filter(Boolean).pop() : group) || group;

/** The open rows rated ACT NOW or SOON: what every alerts count shows. */
export const needingYou = (items: Item[]) => items.filter((item) => item.open && ['ACT NOW', 'SOON'].includes(priority(item.severity))).length;

/** Sweep groups, live incidents and machine alerts as one list, open and worst first. */
export function itemsOf(report: SweepReport | null, incidents: SecurityIncident[], alerts: Alert[]): Item[] {
  const items: Item[] = [];
  const groups = new Map<string, Finding[]>();
  for (const finding of report?.findings ?? []) {
    const group = finding.group || finding.source;
    groups.set(group, [...(groups.get(group) ?? []), finding]);
  }
  for (const [group, findings] of groups) {
    const open = findings.filter((finding) => !finding.ignored);
    const listed = (open.length ? open : findings).sort((a, b) => rank(a.severity) - rank(b.severity));
    const incident = incidents.find((entry) => entry.key === `group:${group}` && entry.state !== 'dismissed') ?? incidents.find((entry) => entry.key === `group:${group}`);
    const title = nameOf(group);
    items.push({
      key: group, kind: 'sweep', title, where: title === group ? '' : group, text: listed[0]!.text,
      severity: listed[0]!.severity, open: open.length > 0, last: incident?.last_at ?? report?.at ?? 0, count: listed.length,
      findings: listed, incident, decision: report?.decisions?.find((decision) => decision.group === group),
    });
  }
  for (const incident of incidents) {
    if (incident.key.startsWith('group:')) continue;
    items.push({ key: incident.id, kind: 'incident', title: incident.title, where: '', text: `${new Intl.NumberFormat().format(incident.observations.length)} linked observation${incident.observations.length === 1 ? '' : 's'}`, severity: incident.severity, open: incident.state !== 'dismissed', last: incident.last_at, count: incident.observations.length, findings: [], incident });
  }
  // A security alert is also its incident (same title): listed once, as the incident.
  const titles = new Set(incidents.map((incident) => incident.title));
  for (const alert of alerts) {
    if (alert.dismissed || alert.kind === 'security-incident' || titles.has(alert.text)) continue;
    items.push({ key: alert.id, kind: 'alert', title: alert.text, where: '', text: alert.kind, severity: alert.severity, open: true, last: alert.at, count: 1, findings: [], alert });
  }
  return items.sort((a, b) => Number(b.open) - Number(a.open) || rank(a.severity) - rank(b.severity) || b.last - a.last);
}
