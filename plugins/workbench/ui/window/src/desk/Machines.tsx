/**
 * SSH hosts and keys (`system.ssh.*`) and scheduled jobs (`system.schedule*`), as panes. A host card
 * opens a shell on it; a key's health says what to do about it; a schedule runs while the app runs.
 */

import { useEffect, useState } from 'react';
import { errorMessage, useRuntime, useEvent } from '@cortex/sdk';
import { seconds } from './api';
import type { PaneRec } from './store';
import { PaneFrame } from './Views';

interface SshHost {
  alias: string; hostname: string; user: string; port: number; identity: string[]; proxy_jump?: string | null;
  source: string; defined_at?: string | null; last_used: number; reachable: string; mosh: boolean;
}
interface SshKey { path: string; kind: string; bits: number; fingerprint: string; comment: string; passphrase?: boolean | null; in_agent: boolean; used_by: string[]; health: string; notes: string[] }
interface ScheduleRun { id: string; name: string; at: number; duration_ms: number; exit_code: number; tail: string[]; alerted: boolean }
interface Schedule { id: string; name: string; kind: string; command: string; cwd: string; when: string; enabled: boolean; alert_on: string; next: number; last?: ScheduleRun | null }

interface Controls { pane: PaneRec; focused: boolean; onFocus: () => void; onShelf: () => void; onClose: () => void }

export function SshPane({ onShell, onAsk, ...frame }: Controls & { onShell: (command: string) => void; onAsk: (text: string, intent: 'ask' | 'explain') => void }) {
  const [hosts, setHosts] = useState<{ hosts: SshHost[]; agent: string; agent_socket: string } | null>(null);
  const [keys, setKeys] = useState<SshKey[] | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const client = useRuntime().client;
  useEffect(() => {
    client.call<{ hosts: SshHost[]; agent: string; agent_socket: string }>('system.ssh.hosts', {}).then(setHosts).catch((cause) => setProblem(errorMessage(cause)));
    client.call<{ keys: SshKey[] }>('system.ssh.keys', {}).then((list) => setKeys(list?.keys ?? [])).catch((cause) => setProblem(errorMessage(cause)));
  }, [client]);
  const shown = (hosts?.hosts ?? []).filter((host) => !filter || `${host.alias} ${host.hostname} ${host.user}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <PaneFrame {...frame} title="SSH · HOSTS & KEYS" status={hosts ? `AGENT: ${hosts.agent.toUpperCase()}` : ''}>
      <div className="ct-machines">
        {problem && <p className="ct-hint ct-warn">{problem}</p>}
        <label className="ct-find"><span className="ct-label ct-faint">HOSTS</span>
          <input type="text" value={filter} placeholder="find a host" onChange={(event) => setFilter(event.target.value)} /></label>
        <div className="ct-hostgrid">
          {hosts && shown.length === 0 && <p className="ct-hint">No hosts yet: they come from ~/.ssh/config, known_hosts and your history.</p>}
          {shown.map((host) => (
            <div key={`${host.alias}:${host.source}`} className="ct-host">
              <div className="ct-host-head">
                <span className={`ct-dot ${host.reachable === 'up' ? 'running' : host.reachable === 'down' ? 'failed' : ''}`} aria-hidden title={host.reachable} />
                <span className="ct-reading-name">{host.alias}</span>
                <span className="grow" />
                <span className="ct-label ct-faint">{host.source}</span>
              </div>
              <span className="ct-mono ct-faint ct-host-line">{host.user ? `${host.user}@` : ''}{host.hostname}{host.port && host.port !== 22 ? `:${host.port}` : ''}{host.proxy_jump ? ` via ${host.proxy_jump}` : ''}</span>
              <span className="ct-label ct-faint">{host.last_used ? `USED ${new Date(host.last_used).toLocaleDateString()}` : 'NOT USED HERE YET'}{host.identity.length ? ` · KEY ${host.identity[0]!.split('/').pop()}` : ''}</span>
              <div className="ct-quick">
                <button type="button" className="detent sm warn" onClick={() => onShell(`ssh ${host.alias}`)}>OPEN SHELL</button>
                {host.mosh && <button type="button" className="detent sm" onClick={() => onShell(`mosh ${host.alias}`)}>MOSH</button>}
                <button type="button" className="detent sm" onClick={() => onAsk(`Check my ssh setup for host "${host.alias}" (${host.user}@${host.hostname}:${host.port}, source ${host.source}, key ${host.identity.join(', ') || 'default'}, reachable: ${host.reachable}). Anything to fix?`, 'ask')}>CHECK</button>
              </div>
            </div>
          ))}
        </div>
        <span className="ct-label ct-faint">KEYS</span>
        <div className="ct-keys">
          {keys && keys.length === 0 && <p className="ct-hint">No keys in ~/.ssh or in the agent.</p>}
          {(keys ?? []).map((key) => (
            <div key={key.path} className={`ct-key ${key.health}`}>
              <span className={`ct-label sev ${key.health === 'good' ? 'ct-ok' : 'ct-lift'}`}>{key.health.toUpperCase()}</span>
              <span className="ct-mono ct-key-path">{key.path.split('/').pop()}</span>
              <span className="ct-faint">{key.kind}{key.bits ? ` ${key.bits}` : ''}{key.in_agent ? ' · in agent' : ''}{key.passphrase === false ? ' · no passphrase' : ''}{key.used_by.length ? ` · ${key.used_by.slice(0, 3).join(', ')}` : ''}</span>
              <span className="grow" />
              {key.notes.length > 0 && <span className="ct-faint ct-key-notes">{key.notes.join(' · ')}</span>}
            </div>
          ))}
        </div>
      </div>
    </PaneFrame>
  );
}

const EMPTY: Schedule = { id: '', name: '', kind: 'command', command: '', cwd: '', when: 'daily 09:00', enabled: true, alert_on: '', next: 0 };

export function SchedulesPane({ home, ...frame }: Controls & { home: string }) {
  const [list, setList] = useState<Schedule[] | null>(null);
  const [draft, setDraft] = useState<Schedule | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const client = useRuntime().client;
  const load = () => client.call<{ schedules: Schedule[] }>('system.schedule.list', {}).then((result) => setList(result?.schedules ?? [])).catch((cause) => setProblem(errorMessage(cause)));
  useEffect(() => { void load(); }, []);
  useEvent('system.schedule.done', () => void load());
  const save = () => {
    if (!draft) return;
    client.call(draft.id ? 'system.schedule.edit' : 'system.schedule.create', { ...draft, cwd: draft.cwd || home }).then(() => { setDraft(null); setProblem(null); void load(); }).catch((cause) => setProblem(errorMessage(cause)));
  };
  const runNow = (schedule: Schedule) => {
    setRunning(schedule.id);
    client.call('system.schedule.run', { id: schedule.id }).then(() => void load()).catch((cause) => setProblem(errorMessage(cause))).finally(() => setRunning(null));
  };
  const toggle = (schedule: Schedule) => client.call('system.schedule.edit', { ...schedule, enabled: !schedule.enabled }).then(() => void load()).catch((cause) => setProblem(errorMessage(cause)));
  const remove = (schedule: Schedule) => client.call('system.schedule.delete', { id: schedule.id }).then(() => void load()).catch((cause) => setProblem(errorMessage(cause)));
  return (
    <PaneFrame {...frame} title="SCHEDULES" status="RUN WHILE CORTEXTERM RUNS · MISSED RUNS CATCH UP AT START"
      tools={<button type="button" className="detent sm" onClick={() => setDraft({ ...EMPTY })}>NEW</button>}>
      <div className="ct-machines">
        {problem && <p className="ct-hint ct-warn">{problem}</p>}
        {draft && (
          <div className="ct-sched-form">
            <label><span className="ct-label ct-faint">NAME</span><input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="nightly backup check" /></label>
            <label><span className="ct-label ct-faint">COMMAND</span><input className="ct-mono" value={draft.command} onChange={(event) => setDraft({ ...draft, command: event.target.value })} placeholder="df -h / && brew outdated" /></label>
            <label><span className="ct-label ct-faint">WHEN</span><input value={draft.when} onChange={(event) => setDraft({ ...draft, when: event.target.value })} placeholder="daily 09:00 · hourly · every 30 min · weekly mon 08:00" /></label>
            <label><span className="ct-label ct-faint">ALERT WHEN OUTPUT HAS</span><input value={draft.alert_on} onChange={(event) => setDraft({ ...draft, alert_on: event.target.value })} placeholder="(optional) error" /></label>
            <label><span className="ct-label ct-faint">IN</span><input className="ct-mono" value={draft.cwd} onChange={(event) => setDraft({ ...draft, cwd: event.target.value })} placeholder={home} /></label>
            <div className="ct-quick"><button type="button" className="detent warn" onClick={save}>SAVE</button><button type="button" className="detent" onClick={() => setDraft(null)}>CANCEL</button></div>
          </div>
        )}
        {list && list.length === 0 && !draft && <p className="ct-hint">Nothing scheduled.</p>}
        {(list ?? []).map((schedule) => (
          <div key={schedule.id} className={`ct-sched${schedule.enabled ? '' : ' off'}`}>
            <div className="ct-sched-head">
              <span className={`ct-dot ${schedule.last && schedule.last.exit_code !== 0 ? 'failed' : schedule.enabled ? 'running' : ''}`} aria-hidden />
              <span className="ct-reading-name">{schedule.name}</span>
              <span className="ct-label ct-faint">{schedule.when.toUpperCase()}{schedule.enabled && schedule.next ? ` · NEXT ${new Date(schedule.next).toLocaleString()}` : schedule.enabled ? '' : ' · OFF'}</span>
              <span className="grow" />
              <button type="button" className="detent sm" disabled={running === schedule.id} onClick={() => runNow(schedule)}>{running === schedule.id ? 'RUNNING…' : 'RUN NOW'}</button>
              <button type="button" className="detent sm" onClick={() => void toggle(schedule)}>{schedule.enabled ? 'PAUSE' : 'RESUME'}</button>
              <button type="button" className="detent sm" onClick={() => setDraft(schedule)}>EDIT</button>
              {schedule.kind !== 'sweep' && <button type="button" className="ct-x" aria-label={`Delete ${schedule.name}`} onClick={() => void remove(schedule)}>×</button>}
            </div>
            {schedule.kind === 'command' && <code className="ct-mono ct-faint">{schedule.command}</code>}
            {schedule.last && (
              <div className="ct-sched-last">
                <span className={`ct-label ${schedule.last.exit_code === 0 && !schedule.last.alerted ? 'ct-ok' : 'ct-lift'}`}>
                  LAST {new Date(schedule.last.at).toLocaleString()} · {schedule.last.exit_code === 0 ? 'OK' : `EXIT ${schedule.last.exit_code}`} · {seconds(schedule.last.duration_ms)}{schedule.last.alerted ? ' · ALERTED' : ''}
                </span>
                {schedule.last.tail.length > 0 && <pre className="ct-mono ct-sched-tail">{schedule.last.tail.slice(-6).join('\n')}</pre>}
              </div>
            )}
          </div>
        ))}
      </div>
    </PaneFrame>
  );
}
