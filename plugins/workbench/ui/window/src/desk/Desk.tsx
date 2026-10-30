/**
 * The Desk: CortexTerm's window. A Desk is one job (a frame session of the `terminal` flow) with
 * its panes. The Stage shows the one to three you work in, the Shelf the rest as cards, and
 * attention routing (⌘J) brings whatever needs you onto the Stage. The Map (⌘M) shows every Desk;
 * jump (⌘;) finds a pane by name, command or folder. The Line types into the focused shell.
 *
 * The layout is the workbench's: the band on top (the Desk adds its items to it), then Desks |
 * Stage | machine, each divider draggable (double-click: default width), each side able to fold
 * and come back from its band toggle. Every pane can go to the Shelf and come back, or close.
 *
 * A pane may run on a joined computer (`PaneRec.node`): it renders inside that computer's
 * `ComputerScope`, so its calls go to that frame through `mesh.link`, and the Line, the AI and the
 * side pane follow the focused pane there. COMPUTERS in the nav lists the joined computers that run
 * CortexTerm, with the shells open on each.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Caret, ComputerScope, Divider, ago, errorMessage, runtime, runtimeFor, useEvent, useHost, useRuntime, useShared } from '@cortex/sdk';
import './sidebar.css';
import type { Proc, TermState } from './api';
import { shortPath } from './api';
import { Line, type LineHandle } from './Line';
import { Sidebar, modelLabel, useModel } from './Sidebar';
import { TermPane, type TermActions } from './TermPane';
import { AlertsPane, EditorPane, ProcessPane, RunPane } from './Views';
import { Investigate } from './Investigate';
import { Traces } from './Traces';
import { SchedulesPane, SshPane } from './Machines';
import { EMPTY_DOC, NEEDS_YOU, STAGE_MAX, live, newId, useLive, type Attention, type DeskDoc, type DeskRec, type PaneRec } from './store';
import './desk.css';

interface TermInfo { term_id: string; cwd: string; alive: boolean }
interface Place { path: string; runs: number; last: number; git: boolean }
interface Peer { member: { node: string; name: string; local?: boolean }; card?: { name: string; software: string } | null; reachable: boolean; path: string }
/** A joined computer that runs CortexTerm. */
interface Computer { node: string; name: string; reachable: boolean; path: string }
type Client = ReturnType<typeof runtime>['client'];

const clientOf = (node?: string | null) => runtimeFor(node).client;

/** The home place's project on a computer's frame: its first project, else one opened at `~`. */
async function homeProject(client: Client): Promise<{ id: string; root: string }> {
  const projects = await client.call<{ projects: { id: string; root: string }[] }>('frame.project.list', {});
  const found = projects?.projects?.[0];
  if (found) return found;
  const probe = await client.call<TermInfo>('terminal.open', { cwd: '~', cols: 80, rows: 24 });
  await client.call('terminal.close', { term_id: probe.term_id }).catch(() => undefined);
  return client.call<{ id: string; root: string }>('frame.project.open', { root: probe.cwd });
}

type SideView = 'machine' | 'alerts' | 'traces' | 'ssh' | 'schedules' | 'log' | 'investigate';

const NAV = { def: 220, min: 160, max: 420, fold: 110 };
const SIDE = { def: 420, min: 320, max: 760, fold: 220 };
const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

/** The three columns' widths and folds, in the workbench's durable state (they survive restarts). */
function useColumns() {
  const work = useRef<HTMLDivElement>(null);
  const [nav, setNav] = useShared<number>('ct.layout.nav', NAV.def);
  const [side, setSide] = useShared<number>('ct.layout.side', SIDE.def);
  const [navOpen, setNavOpen] = useShared<boolean>('ct.layout.navOpen', true);
  const [sideOpen, setSideOpen] = useShared<boolean>('ct.layout.sideOpen', true);
  const [drag, setDrag] = useState<{ nav?: number; side?: number }>({});
  const box = () => work.current?.getBoundingClientRect();
  const navWidth = drag.nav ?? nav;
  const sideWidth = drag.side ?? side;
  return {
    work,
    navOpen, sideOpen,
    toggleNav: () => setNavOpen((open) => !open),
    toggleSide: () => setSideOpen((open) => !open),
    openSide: () => setSideOpen(true),
    style: { gridTemplateColumns: `${navOpen ? navWidth : 0}px ${navOpen ? 1 : 0}px minmax(0,1fr) ${sideOpen ? 1 : 0}px ${sideOpen ? sideWidth : 0}px` },
    moveNav: (x: number) => { const rect = box(); if (rect) setDrag({ nav: clamp(x - rect.left, NAV.fold - 20, NAV.max) }); },
    endNav: () => {
      const width = drag.nav;
      setDrag({});
      if (width === undefined) return;
      if (width < NAV.fold) setNavOpen(false);
      else setNav(clamp(width, NAV.min, NAV.max));
    },
    resetNav: () => { setNav(NAV.def); setNavOpen(true); },
    moveSide: (x: number) => { const rect = box(); if (rect) setDrag({ side: clamp(rect.right - x, SIDE.fold - 20, SIDE.max) }); },
    endSide: () => {
      const width = drag.side;
      setDrag({});
      if (width === undefined) return;
      if (width < SIDE.fold) setSideOpen(false);
      else setSide(clamp(width, SIDE.min, SIDE.max));
    },
    resetSide: () => { setSide(SIDE.def); setSideOpen(true); },
  };
}

export function Desk() {
  useLive();
  const host = useHost();
  const client = runtime().client;
  const [doc, setDoc] = useShared<DeskDoc>('ct.desks', EMPTY_DOC);
  const [home, setHome] = useState('');
  const [projectId, setProjectId] = useState('');
  const [overlay, setOverlay] = useState<'map' | 'jump' | null>(null);
  const [places, setPlaces] = useState<Place[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  const [settings, setSettings] = useShared<string | null>('settings.open', null);
  const [sideView, setSideView] = useShared<SideView>('ct.side.view', 'machine');
  const [sideRun, setSideRun] = useShared<string>('ct.side.run', '');
  /** The process the Investigate tab shows (0: none, and no tab). */
  const [sidePid, setSidePid] = useShared<number>('ct.side.pid', 0);
  /** The trace the Traces tab shows ('': the list). */
  const [sideTrace, setSideTrace] = useShared<string>('ct.side.trace', '');
  const line = useRef<LineHandle>(null);
  const watched = useRef(new Map<string, string>());
  const helpers = useRef(new Set<string>());
  const booted = useRef(false);
  const columns = useColumns();
  const { info: model, problem: modelProblem } = useModel();

  const desk = doc.desks.find((entry) => entry.id === doc.current) ?? doc.desks[0];
  const update = useCallback((id: string, change: (desk: DeskRec) => DeskRec) => {
    setDoc((current) => ({ ...current, desks: current.desks.map((entry) => (entry.id === id ? change(entry) : entry)) }));
  }, [setDoc]);

  useEffect(() => live.start(), []);

  // --- the joined computers ------------------------------------------------------------------
  const [computers, setComputers] = useState<Computer[]>([]);
  const paneNodes = [...new Set(doc.desks.flatMap((entry) => entry.panes.flatMap((pane) => (pane.node ? [pane.node] : []))))].join(',');
  const readComputers = useCallback(() => {
    const used = paneNodes.split(',');
    client.call<{ peers: Peer[] }>('mesh.peers', {}).then((list) => setComputers((list?.peers ?? [])
      // Another app on this Mac is not another computer; one that is away has no card to say
      // what it runs, so it stays listed when a shell of this window is there.
      .filter((peer) => !peer.member.local && (peer.card ? peer.card.software === 'cortexterm' : used.includes(peer.member.node)))
      .map((peer) => ({ node: peer.member.node, name: peer.card?.name || peer.member.name, reachable: peer.reachable, path: peer.path }))))
      .catch(() => undefined);
  }, [client, paneNodes]);
  useEffect(() => { readComputers(); }, [readComputers]);
  useEvent('mesh.changed', () => readComputers());
  const nameOf = (node?: string) => (node ? computers.find((computer) => computer.node === node)?.name ?? 'another computer' : undefined);

  // --- boot: the home place, a Desk, live shells for every terminal pane ------------------------
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    void (async () => {
      try {
        const project = await homeProject(client);
        setHome(project.root);
        setProjectId(project.id);
        const alive = new Set(((await client.call<{ terminals: TermInfo[] }>('terminal.list', {}))?.terminals ?? []).filter((term) => term.alive).map((term) => term.term_id));
        const stored = runtime().state.get<DeskDoc>('workbench', 'ct.desks') ?? EMPTY_DOC;
        let desks = stored.desks;
        if (desks.length === 0) desks = [await createDesk(project.id, project.root, 'main')];
        // Shells the frame no longer has start again in the folder they were last in. A joined
        // computer's shell stays as it is: that computer may be away now.
        const restored: DeskRec[] = [];
        for (const entry of desks) {
          const panes: PaneRec[] = [];
          for (const pane of entry.panes.filter((rec) => rec.kind === 'term' || rec.kind === 'editor')) {
            if (pane.kind === 'term' && !pane.node && (!pane.termId || !alive.has(pane.termId))) {
              const info = await client.call<TermInfo>('terminal.open', { cwd: pane.cwd || project.root, cols: 120, rows: 32 }).catch(() => null);
              panes.push(info ? { ...pane, termId: info.term_id, cwd: info.cwd } : pane);
            } else panes.push(pane);
          }
          const stage = entry.stage.filter((id) => panes.some((pane) => pane.id === id));
          restored.push({ ...entry, panes, stage: stage.length ? stage : panes.slice(-1).map((pane) => pane.id), sessionId: entry.sessionId ?? (await newSession(project.id, entry.name)) });
        }
        setDoc({ desks: restored, current: stored.current && restored.some((entry) => entry.id === stored.current) ? stored.current : restored[0]?.id ?? '' });
      } catch (cause) {
        setProblem(`CortexTerm could not start its shells: ${errorMessage(cause)}`);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    client.call<{ places: Place[] }>('terminal.places', { limit: 8 }).then((list) => setPlaces(list?.places ?? [])).catch(() => undefined);
  }, [client, desk?.focus]);

  const newSession = async (project: string, title: string) => {
    const session = await client.call<{ id: string }>('frame.session.create', { project_id: project, title, flow: 'terminal' }).catch(() => null);
    return session?.id;
  };

  const createDesk = async (project: string, cwd: string, name: string): Promise<DeskRec> => {
    const info = await client.call<TermInfo>('terminal.open', { cwd, cols: 120, rows: 32 });
    const pane: PaneRec = { id: newId('pane'), kind: 'term', title: 'shell', cwd: info.cwd, termId: info.term_id };
    return { id: newId('desk'), name, sessionId: await newSession(project, name), panes: [pane], stage: [pane.id], focus: pane.id };
  };

  // --- panes ---------------------------------------------------------------------------------
  const addPane = useCallback((pane: PaneRec, where: 'stage' | 'shelf' = 'stage') => {
    if (!desk) return;
    update(desk.id, (entry) => {
      const stage = where === 'stage' ? [...entry.stage.filter((id) => id !== pane.id), pane.id].slice(-STAGE_MAX) : entry.stage;
      return { ...entry, panes: [...entry.panes, pane], stage, focus: where === 'stage' ? pane.id : entry.focus };
    });
  }, [desk, update]);

  /** A new shell, on `node` (none: this computer), in `cwd`, else the focused shell's folder when it is on that computer. */
  const openTerm = useCallback(async (cwd?: string, where: 'stage' | 'shelf' = 'stage', title = 'shell', node?: string) => {
    const base = cwd || (focusedTerm?.node === node ? focusedCwd() : '') || (node ? '~' : home);
    const info = await clientOf(node).call<TermInfo>('terminal.open', { cwd: base || '~', cols: 120, rows: 32 });
    const pane: PaneRec = { id: newId('pane'), kind: 'term', title, cwd: info.cwd, termId: info.term_id, ...(node ? { node } : {}) };
    addPane(pane, where);
    return pane;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [home, addPane, desk]);

  /** A shell already open on a joined computer, as a pane here (or the pane that shows it already). */
  const attachTerm = useCallback((node: string, info: TermInfo) => {
    const shown = desk?.panes.find((pane) => pane.termId === info.term_id);
    if (shown) promote(shown.id);
    else addPane({ id: newId('pane'), kind: 'term', title: 'shell', cwd: info.cwd, termId: info.term_id, node });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [desk, addPane]);

  const closePane = useCallback((paneId: string) => {
    if (!desk) return;
    const pane = desk.panes.find((entry) => entry.id === paneId);
    if (pane?.termId) void clientOf(pane.node).call('terminal.close', { term_id: pane.termId }).catch(() => undefined);
    update(desk.id, (entry) => {
      const panes = entry.panes.filter((other) => other.id !== paneId);
      let stage = entry.stage.filter((id) => id !== paneId);
      const next = panes.at(-1);
      if (stage.length === 0 && next) stage = [next.id];
      return { ...entry, panes, stage, focus: stage.at(-1) };
    });
  }, [desk, update]);

  const promote = useCallback((paneId: string) => {
    if (!desk) return;
    update(desk.id, (entry) => ({ ...entry, stage: entry.stage.includes(paneId) ? entry.stage : [...entry.stage, paneId].slice(-STAGE_MAX), focus: paneId }));
  }, [desk, update]);

  const toShelf = useCallback((paneId: string) => {
    if (!desk) return;
    update(desk.id, (entry) => {
      const stage = entry.stage.filter((id) => id !== paneId);
      return { ...entry, stage, focus: stage.at(-1) };
    });
  }, [desk, update]);

  const focusPane = useCallback((paneId: string) => {
    if (!desk || desk.focus === paneId) return;
    update(desk.id, (entry) => ({ ...entry, focus: paneId }));
    live.unseen.delete(paneId);
    live.changed();
  }, [desk, update]);

  const focused = desk?.panes.find((pane) => pane.id === desk.focus && desk.stage.includes(pane.id)) ?? desk?.panes.find((pane) => desk.stage.includes(pane.id));
  const focusedTerm = focused?.kind === 'term' ? focused : desk?.panes.find((pane) => pane.kind === 'term' && desk.stage.includes(pane.id));
  function focusedCwd() {
    const term = focusedTerm?.termId ? live.states.get(focusedTerm.termId) : undefined;
    return term?.cwd || focusedTerm?.cwd || '';
  }

  // Panes remember the folder their shell is in, for a restart.
  useEffect(() => {
    if (!desk) return;
    const moved = desk.panes.some((pane) => pane.termId && live.states.get(pane.termId)?.cwd && live.states.get(pane.termId)!.cwd !== pane.cwd);
    if (moved) update(desk.id, (entry) => ({ ...entry, panes: entry.panes.map((pane) => (pane.termId && live.states.get(pane.termId)?.cwd ? { ...pane, cwd: live.states.get(pane.termId)!.cwd } : pane)) }));
  });

  // --- running and asking --------------------------------------------------------------------
  /** The computer a shell runs on: its pane's, or its parent pane's for a helper shell. */
  const nodeOfTerm = useCallback((termId: string) => doc.desks.flatMap((entry) => entry.panes).find((pane) => pane.termId === termId || pane.workers?.includes(termId))?.node, [doc.desks]);

  const runIn = useCallback((termId: string, command: string, node = nodeOfTerm(termId)) => {
    const data = command.includes('\n') ? `\x15\x1b[200~${command}\x1b[201~\r` : `\x15${command}\r`;
    void clientOf(node).call('terminal.write', { term_id: termId, data }).catch((cause) => host.notify(`Not sent: ${errorMessage(cause)}`));
  }, [host, nodeOfTerm]);

  const onShell = useCallback(async (command: string, how: 'here' | 'pane' | 'background' | 'watch') => {
    if (how === 'here' && focusedTerm?.termId && desk) {
      // Nothing waits: a busy shell hands the command to a helper shell in the same folder, whose
      // card joins this stream; the helper closes once its command is done.
      if (!live.states.get(focusedTerm.termId)?.running) {
        runIn(focusedTerm.termId, command);
        return;
      }
      const parent = focusedTerm;
      const info = await clientOf(parent.node).call<TermInfo>('terminal.open', { cwd: focusedCwd() || (parent.node ? '~' : home), cols: 120, rows: 32 }).catch(() => null);
      if (!info) return;
      update(desk.id, (entry) => ({ ...entry, panes: entry.panes.map((pane) => (pane.id === parent.id ? { ...pane, workers: [...(pane.workers ?? []).slice(-20), info.term_id] } : pane)) }));
      helpers.current.add(info.term_id);
      setTimeout(() => runIn(info.term_id, command, parent.node), 600);
      return;
    }
    // A command typed for the focused shell runs on that shell's computer.
    const node = focusedTerm?.node;
    const pane = await openTerm(undefined, how === 'here' || how === 'pane' ? 'stage' : 'shelf', command.split(/\s+/)[0] || 'shell', node);
    if (!pane.termId) return;
    if (how === 'watch') watched.current.set(pane.termId, command);
    // The new shell needs a moment to show its prompt.
    setTimeout(() => runIn(pane.termId!, command, node), 700);
    if (how === 'background' || how === 'watch') host.notify(how === 'watch' ? `Watching \`${command}\`: you'll be told when it ends.` : `\`${command}\` runs on the Shelf.`);
  }, [focusedTerm, openTerm, runIn, host, desk, client, home, update]);

  useEffect(() => live.onFinished((run, node) => {
    if (helpers.current.has(run.term_id)) {
      helpers.current.delete(run.term_id);
      setTimeout(() => void clientOf(node).call('terminal.close', { term_id: run.term_id }).catch(() => undefined), 1000);
    }
    const command = watched.current.get(run?.term_id);
    if (!command) return;
    watched.current.delete(run.term_id);
    const outcome = run.exit_code === 0 ? 'finished' : `failed (exit ${run.exit_code})`;
    host.notify(`\`${command}\` ${outcome}`);
    void client.call('notify.send', { kind: run.exit_code === 0 ? 'done' : 'failed', title: `${command} ${outcome}`, body: '' }).catch(() => undefined);
  }), [client, host]);

  /** The Desk's `terminal` session on a computer (none: this one), made on first use there. */
  const sessionOn = async (node: string | undefined): Promise<string | undefined> => {
    if (!desk) return undefined;
    if (!node) {
      if (desk.sessionId || !projectId) return desk.sessionId;
      const sessionId = await newSession(projectId, desk.name);
      if (sessionId) update(desk.id, (entry) => ({ ...entry, sessionId }));
      return sessionId;
    }
    if (desk.sessions?.[node]) return desk.sessions[node];
    const remote = clientOf(node);
    const project = await homeProject(remote).catch(() => null);
    const session = project ? await remote.call<{ id: string }>('frame.session.create', { project_id: project.id, title: desk.name, flow: 'terminal' }).catch(() => null) : null;
    if (session?.id) update(desk.id, (entry) => ({ ...entry, sessions: { ...entry.sessions, [node]: session.id } }));
    return session?.id;
  };

  const onAsk = useCallback(async (text: string, intent: 'ask' | 'explain' | 'fix', runId?: string) => {
    if (!desk) return;
    let termPane = focusedTerm;
    if (!termPane) termPane = await openTerm();
    if (termPane && !desk.stage.includes(termPane.id)) promote(termPane.id);
    // The AI runs on the computer the shell runs on, with that computer's terminal flow.
    const node = termPane?.node;
    const sessionId = await sessionOn(node);
    if (!sessionId) {
      host.notify(node ? `No conversation on ${nameOf(node)} yet: is it reachable?` : 'No conversation for this Desk yet.');
      return;
    }
    void clientOf(node).call('chatflow-terminal.turn', { session_id: sessionId, text, intent, term_id: termPane?.termId, run_id: runId })
      .catch((cause) => host.notify(`Not asked: ${errorMessage(cause)}`));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [desk, projectId, focusedTerm, openTerm, promote, host, update, computers]);

  /** The side pane shows the machine; a tool (alerts, SSH, schedules, a Run's log) opens there in its place. */
  const openTool = useCallback((kind: 'alerts' | 'ssh' | 'schedules' | 'process', _title?: string) => {
    setSideView(kind === 'process' ? 'machine' : kind);
    columns.openSide();
  }, [setSideView, columns]);

  const onNative = useCallback((view: string, target: string | null | undefined) => {
    const cwd = focusedCwd() || home;
    if (view === 'editor' && target) {
      const node = focusedTerm?.node;
      addPane({ id: newId('pane'), kind: 'editor', title: target.split('/').pop() || target, cwd, path: target, ...(node ? { node } : {}) });
      return true;
    }
    if (view === 'process') {
      openTool('process');
      return true;
    }
    return false;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [addPane, openTool, home, desk]);

  /** The computer the side pane shows: the focused pane's. */
  const sideNode = focused?.node;

  const onSignal = useCallback((proc: Proc, signal: string) => {
    clientOf(sideNode).call<{ ok: boolean; detail?: string }>('system.signal', { pid: proc.pid, signal })
      .then((result) => host.notify(result?.ok ? `${signal} sent to ${proc.name} (${proc.pid})` : `${proc.name}: ${result?.detail ?? 'not sent'}`))
      .catch((cause) => host.notify(`${proc.name}: ${errorMessage(cause)}`));
  }, [host, sideNode]);

  const onInvestigate = useCallback((pid: number) => {
    setSidePid(pid);
    setSideView('investigate');
    columns.openSide();
  }, [setSidePid, setSideView, columns]);

  const onOpenTrace = useCallback((id: string) => {
    setSideTrace(id);
    setSideView('traces');
    columns.openSide();
  }, [setSideTrace, setSideView, columns]);

  const actions: TermActions = useMemo(() => ({
    runCommand: runIn,
    editCommand: (command) => line.current?.set(command),
    openRun: (run) => { setSideRun(run.id); setSideView('log'); columns.openSide(); },
    fix: (_pane, run) => void onAsk(`\`${run.command}\` failed with exit code ${run.exit_code}. What went wrong and how do I fix it?`, 'fix', run.id),
    explain: (_pane, text) => void onAsk(`Explain: ${text}`, 'explain'),
  }), [runIn, onAsk, setSideRun, setSideView, columns]);

  // --- attention -------------------------------------------------------------------------------
  const everyPane = doc.desks.flatMap((entry) => entry.panes.map((pane) => ({ desk: entry, pane, attention: live.attention(pane) })));
  const needsYou = everyPane.filter((entry) => NEEDS_YOU.has(entry.attention));
  const openAlerts = live.alerts.filter((alert) => !alert.dismissed && alert.severity !== 'info');
  const back = useRef<{ desk: string; pane: string } | null>(null);

  const jumpNext = useCallback(() => {
    const next = needsYou.find((entry) => !(entry.desk.id === desk?.id && entry.pane.id === desk?.focus));
    if (!next) {
      if (back.current) {
        const target = back.current;
        back.current = null;
        setDoc((current) => ({ ...current, current: target.desk, desks: current.desks.map((entry) => (entry.id === target.desk ? { ...entry, focus: target.pane } : entry)) }));
      } else host.notify('Nothing needs you.');
      return;
    }
    if (desk?.focus) back.current = { desk: desk.id, pane: desk.focus };
    setDoc((current) => ({
      ...current,
      current: next.desk.id,
      desks: current.desks.map((entry) => (entry.id === next.desk.id ? { ...entry, stage: entry.stage.includes(next.pane.id) ? entry.stage : [...entry.stage, next.pane.id].slice(-STAGE_MAX), focus: next.pane.id } : entry)),
    }));
  }, [needsYou, desk, setDoc, host]);

  const openAlertsPane = useCallback(() => openTool('alerts', 'alerts'), [openTool]);

  const newDesk = useCallback(async () => {
    if (!projectId) return;
    const name = `desk ${doc.desks.length + 1}`;
    const created = await createDesk(projectId, focusedCwd() || home, name).catch(() => null);
    if (created) setDoc((current) => ({ desks: [...current.desks, created], current: created.id }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, doc.desks.length, home, setDoc]);

  const closeDesk = useCallback((deskId: string) => {
    const target = doc.desks.find((entry) => entry.id === deskId);
    if (!target || doc.desks.length < 2) return;
    for (const pane of target.panes) if (pane.termId) void clientOf(pane.node).call('terminal.close', { term_id: pane.termId }).catch(() => undefined);
    setDoc((current) => {
      const desks = current.desks.filter((entry) => entry.id !== deskId);
      return { desks, current: current.current === deskId ? desks[0]?.id ?? '' : current.current };
    });
  }, [doc.desks, setDoc]);

  // --- keys ------------------------------------------------------------------------------------
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const meta = event.metaKey || event.ctrlKey;
      if (event.key === 'Escape' && overlay) { event.preventDefault(); setOverlay(null); return; }
      if (!meta) return;
      const key = event.key.toLowerCase();
      if (key === 'j') { event.preventDefault(); jumpNext(); }
      else if (key === 'm' && !event.altKey) { event.preventDefault(); setOverlay((open) => (open === 'map' ? null : 'map')); }
      else if (key === ';') { event.preventDefault(); setOverlay('jump'); }
      else if (key === 't') { event.preventDefault(); void openTerm(); }
      else if (key === 'w' && focused) { event.preventDefault(); closePane(focused.id); }
      else if (key === '.' && focused) { event.preventDefault(); toShelf(focused.id); }
      else if (key === 'l') { event.preventDefault(); line.current?.focus(); }
      else if (key === ',') { event.preventDefault(); setSettings((open) => (open === null ? '' : null)); }
      else if (key === 'b') { event.preventDefault(); columns.toggleNav(); }
      else if (key === 'k' && event.shiftKey) { event.preventDefault(); columns.toggleSide(); }
      else if (key === 'n' && event.shiftKey) { event.preventDefault(); void newDesk(); }
      else if (/^[1-9]$/.test(key) && desk?.panes[Number(key) - 1]) {
        event.preventDefault();
        promote(desk.panes[Number(key) - 1]!.id);
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [desk, overlay, focused, jumpNext, openTerm, closePane, toShelf, promote, newDesk, columns, setSettings]);

  const bandTarget = document.getElementById('ct-band');
  if (problem) return <div className="ct-desk"><p className="ct-hint ct-warn ct-boot">{problem}</p></div>;
  if (!desk) return <div className="ct-desk"><p className="ct-hint ct-boot">Starting your shells…</p></div>;

  const stagePanes = desk.stage.map((id) => desk.panes.find((pane) => pane.id === id)).filter(Boolean) as PaneRec[];
  const fullscreen = focusedTerm?.termId ? live.states.get(focusedTerm.termId)?.alternate_screen : false;
  const sideFrame = (kind: PaneRec['kind'], runId?: string) => ({
    pane: { id: `side-${kind}`, kind, title: kind, cwd: home, runId },
    focused: false, bare: true, onFocus: () => undefined, onShelf: () => undefined, onClose: () => setSideView('machine'),
  });

  const renderPane = (pane: PaneRec, slot: number) => <ComputerScope node={pane.node ?? null}>{paneView(pane, slot)}</ComputerScope>;
  const paneView = (pane: PaneRec, slot: number) => {
    const isFocused = pane.id === (focused?.id ?? '');
    const common = { focused: isFocused, onFocus: () => focusPane(pane.id), onShelf: () => toShelf(pane.id), onClose: () => closePane(pane.id) };
    switch (pane.kind) {
      case 'term': return <TermPane pane={pane} sessionId={pane.node ? desk.sessions?.[pane.node] : desk.sessionId} computer={nameOf(pane.node)} home={home} slot={slot} actions={actions} {...common} />;
      case 'editor': return <EditorPane pane={pane} home={home} onAsk={onAsk} onRunReal={(command) => void onShell(command, 'pane')} {...common} />;
      case 'run': return <RunPane pane={pane} home={home} onAsk={onAsk} {...common} />;
      case 'process': return <ProcessPane pane={pane} onAsk={onAsk} onSignal={onSignal} onInvestigate={onInvestigate} {...common} />;
      case 'alerts': return <AlertsPane pane={pane} onAsk={onAsk} onRunCommand={(command) => line.current?.set(command)} {...common} />;
      case 'ssh': return <SshPane pane={pane} onShell={(command) => void onShell(command, 'pane')} onAsk={(text, intent) => void onAsk(text, intent)} {...common} />;
      case 'schedules': return <SchedulesPane pane={pane} home={home} {...common} />;
    }
  };

  // The band only says what is going on; everything you can do has a key (and a View menu entry).
  const band = (
    <>
      <span className="grow" />
      {needsYou.length > 0 && <button type="button" className="ct-band-note warn" onClick={jumpNext} title="Next that needs you (⌘J)">{needsYou.length} NEED YOU</button>}
      {openAlerts.length > 0 && <button type="button" className="ct-band-note warn" onClick={openAlertsPane}>{openAlerts.length} ALERT{openAlerts.length > 1 ? 'S' : ''}</button>}
      <span className={`ct-band-note${model?.extra?.source === 'borrowed' ? ' blue' : ''}`} title={modelProblem ?? ''}>{modelLabel(model, modelProblem)}</span>
      <button type="button" className="ct-band-note ct-band-gear" onClick={() => setSettings((open) => (open === null ? '' : null))} title="Settings (⌘,)" aria-label="Settings">
        <svg viewBox="0 0 16 16" width="13" height="13" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.3">
          <circle cx="8" cy="8" r="2.2" />
          <path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4" strokeLinecap="round" />
        </svg>
      </button>
    </>
  );

  return (
    <div className="ct-desk">
      {bandTarget && createPortal(band, bandTarget)}
      <div ref={columns.work} className="ct-work" style={columns.style}>
        <nav className="ct-nav cx-sidebar" aria-label="Desks" hidden={!columns.navOpen}>
          <div className="bar cx-sidebar-actions">
            <button type="button" className="detent" onClick={() => void newDesk()}>NEW DESK</button>
            <button type="button" className="detent" onClick={() => void openTerm()}>NEW SHELL <span className="k">⌘T</span></button>
          </div>
          <div className="cx-sidebar-scroll">
            {doc.desks.map((entry) => {
              const on = entry.id === desk.id;
              const running = entry.panes.filter((pane) => live.attention(pane) === 'running').length;
              return (
                <section key={entry.id} className={`cx-proj${on ? ' on' : ''}`}>
                  <div className="cx-proj-h">
                    <button type="button" className="cx-proj-toggle cx-proj-open" aria-pressed={on} onClick={() => setDoc((current) => ({ ...current, current: entry.id }))}>
                      <Caret dir={on ? 'down' : 'right'} className="cx-caret" />
                      <span className="cx-proj-name">{entry.name}</span>
                    </button>
                    <span className="grow" />
                    {running > 0 && <span className="cx-run-badge" title={`${running} running`}>{running}</span>}
                    {doc.desks.length > 1 && <CloseButton label={`Close Desk ${entry.name}`} title={`Close ${entry.name}?`} body="Its shells end and whatever runs in them stops; their commands stay in the history." action="Close Desk" onConfirm={() => closeDesk(entry.id)} />}
                  </div>
                  {on && (
                    <ul className="lst cx-sessions" aria-label={`Shells in ${entry.name}`}>
                      {entry.panes.map((pane) => {
                        const attention = live.attention(pane);
                        const [status, label, tone] = ROW_STATE[attention];
                        const selected = entry.stage.includes(pane.id);
                        return (
                          <li key={pane.id} className={['cx-row', selected ? 'sel' : '', NEEDS_YOU.has(attention) ? 'cx-attn' : ''].filter(Boolean).join(' ')}>
                            <button type="button" onClick={() => promote(pane.id)} aria-current={selected ? 'true' : undefined}>
                              <div className="t">{pane.node && <span className="ct-blue">{nameOf(pane.node)} </span>}{paneTitle(pane, home)}</div>
                              <div className="r">
                                <span className={`cx-pip cx-pip-${status}`} aria-hidden />
                                <span className={`ap ${tone}`}>{label}</span>
                                <span className="grow" />
                                <span className="ap faint">{paneWhen(pane)}</span>
                              </div>
                            </button>
                            <CloseButton label="Close this shell" title="Close this shell?"
                              body={live.states.get(pane.termId ?? '')?.running ? `“${paneTitle(pane, home)}” is still running: closing the shell stops it.` : 'The shell ends; its commands stay in the history.'}
                              action="Close shell" onConfirm={() => closePane(pane.id)} />
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </section>
              );
            })}
            {computers.length > 0 && (
              <section className="cx-proj">
                <div className="cx-proj-h"><span className="cx-proj-name ct-faint">COMPUTERS</span></div>
                {computers.map((computer) => (
                  <ComputerScope key={computer.node} node={computer.node}>
                    <ComputerShells computer={computer} home={home} shown={desk.panes} onOpen={(info) => attachTerm(computer.node, info)} onNew={() => void openTerm(undefined, 'stage', 'shell', computer.node).catch((cause) => host.notify(`No shell on ${computer.name}: ${errorMessage(cause)}`))} />
                  </ComputerScope>
                ))}
              </section>
            )}
            {places.length > 0 && (
              <section className="cx-proj">
                <div className="cx-proj-h"><span className="cx-proj-name ct-faint">PLACES I KNOW</span></div>
                <ul className="lst cx-sessions" aria-label="Places">
                  {places.map((place) => (
                    <li key={place.path} className="cx-row">
                      <button type="button" onClick={() => void openTerm(place.path)} title="Open a shell there">
                        <div className="t ct-mono ct-place-t">{shortPath(place.path, home)}</div>
                        <div className="r">
                          <span className="ap faint">{place.runs} COMMANDS{place.git ? ' · GIT' : ''}</span>
                          <span className="grow" />
                          <span className="ap faint">{place.last ? ago(place.last) : ''}</span>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        </nav>
        <Divider name="ct-nav" label="Desks width" onMove={columns.moveNav} onEnd={columns.endNav} onReset={columns.resetNav} className={columns.navOpen ? '' : 'ct-hidden'} />
        <main className="ct-main">
          <div className="ct-stage">
            {stagePanes.length === 0 && (
              <div className="ct-stage-empty">
                <p className="ct-reading ct-faint">{desk.panes.length ? 'Pick a view above, or' : 'No shell open.'}</p>
                <button type="button" className="detent" onClick={() => void openTerm()}>NEW SHELL <span className="k">⌘T</span></button>
              </div>
            )}
            {stagePanes.map((pane, index) => <div key={pane.id} className="ct-cell">{renderPane(pane, index)}</div>)}
          </div>
          <ComputerScope node={focusedTerm?.node ?? null}>
            <Line ref={line} termId={focusedTerm?.termId} home={home} onShell={(command, how) => void onShell(command, how)} onAsk={(text, intent) => void onAsk(text, intent)} onNative={onNative}
              disabled={fullscreen ? 'A full-screen program has the keyboard: click into it, or quit it to use the Line.' : null} />
          </ComputerScope>
        </main>
        <Divider name="ct-side" label="Machine width" onMove={columns.moveSide} onEnd={columns.endSide} onReset={columns.resetSide} className={columns.sideOpen ? '' : 'ct-hidden'} />
        {columns.sideOpen ? (
          <aside className="ct-side" aria-label="Side">
            <div className="ct-side-tabs" role="tablist">
              {([['machine', 'MACHINE'], ['alerts', openAlerts.length ? `ALERTS · ${openAlerts.length}` : 'ALERTS'], ['traces', 'TRACES'], ['ssh', 'SSH'], ['schedules', 'SCHEDULES'], ...(sideRun ? [['log', 'LOG']] : []), ...(sidePid ? [['investigate', `PID ${sidePid}`]] : [])] as [SideView, string][]).map(([view, label]) => (
                <button key={view} type="button" role="tab" aria-selected={sideView === view} className={`ct-side-tab${sideView === view ? ' on' : ''}${view === 'alerts' && openAlerts.length ? ' hot' : ''}`} onClick={() => setSideView(view)}>{label}</button>
              ))}
            </div>
            {/* Alerts are this Mac's; everything else in the side pane is the focused pane's computer's. */}
            {sideView === 'alerts' && <AlertsPane {...sideFrame('alerts')} onAsk={onAsk} onRunCommand={(command) => line.current?.set(command)} />}
            <ComputerScope node={sideNode ?? null}>
            {sideView === 'machine' && <Sidebar computer={nameOf(sideNode)} onAsk={(text, intent) => void onAsk(text, intent)} onSignal={onSignal} onInvestigate={onInvestigate} />}
            {sideView === 'traces' && <Traces open={sideTrace} home={home} onOpen={setSideTrace} onAsk={(text, intent, runId) => void onAsk(text, intent, runId)}
              onOpenRun={(runId) => { setSideRun(runId); setSideView('log'); }} />}
            {sideView === 'ssh' && <SshPane {...sideFrame('ssh')} onShell={(command) => void onShell(command, 'pane')} onAsk={(text, intent) => void onAsk(text, intent)} />}
            {sideView === 'schedules' && <SchedulesPane {...sideFrame('schedules')} home={home} />}
            {sideView === 'investigate' && sidePid > 0 && <Investigate pid={sidePid} home={home} onAsk={(text, intent, runId) => void onAsk(text, intent, runId)} onSignal={onSignal}
              onShell={(command) => void onShell(command, 'pane')} onInvestigate={onInvestigate} onOpenTrace={onOpenTrace}
              onOpenFile={(path) => addPane({ id: newId('pane'), kind: 'editor', title: path.split('/').pop() || path, cwd: home, path, ...(sideNode ? { node: sideNode } : {}) })}
              onOpenRun={(runId) => { setSideRun(runId); setSideView('log'); }}
              onClose={() => { setSidePid(0); setSideView('machine'); }} />}
            {sideView === 'log' && sideRun && <RunPane {...sideFrame('run', sideRun)} named home={home} onAsk={onAsk} onRun={(command) => void onShell(command, 'pane')} onClose={() => { setSideRun(''); setSideView('machine'); }} />}
            </ComputerScope>
          </aside>
        ) : <div />}
      </div>
      {settings !== null && <host.Slot name="settings.host@1" className="cx-settings-layer" props={{ onClose: () => setSettings(null) }} />}
      {overlay && (
        <MapView desks={doc.desks} current={desk.id} home={home} jump={overlay === 'jump'} onClose={() => setOverlay(null)}
          onOpen={(deskId, paneId) => {
            setDoc((current) => ({ ...current, current: deskId, desks: current.desks.map((entry) => (entry.id === deskId ? { ...entry, stage: entry.stage.includes(paneId) ? entry.stage : [...entry.stage, paneId].slice(-STAGE_MAX), focus: paneId } : entry)) }));
            setOverlay(null);
          }} />
      )}
    </div>
  );
}

/** CortexCode's sidebar delete: an × beside the row (shown on hover), asking in the theme's dialog. */
function CloseButton({ label, title, body, action, onConfirm }: { label: string; title: string; body: string; action: string; onConfirm: () => void }) {
  const [asking, setAsking] = useState(false);
  const confirmButton = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (asking) confirmButton.current?.focus(); }, [asking]);
  return (
    <>
      <button type="button" className="cx-del" aria-label={label} title={label} onClick={(event) => { event.stopPropagation(); setAsking(true); }}>×</button>
      {asking && createPortal(
        <div className="modal-backdrop" role="presentation" onClick={(event) => event.target === event.currentTarget && setAsking(false)}
          onKeyDown={(event) => event.key === 'Escape' && setAsking(false)}>
          <div className="modal-card cx-confirm" role="alertdialog" aria-modal="true" aria-label={title}>
            <h2 className="cx-confirm-title">{title}</h2>
            <p className="cx-confirm-body">{body}</p>
            <div className="modal-actions cx-confirm-actions">
              <button type="button" className="detent" onClick={() => setAsking(false)}>Cancel</button>
              <button type="button" className="detent warn" ref={confirmButton} onClick={() => { setAsking(false); onConfirm(); }}>{action}</button>
            </div>
          </div>
        </div>,
        document.getElementById('cc') ?? document.body,
      )}
    </>
  );
}

/** A joined computer in the nav: its name in blue, the shells open there (`terminal.list` on its
 * frame) and a new shell there; greyed while it is away. */
function ComputerShells({ computer, home, shown, onOpen, onNew }: { computer: Computer; home: string; shown: PaneRec[]; onOpen: (info: TermInfo) => void; onNew: () => void }) {
  useLive();
  const { client } = useRuntime();
  const [shells, setShells] = useState<TermInfo[]>([]);
  useEffect(() => {
    if (!computer.reachable) return;
    let stopped = false;
    const read = () => client.call<{ terminals: TermInfo[] }>('terminal.list', {})
      .then((list) => {
        if (stopped) return;
        const alive = (list?.terminals ?? []).filter((term) => term.alive);
        for (const term of alive) live.ensure(term.term_id, computer.node);
        setShells(alive);
      })
      .catch(() => undefined);
    void read();
    const timer = setInterval(read, 5000);
    return () => { stopped = true; clearInterval(timer); };
  }, [client, computer.reachable, computer.node]);
  return (
    <div className="ct-computer">
      <div className="cx-proj-h">
        <span className={`cx-proj-name ${computer.reachable ? 'ct-blue' : 'ct-faint'}`}>{computer.name}</span>
        <span className="grow" />
        <span className="ap faint">{computer.reachable ? (computer.path || 'mesh').toUpperCase() : 'AWAY'}</span>
      </div>
      {computer.reachable && (
        <>
          <ul className="lst cx-sessions" aria-label={`Shells on ${computer.name}`}>
            {shells.map((term) => {
              const pane: PaneRec = { id: term.term_id, kind: 'term', title: 'shell', cwd: term.cwd, termId: term.term_id, node: computer.node };
              const attention = live.attention(pane);
              const [status, label, tone] = ROW_STATE[attention];
              const here = shown.some((entry) => entry.termId === term.term_id);
              return (
                <li key={term.term_id} className={['cx-row', here ? 'sel' : '', NEEDS_YOU.has(attention) ? 'cx-attn' : ''].filter(Boolean).join(' ')}>
                  <button type="button" onClick={() => onOpen(term)} title={here ? 'Show it' : 'Open it here'}>
                    <div className="t ct-mono ct-place-t">{shortPath(live.states.get(term.term_id)?.cwd || term.cwd, home)}</div>
                    <div className="r">
                      <span className={`cx-pip cx-pip-${status}`} aria-hidden />
                      <span className={`ap ${tone}`}>{live.states.get(term.term_id)?.running ? `${label} · ${live.states.get(term.term_id)!.running!.command.split(/\s+/)[0]!.toUpperCase()}` : label}</span>
                      <span className="grow" />
                      <span className="ap faint">{paneWhen(pane)}</span>
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
          <button type="button" className="detent sm ct-computer-new" onClick={onNew}>NEW SHELL THERE</button>
        </>
      )}
    </div>
  );
}

function paneDetail(pane: PaneRec, home: string): string {
  if (pane.kind !== 'term' || !pane.termId) return pane.kind === 'editor' ? `edit ${pane.path ?? ''}` : pane.kind;
  const state: TermState | undefined = live.states.get(pane.termId);
  if (state?.running) return state.running.command;
  const run = live.lastRun.get(pane.termId);
  if (run) return `${run.exit_code === 0 ? '✓' : '✗'} ${run.command}`;
  return shortPath(state?.cwd || pane.cwd, home);
}

/** A row's pip status, label and tone, as the CortexCode sidebar shows a session's. */
const ROW_STATE: Record<Attention, [string, string, string]> = {
  input: ['waiting', 'WAITING FOR INPUT', 'live'], failed: ['failed', 'FAILED', 'live'], proposal: ['waiting', 'ANSWER READY', 'live'],
  bell: ['waiting', 'BELL', 'live'], alert: ['waiting', 'ALERT', 'live'], running: ['running', 'RUNNING', 'origin'], idle: ['idle', 'IDLE', 'faint'], ended: ['done', 'ENDED', 'faint'],
};

/** What a shell is doing, as its row's title: the command running, else the last one, else its folder. */
function paneTitle(pane: PaneRec, home: string): string {
  if (pane.kind !== 'term' || !pane.termId) return pane.title;
  const state = live.states.get(pane.termId);
  if (state?.running) return state.running.command;
  const run = live.lastRun.get(pane.termId);
  return run?.command || shortPath(state?.cwd || pane.cwd, home);
}

function paneWhen(pane: PaneRec): string {
  if (!pane.termId) return '';
  const state = live.states.get(pane.termId);
  if (state?.running) return ago(state.running.started);
  const run = live.lastRun.get(pane.termId);
  return run ? ago(run.ended ?? run.started) : '';
}

const ATTENTION_LABEL: Record<Attention, string> = {
  input: 'WAITING FOR INPUT', failed: 'FAILED', proposal: 'ANSWER READY', bell: 'BELL', alert: 'ALERT', running: 'RUNNING', idle: 'QUIET', ended: 'ENDED',
};

function MapView({ desks, current, home, jump, onOpen, onClose }: {
  desks: DeskRec[]; current: string; home: string; jump: boolean; onOpen: (desk: string, pane: string) => void; onClose: () => void;
}) {
  const [query, setQuery] = useState('');
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const timer = setTimeout(() => input.current?.focus(), 30);
    return () => clearTimeout(timer);
  }, []);
  const words = query.toLowerCase().split(/\s+/).filter((word) => word.length > 1 && !['the', 'one', 'that', 'is', 'a', 'with'].includes(word));
  const score = (pane: PaneRec) => {
    if (!words.length) return 0;
    const hay = `${pane.title} ${pane.kind} ${paneDetail(pane, home)} ${pane.cwd} ${pane.path ?? ''} ${live.attention(pane)}`.toLowerCase();
    return words.reduce((sum, word) => sum + (hay.includes(word) ? 2 : 0), 0);
  };
  const ranked = desks.flatMap((desk) => desk.panes.map((pane) => ({ desk, pane, score: score(pane) }))).filter((entry) => entry.score > 0).sort((a, b) => b.score - a.score);
  const best = ranked[0];
  return (
    <div className="ct-map" role="dialog" aria-modal="true" aria-label="Map of every Desk">
      <div className="ct-map-bar">
        <span className="ct-serif-title">{jump ? 'Jump' : 'Map'}</span>
        <label className="ct-map-jump">
          <span className="ct-label ct-faint">JUMP TO</span>
          <input ref={input} autoFocus type="text" value={query} placeholder="a name, command, folder… or plain words" onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === 'Enter' && best) onOpen(best.desk.id, best.pane.id); }} />
        </label>
        <span className="grow" />
        <button type="button" className="detent" onClick={onClose}>BACK <span className="k">ESC</span></button>
      </div>
      <div className="ct-map-field">
        {desks.map((desk) => {
          const urgent = desk.panes.filter((pane) => NEEDS_YOU.has(live.attention(pane))).length;
          return (
            <section key={desk.id} className={`ct-map-desk${urgent ? ' urgent' : ''}${desk.id === current ? ' current' : ''}`}>
              <div className="ct-map-desk-head">
                <span className="ct-serif-title">{desk.name}</span>
                <span className={`ct-label ${urgent ? 'ct-lift' : 'ct-faint'}`}>{urgent ? `${urgent} NEED YOU` : 'ALL QUIET'}</span>
              </div>
              <div className="ct-map-grid">
                {desk.panes.map((pane) => {
                  const attention = live.attention(pane);
                  const isBest = best && best.pane.id === pane.id;
                  return (
                    <button key={pane.id} type="button" className={`ct-map-card${NEEDS_YOU.has(attention) ? ' urgent' : ''}${isBest ? ' best' : ''}`} onClick={() => onOpen(desk.id, pane.id)}>
                      <span className="ct-card-head"><span className={`ct-dot ${attention}`} aria-hidden /><span className="ct-label">{pane.title}</span></span>
                      <span className="ct-mono ct-card-detail">{paneDetail(pane, home)}</span>
                      <span className={`ct-label ${isBest ? 'ct-lift' : 'ct-faint'}`}>{isBest ? 'BEST MATCH ↵' : ATTENTION_LABEL[attention]}</span>
                    </button>
                  );
                })}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
