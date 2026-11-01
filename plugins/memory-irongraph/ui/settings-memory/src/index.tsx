/**
 * settings.memory@1 — what CortexTerm remembers (global memory, `memory.knowledge.list`, history
 * included): the lessons the terminal flow learned (`by` chatflow-terminal) with why each is kept
 * and how it fared (`seen`/`helped`/`hurt`), the folders' habits (`place <path>: …` facts), and
 * what was set aside. Why opens the episodes a lesson came from (`LEARNED_FROM`, graph read) and
 * its held-out replays; Forget withdraws it as the user's, so the learner does not learn it again.
 */

import { useState } from 'react';
import { ServiceProblem, clock, definePlugin, errorMessage, useClient, useHost, useQuery } from '@cortex/sdk';
import './memory.css';

interface KnowledgeLink { rel: string; target: string }
interface KnowledgeItem {
  id: string; kind: string; name: string; text: string; state: string; by?: string;
  aliases?: string[]; links?: KnowledgeLink[]; superseded_by?: string | null; reason?: string | null;
  seen?: number; helped?: number; hurt?: number; created_ms: number; updated_ms: number;
}
interface Rows { rows: unknown[][] }

type Tab = 'learned' | 'places' | 'aside';
const LIVE = (state: string) => state !== 'withdrawn' && state !== 'superseded';
const WHY: Record<string, string> = { fix: 'A fix that worked', check: 'A check that worked', correction: 'You corrected it', preference: 'You said it' };
const KIND: Record<string, string> = { fix: 'Fix', check: 'Check', correction: 'Correction', preference: 'Preference' };

/** `<anchor> [<scope>]: <text>`, the learner's lesson name. */
function parts(name: string): { anchor: string; scope: string } {
  const found = /^(\S+) \[([^\]]*)\]: /.exec(name);
  return { anchor: found?.[1] ?? '', scope: found?.[2] ?? '' };
}

function tilde(path: string, home: string): string {
  return home && (path === home || path.startsWith(`${home}/`)) ? `~${path.slice(home.length)}` : path;
}

/** Where a lesson holds: its folder, or this Mac for a platform rule. */
function where(scope: string, home: string): string {
  return scope.startsWith('folder:') ? tilde(scope.slice('folder:'.length), home) : 'this Mac';
}

const text = (row: unknown[], index: number) => (typeof row[index] === 'string' ? (row[index] as string) : '');
const num = (row: unknown[], index: number) => (typeof row[index] === 'number' ? (row[index] as number) : null);

function MemorySection() {
  const client = useClient();
  const host = useHost();
  const [tab, setTab] = useState<Tab>('learned');
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const items = useQuery<KnowledgeItem[]>('settings.memory:items', async (c) => {
    const [lessons, facts] = await Promise.all([
      c.call<{ items: KnowledgeItem[] }>('memory.knowledge.list', { kind: 'lesson', include_history: true }),
      c.call<{ items: KnowledgeItem[] }>('memory.knowledge.list', { kind: 'fact' }),
    ]);
    return [...(lessons?.items ?? []), ...(facts?.items ?? [])];
  }, { topics: ['memory.knowledge.changed'] });
  // Why each lesson is kept: the first episode it was learned from. Lessons from before the edge
  // carried it were all fixes, checks or corrections.
  const why = useQuery<Record<string, string>>('settings.memory:why', async (c) => {
    const found = await c.call<Rows>('memory.graph.query', {
      cypher: 'MATCH (k:Knowledge)-[r:LEARNED_FROM]->(e:TerminalEpisode) RETURN k.id, r.why, e.verified_fix, e.check_repair ORDER BY e.created_ms LIMIT 5000',
      limit: 5000,
    });
    const out: Record<string, string> = {};
    for (const row of found?.rows ?? []) {
      const id = text(row, 0);
      if (!id || out[id]) continue;
      out[id] = text(row, 1) || (row[2] === true ? 'fix' : row[3] === true ? 'check' : 'correction');
    }
    return out;
  }, { topics: ['memory.knowledge.changed'] });
  const home = useQuery<string>('settings.memory:home', async (c) => (await c.call<{ projects: { root: string }[] }>('frame.project.list', {}))?.projects?.[0]?.root ?? '');
  const forget = async (item: KnowledgeItem) => {
    setBusy(item.id);
    try {
      await client.call('memory.knowledge.withdraw', { id: item.id, reason: 'Forgotten in Settings', by: 'user' });
      await items.refresh();
      host.notify('Forgotten');
    } catch (cause) {
      host.notify(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  };
  const all = items.data ?? [];
  const at = home.data ?? '';
  const learned = all.filter((item) => item.kind === 'lesson');
  const live = learned.filter((item) => LIVE(item.state)).sort((a, b) => b.updated_ms - a.updated_ms);
  const aside = learned.filter((item) => !LIVE(item.state)).sort((a, b) => b.updated_ms - a.updated_ms);
  const places = all.filter((item) => item.kind === 'fact' && item.name.startsWith('place ') && LIVE(item.state));
  return (
    <section className="cx-memory" data-build={__CORTEX_BUILD__}>
      <h2 className="cx-settings-title">What CortexTerm remembers</h2>
      <p className="cx-settings-line">Learned from your corrections, from fixes that worked and from what you asked it to keep. The model reads these as notes; what runs is still yours and the risk engine's.</p>
      {items.error && <ServiceProblem service="memory" state={items} className="inline-error" />}
      <div className="cx-memory-tabs" role="group" aria-label="What to show">
        <button type="button" className={`ct-seg${tab === 'learned' ? ' on' : ''}`} aria-pressed={tab === 'learned'} onClick={() => setTab('learned')}>Learned · {live.length}</button>
        <button type="button" className={`ct-seg${tab === 'places' ? ' on' : ''}`} aria-pressed={tab === 'places'} onClick={() => setTab('places')}>Places · {places.length}</button>
        <button type="button" className={`ct-seg${tab === 'aside' ? ' on' : ''}`} aria-pressed={tab === 'aside'} onClick={() => setTab('aside')}>Set aside · {aside.length}</button>
        <span className="grow" />
        {tab !== 'places' && <span className="ap faint">helped · hurt · shown</span>}
      </div>
      {!items.data && !items.error && <p className="cx-settings-line">…</p>}
      {items.data && tab === 'learned' && (live.length === 0
        ? <p className="cx-settings-line">Nothing learned yet. Correct an answer, run a fix that works, or say how you like things done.</p>
        : <ul className="cx-memory-list" aria-label="Learned">
          {live.map((item) => <Lesson key={item.id} item={item} why={why.data?.[item.id]} home={at} open={open === item.id} onOpen={() => setOpen(open === item.id ? null : item.id)} busy={busy !== null} onForget={() => void forget(item)} />)}
        </ul>)}
      {items.data && tab === 'places' && (places.length === 0
        ? <p className="cx-settings-line">No folder habits yet: a command run three times in a folder becomes one.</p>
        : <ul className="cx-memory-list" aria-label="Places">
          {places.map((item) => (
            <li key={item.id} className="cx-memory-item">
              <div className="cx-memory-head"><span className="ap">{tilde(item.name.slice('place '.length).split(': ')[0] ?? '', at)}</span><span className="ap faint">from your runs · {clock(item.updated_ms)}</span></div>
              <p className="cx-memory-text">{item.text}</p>
            </li>
          ))}
        </ul>)}
      {items.data && tab === 'aside' && (aside.length === 0
        ? <p className="cx-settings-line">Nothing set aside.</p>
        : <ul className="cx-memory-list" aria-label="Set aside">
          {aside.map((item) => (
            <li key={item.id} className="cx-memory-item" data-state={item.state}>
              <div className="cx-memory-head"><span className="ap faint">{where(parts(item.name).scope, at)} · {clock(item.updated_ms)}</span></div>
              <p className="cx-memory-text faint">{item.text}</p>
              <span className="ap faint">{item.superseded_by ? 'replaced after you corrected it' : item.by === 'user' ? 'you forgot it' : item.reason ?? item.state}</span>
            </li>
          ))}
        </ul>)}
      <p className="cx-memory-note">A lesson more harmful than helpful over three runs is set aside by itself.</p>
    </section>
  );
}

function Lesson({ item, why, home, open, onOpen, busy, onForget }: {
  item: KnowledgeItem; why?: string; home: string; open: boolean; onOpen: () => void; busy: boolean; onForget: () => void;
}) {
  const { anchor, scope } = parts(item.name);
  const reason = why ?? (anchor === 'preference' ? 'preference' : '');
  const program = anchor.startsWith('command:') ? anchor.slice('command:'.length) : '';
  const kind = KIND[reason] ?? (anchor === 'approach' ? 'Approach' : 'Lesson');
  const replaced = (item.links ?? []).filter((link) => link.rel === 'supersedes').length;
  const meta = [where(scope, home), WHY[reason], clock(item.created_ms), replaced > 0 ? `replaced ${replaced}` : ''].filter(Boolean).join(' · ');
  const harm = (item.hurt ?? 0) > (item.helped ?? 0);
  return (
    <li className={`cx-memory-item${open ? ' open' : ''}`} data-id={item.id}>
      <div className="cx-memory-row">
        <div className="grow">
          <div className="cx-memory-head"><span className={`ap cx-memory-kind${reason === 'preference' ? ' pref' : ''}`}>{program ? `${kind} · ${program}` : kind}</span><span className="ap faint">{meta}</span></div>
          <p className="cx-memory-text">{item.text}</p>
        </div>
        <span className={`cx-memory-score${harm ? ' hot' : ''}`} title="helped · hurt · shown">{item.helped ?? 0} · {item.hurt ?? 0} · {item.seen ?? 0}</span>
        <button type="button" className="detent tiny" aria-expanded={open} onClick={onOpen}>Why</button>
        <button type="button" className="detent tiny" disabled={busy} aria-label={`Forget: ${item.text}`} onClick={onForget}>Forget</button>
      </div>
      {open && <Why id={item.id} home={home} />}
    </li>
  );
}

/** The episodes a lesson was learned from, and how it did on held-out ones. */
function Why({ id, home }: { id: string; home: string }) {
  const found = useQuery<{ episodes: unknown[][]; replays: unknown[][] }>(`settings.memory:why:${id}`, async (c) => {
    const [episodes, replays] = await Promise.all([
      c.call<Rows>('memory.graph.query', {
        cypher: 'MATCH (k:Knowledge {id: $id})-[r:LEARNED_FROM]->(e:TerminalEpisode) RETURN r.why, e.created_ms, e.cwd, e.failure, e.outcome_command, e.outcome_exit, e.rerun_ok, e.correction, e.question ORDER BY e.created_ms DESC LIMIT 3',
        params: { id },
        limit: 3,
      }),
      c.call<Rows>('memory.graph.query', {
        cypher: 'MATCH (r:TerminalReplay)-[:FOR]->(k:Knowledge {id: $id}) RETURN r.state, r.verdict, r.oracle LIMIT 200',
        params: { id },
        limit: 200,
      }),
    ]);
    return { episodes: episodes?.rows ?? [], replays: replays?.rows ?? [] };
  });
  if (found.error) return <p className="inline-error">Not available: {found.error}</p>;
  if (!found.data) return <p className="cx-settings-line">…</p>;
  // Only held-out replays count; the earlier ones graded a lesson on its own episode.
  const held = found.data.replays.filter((row) => text(row, 0) === 'done' && text(row, 2).includes('held-out'));
  const helped = held.filter((row) => text(row, 1) === 'helped').length;
  const hurt = held.filter((row) => text(row, 1) === 'hurt').length;
  return (
    <div className="cx-memory-why">
      <span className="ap faint">why it is kept</span>
      {found.data.episodes.map((row, index) => {
        const exit = num(row, 5);
        const quote = text(row, 0) === 'preference' ? text(row, 8) : text(row, 0) === 'correction' ? text(row, 7) : '';
        return (
          <div key={index} className="cx-memory-episode">
            <div className="cx-path">{tilde(text(row, 2), home) || 'no folder'} · {clock(num(row, 1) ?? 0)}</div>
            {text(row, 3) && <div className="cx-path"><span className="hot">✕</span> {text(row, 3).replace(/^failed /, '')}</div>}
            {text(row, 4) && <div className="cx-path"><span className={exit === 0 ? 'ok' : 'hot'}>{exit === 0 ? '✓' : '✕'}</span> {text(row, 4)} <span className="faint">(you ran it)</span></div>}
            {row[6] === true && <div className="cx-path"><span className="ok">✓</span> <span className="faint">the failing command passed on its next run</span></div>}
            {quote && <p className="cx-memory-quote">You said: “{quote.length > 240 ? `${quote.slice(0, 240)}…` : quote}”</p>}
          </div>
        );
      })}
      {held.length > 0 && <p className="cx-memory-quote">Tried on {held.length} earlier {held.length === 1 ? 'run' : 'runs'} it was not learned from: it helped {helped}, hurt {hurt}.</p>}
    </div>
  );
}

export default definePlugin({ slot: 'settings.memory@1', component: MemorySection });
