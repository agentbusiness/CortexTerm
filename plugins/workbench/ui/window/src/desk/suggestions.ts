/** Inline predictions use the focused shell and its conversation, never another app's memory.
 * Only append to what was typed. Accepting a prediction still goes through the normal submit path.
 */
import type { JournalEntry } from '@cortex/sdk';
import type { Completions, Run } from './api';

type Candidate = { text: string; score: number; at: number };
type Mode = 'shell' | 'ask' | 'unsure';

const singleLine = (text: string) => text.length <= 2048 && !/[\u0000-\u001f\u007f]/.test(text);
const words = (text: string) => new Set(text.toLowerCase().match(/[\p{L}\p{N}_./-]{3,}/gu) ?? []);

/** Marker and spacing belong to the user's input; shell command text remains case sensitive. */
export function inputText(value: string): { marker: string; text: string } {
  const marker = value.match(/^[?!]\s*/)?.[0] ?? '';
  return { marker, text: value.slice(marker.length) };
}

export function contextualSuggestion(value: string, mode: Mode, entries: readonly JournalEntry[], termId: string | undefined, runs: Run[], cwd: string): string | null {
  if (!singleLine(value)) return null;
  const { marker, text } = inputText(value);
  if (text.trim().length < (mode === 'shell' ? 2 : 3) || !singleLine(text)) return null;
  const candidates: Candidate[] = [];
  const recent = entries.slice(-600);
  const turns = recent.filter((entry) => entry.kind === 'user_message' && (entry.data.term_id ?? undefined) === termId).slice(-100);
  const latest = turns.at(-1);
  const current = runs.filter((run) => run.term_id === termId && run.author !== 'agent').sort((a, b) => b.started - a.started)[0];
  const proposal = latest ? recent.findLast((entry) => entry.kind === 'command_proposal' && entry.data.run_id === latest.data.run_id) : undefined;
  const offered = proposal && proposal.ts_ms > (current?.started ?? 0) && Date.now() - proposal.ts_ms <= 30 * 60 * 1000
    && typeof proposal.data.command === 'string' && singleLine(proposal.data.command) ? proposal.data.command : null;

  if (mode === 'shell') {
    // The last offered command is often the next thing the user wants. Never replay an offer
    // that predates an executed command, or take a command from an unfinished model response.
    if (offered) candidates.push({ text: offered, score: 200, at: proposal!.ts_ms });
  } else {
    const topic = words(String(latest?.data.text ?? ''));
    const repeated = new Map<string, Candidate>();
    for (const [index, entry] of turns.entries()) {
      if (entry.data.automatic || entry.data.intent === 'explain' || entry.data.intent === 'fix') continue;
      const question = String(entry.data.text ?? '');
      if (!singleLine(question) || question.startsWith('I ran `')) continue;
      const overlap = [...words(question)].filter((word) => topic.has(word)).length;
      const key = question.toLowerCase();
      const previous = repeated.get(key);
      const score = 60 + index / 5 + Math.min(overlap, 4) * 10;
      repeated.set(key, { text: question, score: previous ? Math.max(score, previous.score + 5) : score, at: entry.ts_ms });
    }
    candidates.push(...repeated.values());

    // Complete recognizable questions with actual local context. No invented filenames, flags
    // or claims about an outcome, and no model generation competing with an active chat turn.
    if (current && singleLine(current.command) && current.command.length <= 160 && !current.command.includes('`')) {
      const command = `\`${current.command}\``;
      const add = (phrases: string[], score: number) => phrases.forEach((phrase) => candidates.push({ text: phrase, score, at: current.started }));
      add([`explain ${command}`, `what does ${command} do?`, `how does ${command} work?`], 85);
      if (current.ended != null && current.exit_code != null && current.exit_code !== 0) {
        add([`why did ${command} fail?`, `what went wrong with ${command}?`, `how can I fix ${command}?`, `how do I fix ${command}?`, `help me fix ${command}`, `fix ${command}`], 130);
      } else if (current.ended != null) {
        add([`explain the output of ${command}`, `what does the output of ${command} mean?`], 100);
      }
    }
    if (offered && offered.length <= 160 && !offered.includes('`')) {
      for (const phrase of [`explain \`${offered}\``, `is it safe to run \`${offered}\`?`, `what will \`${offered}\` change?`]) {
        candidates.push({ text: phrase, score: 115, at: proposal!.ts_ms });
      }
    }
    if (cwd && singleLine(cwd) && !cwd.includes('`')) {
      candidates.push({ text: `show me the files in \`${cwd}\``, score: 65, at: 0 });
      candidates.push({ text: `what is in \`${cwd}\`?`, score: 65, at: 0 });
    }
  }

  const prefix = mode === 'shell' ? text : text.toLowerCase();
  const matched = candidates.filter((candidate) => singleLine(candidate.text) && candidate.text.length > text.length
    && (mode === 'shell' ? candidate.text : candidate.text.toLowerCase()).startsWith(prefix));
  matched.sort((a, b) => b.score - a.score || b.at - a.at || a.text.length - b.text.length || a.text.localeCompare(b.text));
  const best = matched[0];
  return best ? marker + text + best.text.slice(text.length) : null;
}

/** The wire cursor and replacement start are UTF-8 byte offsets; the textarea uses UTF-16. */
export const byteCursor = (text: string, cursor = text.length) => new TextEncoder().encode(text.slice(0, cursor)).length;
export const textCursor = (text: string, bytes: number) => new TextDecoder().decode(new TextEncoder().encode(text).slice(0, bytes)).length;

/** With no personal history yet, an unambiguous live completion can still finish this word.
 * Leave quotes and shell operators to Tab; a ghost must be a literal, append-only continuation.
 */
export function shellSuggestion(value: string, result: Completions): string | null {
  if (!singleLine(value)) return null;
  const { marker, text } = inputText(value);
  if (text.trim().length < 2 || !singleLine(text)) return null;
  if (result.suggestion?.startsWith(text) && result.suggestion !== text && singleLine(result.suggestion)) return marker + result.suggestion;
  const from = textCursor(text, result.from);
  const word = text.slice(from);
  if (word.length < 2 || /['"`$\\;|&<>()[\]{}*?!]/.test(word)) return null;
  const matching = result.items.filter((item) => item.value.startsWith(word));
  if (matching.length !== 1 || matching[0]!.value === word) return null;
  const item = matching[0]!;
  const next = text.slice(0, from) + item.value;
  return singleLine(next) && next.startsWith(text) ? marker + next : null;
}
