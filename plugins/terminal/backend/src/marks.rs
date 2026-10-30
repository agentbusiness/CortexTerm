//! The shell integration's marks, read from a terminal's output: where the shell is (folder,
//! prompt, running command, last exit code, full-screen program) and the Runs it records.
//!
//! A small escape-sequence scanner runs over every output byte next to the VT emulator. It sees
//! OSC 133 (A prompt, B input, C command, D;<exit> done), OSC 7 (folder), OSC 633;E (the command
//! line, accepted only with this terminal's nonce), OSC 6973 (our PATH, aliases and functions,
//! nonce too), the alternate screen switches and BEL. Between C and D, the text with escape
//! sequences removed becomes the Run's output lines.

use crate::logs;
use crate::store::{Line, OUTPUT_CAP, Store};
use base64::Engine;
use crate::wire::Tty;
use cc_protocol::contracts::terminal::{Ask, Run, TermState, topics};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// A running command with no output for this long is probably waiting for input.
const QUIET_MS: u64 = 2000;
/// A hanging line counts as a question after this much quiet (a password prompt or a yes/no
/// one sooner than free text, which is more often a slow line of output).
const ASK_QUIET_MS: u64 = 250;
const TEXT_QUIET_MS: u64 = 800;
/// Lines after a Keychain fill within which the same prompt means the secret was refused.
const REFUSED_LINES: u64 = 3;
/// Longest kept line; longer text continues on the next line.
const MAX_LINE: usize = 64 * 1024;
/// Longest OSC payload read (the alias and function lists are the big ones).
const MAX_OSC: usize = 4 * 1024 * 1024;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// What the shell told us about itself (through OSC 6973).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellEnv {
    pub path: Option<String>,
    pub aliases: HashMap<String, String>,
    pub functions: HashSet<String>,
}

#[derive(Clone, Copy, PartialEq)]
enum Scan {
    Ground,
    Esc,
    /// ESC ( B and friends: one more byte.
    EscArg,
    Csi,
    Osc,
    OscEsc,
    /// DCS, SOS, PM, APC: skipped up to ST.
    Str,
    StrEsc,
}

/// What a terminal's tracker must remember across a plugin restart: kept by `cortexd` with the
/// terminal (its opaque `meta`) and handed to the next plugin instance, which resumes from it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Saved {
    pub nonce: String,
    pub cwd: String,
    #[serde(default)]
    pub integrated: bool,
    #[serde(default)]
    pub last_exit: Option<i32>,
    /// The Run in progress: its id, and the Run as it started (so the next instance continues it
    /// without asking the graph).
    #[serde(default)]
    pub running: Option<String>,
    #[serde(default)]
    pub run: Option<Run>,
    #[serde(default)]
    pub env: ShellEnv,
    /// The session that owns the terminal, if one does.
    #[serde(default)]
    pub session: Option<String>,
}

struct Recorder {
    run: Run,
    /// Lines ended since the last [`Tracker::feed`] handed them to the store.
    batch: Vec<Line>,
    /// Output text kept (up to [`OUTPUT_CAP`]).
    kept: u64,
    sample: Vec<String>,
    detected: bool,
}

/// One terminal's marks and Runs.
pub struct Tracker {
    nonce: String,
    store: Option<Arc<Store>>,
    /// The session that owns the terminal.
    pub session: Option<String>,
    state: TermState,
    pub env: ShellEnv,
    scan: Scan,
    buf: Vec<u8>,
    line: Vec<u8>,
    line_at: u64,
    cr: bool,
    /// The line before a carriage return redrew it.
    overwritten: Vec<u8>,
    /// `line` with its SGR codes (colour, style) kept, and the same for `overwritten`.
    ansi: Vec<u8>,
    overwritten_ansi: Vec<u8>,
    command: Option<String>,
    recorder: Option<Recorder>,
    last_output: u64,
    bell: bool,
    published: Option<String>,
    /// Bumped whenever `env` changes (so [`Tracker::saved_key`] stays cheap).
    env_generation: u64,
    /// The terminal's echo and foreground program, read since the last output.
    tty: Option<Tty>,
    /// The daemon can report them (an older one cannot: the prompt's words decide).
    reads_tty: bool,
    /// The current prompt was answered (typed into); it waits for the command's next output.
    answered: bool,
    /// The Keychain key looked up for the current prompt (once per prompt).
    tried: Option<String>,
    /// The Keychain key filled in during this Run, and [`Tracker::lines`] then.
    filled: Option<(String, u64)>,
    /// Output lines ended during this Run (the file's count stops at its cap).
    lines: u64,
    out: Vec<(&'static str, Value)>,
}

impl Tracker {
    pub fn new(term_id: &str, cwd: &str, nonce: String, store: Option<Arc<Store>>) -> Self {
        let state = TermState {
            term_id: term_id.to_owned(),
            cwd: cwd.to_owned(),
            attention: "idle".into(),
            git_branch: git_branch(Path::new(cwd)),
            ..TermState::default()
        };
        Self {
            nonce,
            store,
            session: None,
            state,
            env: ShellEnv::default(),
            scan: Scan::Ground,
            buf: Vec::new(),
            line: Vec::new(),
            line_at: 0,
            cr: false,
            overwritten: Vec::new(),
            ansi: Vec::new(),
            overwritten_ansi: Vec::new(),
            command: None,
            recorder: None,
            last_output: 0,
            bell: false,
            published: None,
            env_generation: 0,
            tty: None,
            reads_tty: false,
            answered: false,
            tried: None,
            filled: None,
            lines: 0,
            out: Vec::new(),
        }
    }

    /// A tracker for a terminal that was already running (a plugin restart or swap): its folder,
    /// what the shell reported and the Run in progress (`running`, with the lines it already
    /// has), whose output stream is continued.
    pub fn resume(term_id: &str, saved: Saved, store: Option<Arc<Store>>, running: Option<Run>) -> Self {
        let mut tracker = Self::new(term_id, &saved.cwd, saved.nonce, store);
        tracker.state.integrated = saved.integrated;
        tracker.state.last_exit = saved.last_exit;
        tracker.env = saved.env;
        tracker.session = saved.session;
        if let Some(run) = running.filter(|run| run.ended.is_none() && tracker.store.is_some()) {
            tracker.last_output = now_ms();
            tracker.recorder = Some(Recorder { run, batch: Vec::new(), kept: 0, sample: Vec::new(), detected: false });
        } else {
            tracker.state.at_prompt = saved.integrated;
        }
        tracker
    }

    /// What to keep with the terminal in the daemon.
    pub fn saved(&self) -> Saved {
        Saved {
            nonce: self.nonce.clone(),
            cwd: self.state.cwd.clone(),
            integrated: self.state.integrated,
            last_exit: self.state.last_exit,
            running: self.recorder.as_ref().map(|r| r.run.id.clone()),
            run: self.recorder.as_ref().map(|r| r.run.clone()),
            env: self.env.clone(),
            session: self.session.clone(),
        }
    }

    /// Changes whenever [`Tracker::saved`] would.
    pub fn saved_key(&self) -> String {
        format!(
            "{}|{}|{:?}|{:?}|{}",
            self.state.cwd,
            self.state.integrated,
            self.state.last_exit,
            self.recorder.as_ref().map(|r| &r.run.id),
            self.env_generation
        )
    }

    pub fn cwd(&self) -> String {
        self.state.cwd.clone()
    }

    /// The Run in progress.
    pub fn running(&self) -> Option<Run> {
        self.recorder.as_ref().map(|r| r.run.clone())
    }

    pub fn state(&self) -> TermState {
        let mut state = self.state.clone();
        let now = now_ms();
        state.running = self.running();
        state.ask = self.ask(now);
        state.keychain = self.filled.as_ref().map(|(key, _)| key.clone());
        state.attention = self.attention(now, state.ask.is_some()).into();
        state
    }

    fn attention(&self, now: u64, asks: bool) -> &'static str {
        if self.bell {
            "bell"
        } else if asks {
            "input"
        } else if self.recorder.is_some() {
            if now.saturating_sub(self.last_output) >= QUIET_MS { "input" } else { "running" }
        } else if self.state.last_exit.is_some_and(|code| code != 0) {
            "failed"
        } else {
            "idle"
        }
    }

    /// What the running command asks, if its last line is a question or the terminal stopped
    /// echoing (a password).
    fn ask(&self, now: u64) -> Option<Ask> {
        let recorder = self.recorder.as_ref()?;
        if self.state.alternate_screen || self.answered {
            return None;
        }
        let quiet = now.saturating_sub(self.last_output);
        // The asking program names the Keychain key: wait for it.
        if quiet < ASK_QUIET_MS || (self.reads_tty && self.tty.is_none()) {
            return None;
        }
        let text = String::from_utf8_lossy(&self.line).trim().to_owned();
        let program = match self.tty.as_ref().map(|tty| tty.program.as_str()).filter(|p| !p.is_empty()) {
            Some(program) => program.to_owned(),
            None => recorder.run.command.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("").to_owned(),
        };
        let lower = text.to_lowercase();
        let secret = match &self.tty {
            Some(tty) => !tty.echo && tty.canonical,
            // An older daemon cannot say: the words decide.
            None => text.ends_with(':') && ["password", "passphrase", "passcode"].iter().any(|word| lower.contains(word)),
        };
        if secret {
            let key = format!("{program} · {}", if text.is_empty() { "password" } else { &text });
            let refused = self.filled.as_ref().is_some_and(|(filled, lines)| {
                *filled == key && self.lines > *lines && self.lines - lines <= REFUSED_LINES
            });
            return Some(Ask { kind: "secret".into(), text, program, key, refused, ..Ask::default() });
        }
        // A redrawn line is a progress bar or a spinner, not a question.
        if text.is_empty() || !self.overwritten.is_empty() {
            return None;
        }
        if let Some((options, default)) = yes_no(&text) {
            return Some(Ask { kind: "confirm".into(), text, default, options, program, ..Ask::default() });
        }
        if quiet >= TEXT_QUIET_MS && text.ends_with([':', '?', '>', ')', ']']) {
            let default = text
                .strip_suffix(')')
                .and_then(|rest| rest.rsplit_once('('))
                .map(|(_, inside)| inside.trim().to_owned())
                .filter(|inside| !inside.is_empty());
            return Some(Ask { kind: "text".into(), text, default, program, ..Ask::default() });
        }
        None
    }

    /// The running command is quiet: is its terminal's echo worth reading now?
    pub fn wants_tty(&self, now: u64) -> bool {
        self.recorder.is_some() && !self.state.alternate_screen && !self.answered && self.tty.is_none() && now.saturating_sub(self.last_output) >= ASK_QUIET_MS
    }

    pub fn set_tty(&mut self, tty: Tty) {
        self.tty = Some(tty);
    }

    pub fn set_reads_tty(&mut self, reads: bool) {
        self.reads_tty = reads;
    }

    /// A secret prompt seen for the first time whose answer may be in the Keychain: its key.
    pub fn fill_wanted(&mut self) -> Option<String> {
        let ask = self.ask(now_ms())?;
        if ask.kind != "secret" || ask.refused || self.tried.as_deref() == Some(ask.key.as_str()) {
            return None;
        }
        self.tried = Some(ask.key.clone());
        Some(ask.key)
    }

    /// The secret for `key` was filled in from the Keychain.
    pub fn filled(&mut self, key: String) -> Vec<(&'static str, Value)> {
        self.filled = Some((key, self.lines));
        self.answered = true;
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// The Keychain no longer holds `key`.
    pub fn forgot(&mut self, key: &str) -> Vec<(&'static str, Value)> {
        if self.filled.as_ref().is_some_and(|(filled, _)| filled == key) {
            self.filled = None;
        }
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// The user typed into the terminal: a bell has been seen, a prompt has its answer.
    pub fn typed(&mut self) -> Vec<(&'static str, Value)> {
        self.bell = false;
        self.answered = self.recorder.is_some();
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// Re-evaluate time-based attention (`input`).
    pub fn tick(&mut self) -> Vec<(&'static str, Value)> {
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// Read output bytes; returns the events to publish.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<(&'static str, Value)> {
        let now = now_ms();
        if let Some(recorder) = &mut self.recorder {
            recorder.run.bytes += bytes.len() as u64;
            self.last_output = now;
            self.tty = None;
            self.answered = false;
            self.tried = None;
        }
        for &byte in bytes {
            self.byte(byte, now);
        }
        self.hand_lines();
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// The shell's output ended: a Run still open ends without an exit code.
    pub fn end(&mut self) -> Vec<(&'static str, Value)> {
        if self.recorder.is_some() {
            self.finish(None, now_ms());
        }
        self.state.at_prompt = false;
        self.publish_state();
        std::mem::take(&mut self.out)
    }

    /// Give the lines ended so far to the store (it sends them in batches).
    fn hand_lines(&mut self) {
        if let (Some(recorder), Some(store)) = (self.recorder.as_mut(), self.store.as_ref())
            && !recorder.batch.is_empty()
        {
            store.lines(&recorder.run.id, std::mem::take(&mut recorder.batch));
        }
    }

    fn byte(&mut self, byte: u8, now: u64) {
        match self.scan {
            Scan::Ground => match byte {
                0x1b => self.scan = Scan::Esc,
                0x07 => self.bell = true,
                b'\n' => {
                    self.cr = false;
                    self.overwritten.clear();
                    self.overwritten_ansi.clear();
                    self.end_line();
                }
                b'\r' => self.cr = true,
                0x08 => {
                    for line in [&mut self.line, &mut self.ansi] {
                        while let Some(last) = line.pop() {
                            if last & 0xC0 != 0x80 {
                                break;
                            }
                        }
                    }
                }
                b'\t' | 0x20.. => self.text(byte, now),
                _ => {}
            },
            Scan::Esc => {
                self.scan = match byte {
                    b'[' => Scan::Csi,
                    b']' => Scan::Osc,
                    b'P' | b'X' | b'^' | b'_' => Scan::Str,
                    b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' | b'#' | b'%' | b' ' => Scan::EscArg,
                    0x1b => Scan::Esc,
                    _ => Scan::Ground,
                };
                self.buf.clear();
            }
            Scan::EscArg => self.scan = Scan::Ground,
            Scan::Csi => match byte {
                0x40..=0x7e => {
                    self.csi(byte);
                    self.scan = Scan::Ground;
                }
                0x1b => self.scan = Scan::Esc,
                0x20..=0x3f => {
                    if self.buf.len() < 64 {
                        self.buf.push(byte);
                    }
                }
                _ => {}
            },
            Scan::Osc => match byte {
                0x07 => {
                    self.osc(now);
                    self.scan = Scan::Ground;
                }
                0x1b => self.scan = Scan::OscEsc,
                _ => {
                    if self.buf.len() < MAX_OSC {
                        self.buf.push(byte);
                    }
                }
            },
            Scan::OscEsc => {
                self.osc(now);
                self.scan = Scan::Ground;
                if byte != b'\\' {
                    self.byte(0x1b, now);
                    self.byte(byte, now);
                }
            }
            Scan::Str => {
                if byte == 0x1b {
                    self.scan = Scan::StrEsc;
                } else if byte == 0x07 {
                    self.scan = Scan::Ground;
                }
            }
            Scan::StrEsc => self.scan = if byte == b'\\' { Scan::Ground } else { Scan::Str },
        }
    }

    fn recording(&self) -> bool {
        self.recorder.is_some() && !self.state.alternate_screen
    }

    fn text(&mut self, byte: u8, now: u64) {
        if !self.recording() {
            return;
        }
        self.redraw();
        if self.line.is_empty() {
            self.line_at = now;
        }
        self.line.push(byte);
        self.ansi.push(byte);
        if self.line.len() >= MAX_LINE {
            self.end_line();
        }
    }

    /// After a carriage return without a newline, new text redraws the line (progress bars).
    fn redraw(&mut self) {
        if self.cr {
            self.cr = false;
            self.overwritten = std::mem::take(&mut self.line);
            self.overwritten_ansi = std::mem::take(&mut self.ansi);
        }
    }

    fn clear_line(&mut self) {
        self.line.clear();
        self.ansi.clear();
    }

    /// The line with its SGR codes, when it has any and they decorate exactly the stored text.
    fn take_ansi(&mut self, text: &str) -> String {
        let ansi = String::from_utf8_lossy(&std::mem::take(&mut self.ansi)).into_owned();
        if ansi.contains('\x1b') && strip_sgr(&ansi) == text { ansi } else { String::new() }
    }

    fn end_line(&mut self) {
        if !self.recording() {
            self.clear_line();
            return;
        }
        self.lines += 1;
        let text = String::from_utf8_lossy(&self.line).into_owned();
        let ansi = self.take_ansi(&text);
        self.clear_line();
        let at = if self.line_at == 0 { now_ms() } else { self.line_at };
        self.line_at = 0;
        let Some(recorder) = &mut self.recorder else { return };
        let level = logs::level(&text);
        match level {
            "error" => recorder.run.errors += 1,
            "warn" => recorder.run.warnings += 1,
            _ => {}
        }
        if !recorder.detected {
            recorder.sample.push(text.clone());
            if recorder.sample.len() >= logs::SAMPLE_LINES {
                recorder.run.format = logs::detect(&recorder.sample).into();
                recorder.detected = true;
                recorder.sample = Vec::new();
            }
        }
        if recorder.kept < OUTPUT_CAP && self.store.is_some() {
            let line = Line { at, level: level.to_owned(), text, ansi };
            recorder.kept += line.size();
            recorder.run.lines += 1;
            recorder.batch.push(line);
        }
    }

    fn csi(&mut self, last: u8) {
        if last == b'm' && self.recording() {
            self.redraw();
            self.ansi.extend_from_slice(b"\x1b[");
            self.ansi.extend_from_slice(&self.buf);
            self.ansi.push(b'm');
            return;
        }
        if !(last == b'h' || last == b'l') || self.buf.first() != Some(&b'?') {
            return;
        }
        let params = String::from_utf8_lossy(&self.buf[1..]).into_owned();
        if params.split(';').any(|p| matches!(p, "1049" | "1047" | "47")) {
            let on = last == b'h';
            if on && !self.state.alternate_screen {
                // What was typed before the switch stays a line of its own.
                if !self.line.is_empty() {
                    self.end_line();
                }
                if let Some(recorder) = &mut self.recorder {
                    recorder.run.fullscreen = true;
                }
            }
            self.state.alternate_screen = on;
            self.clear_line();
        }
    }

    fn osc(&mut self, now: u64) {
        let payload = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        let (code, rest) = payload.split_once(';').unwrap_or((payload.as_str(), ""));
        match code {
            "133" => self.mark(rest, now),
            "7" => {
                // file://host/path (percent-encoded)
                if let Some(path) = rest.strip_prefix("file://").and_then(|r| r.find('/').map(|i| &r[i..])) {
                    let path = percent_decode(path);
                    if !path.is_empty() && path != self.state.cwd {
                        self.state.git_branch = git_branch(Path::new(&path));
                        self.state.cwd = path;
                    }
                }
            }
            "633" => {
                if let Some(line) = rest.strip_prefix("E;")
                    && let Some((command, nonce)) = line.rsplit_once(';')
                    && nonce == self.nonce
                {
                    self.command = Some(unescape(command));
                }
            }
            "6973" => self.shell_env(rest),
            _ => {}
        }
    }

    fn mark(&mut self, rest: &str, now: u64) {
        let mut parts = rest.split(';');
        let kind = parts.next().unwrap_or("");
        self.state.integrated = true;
        match kind {
            "A" | "B" if self.recorder.is_none() => self.state.at_prompt = true,
            "C" if self.recorder.is_none() => self.start(now),
            "D" if self.recorder.is_some() => {
                let code = parts.next().and_then(|c| c.trim().parse::<i32>().ok());
                self.finish(code, now);
            }
            _ => {}
        }
    }

    fn start(&mut self, now: u64) {
        self.state.at_prompt = false;
        self.bell = false;
        self.filled = None;
        self.tried = None;
        self.answered = false;
        self.tty = None;
        self.lines = 0;
        self.clear_line();
        self.cr = false;
        let command = self.command.take().unwrap_or_default().trim().to_owned();
        let cwd = self.state.cwd.clone();
        let usual_ms = match &self.store {
            Some(store) if !command.is_empty() => store.usual_ms(&command, &cwd),
            _ => 0,
        };
        let run = Run {
            id: format!("run-{}", uuid::Uuid::new_v4().simple()),
            term_id: self.state.term_id.clone(),
            command,
            cwd,
            started: now,
            format: "raw".into(),
            author: "user".into(),
            fullscreen: self.state.alternate_screen,
            usual_ms,
            ..Run::default()
        };
        if let Some(store) = &self.store {
            store.started(&run, self.env.path.clone());
        }
        self.last_output = now;
        self.push(topics::RUN_STARTED, &run);
        self.recorder = Some(Recorder { run, batch: Vec::new(), kept: 0, sample: Vec::new(), detected: false });
    }

    fn finish(&mut self, code: Option<i32>, now: u64) {
        // The shell's prompt redraws the last line (zsh's PROMPT_SP prints `%`, spaces and
        // carriage returns after output without a final newline): keep what the command wrote.
        if self.cr || self.line.iter().all(u8::is_ascii_whitespace) {
            let mut last = std::mem::take(&mut self.overwritten);
            let mut last_ansi = std::mem::take(&mut self.overwritten_ansi);
            if self.cr && !self.line.iter().all(u8::is_ascii_whitespace) {
                last = std::mem::take(&mut self.line);
                last_ansi = std::mem::take(&mut self.ansi);
            }
            while last.last().is_some_and(u8::is_ascii_whitespace) {
                last.pop();
            }
            if matches!(last.last(), Some(b'%' | b'#')) && self.line.iter().all(u8::is_ascii_whitespace) {
                last.pop();
            }
            self.line = last;
            // The codes still match when only plain trailing spaces (or the `%`) went.
            while last_ansi.last().is_some_and(u8::is_ascii_whitespace) {
                last_ansi.pop();
            }
            if last_ansi.len() > self.line.len() && matches!(last_ansi.last(), Some(b'%' | b'#')) {
                last_ansi.pop();
            }
            self.ansi = last_ansi;
            self.cr = false;
        }
        if !self.line.is_empty() {
            self.end_line();
        }
        self.overwritten.clear();
        self.overwritten_ansi.clear();
        self.filled = None;
        self.hand_lines();
        let Some(mut recorder) = self.recorder.take() else { return };
        let run = &mut recorder.run;
        if !recorder.detected {
            run.format = logs::detect(&recorder.sample).into();
        }
        run.ended = Some(now);
        run.exit_code = code;
        run.duration_ms = now.saturating_sub(run.started);
        if let Some(store) = &self.store {
            store.finished(run);
        }
        if code.is_some() {
            self.state.last_exit = code;
        }
        let run = recorder.run;
        self.push(topics::RUN_FINISHED, &run);
    }

    fn shell_env(&mut self, rest: &str) {
        let mut parts = rest.splitn(3, ';');
        let (Some(kind), Some(data), Some(nonce)) = (parts.next(), parts.next(), parts.next()) else { return };
        if nonce != self.nonce {
            return;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data.trim()) else { return };
        let text = String::from_utf8_lossy(&bytes);
        self.env_generation += 1;
        match kind {
            "env" => self.env.path = Some(text.into_owned()),
            "alias" => {
                self.env.aliases = text
                    .lines()
                    .filter_map(|line| line.split_once('='))
                    .map(|(name, value)| (name.to_owned(), unquote_alias(value)))
                    .collect();
            }
            "func" => self.env.functions = text.lines().filter(|l| !l.is_empty()).map(str::to_owned).collect(),
            _ => {}
        }
    }

    fn push<T: serde::Serialize>(&mut self, topic: &'static str, data: &T) {
        if let Ok(value) = serde_json::to_value(data) {
            self.out.push((topic, value));
        }
    }

    /// Queue `terminal.state` when something other than the running Run's counters changed.
    fn publish_state(&mut self) {
        let state = self.state();
        let key = format!(
            "{}|{}|{}|{:?}|{:?}|{}|{}|{:?}|{:?}|{:?}",
            state.cwd,
            state.integrated,
            state.at_prompt,
            state.running.as_ref().map(|r| &r.id),
            state.last_exit,
            state.alternate_screen,
            state.attention,
            state.git_branch,
            state.ask,
            state.keychain
        );
        if self.published.as_deref() != Some(key.as_str()) {
            self.published = Some(key);
            self.push(topics::STATE_CHANGED, &state);
        }
    }
}

/// A yes/no question: `[Y/n]`, `(y/N)`, `(yes/no)`, `(yes/no/[fingerprint])`. Returns the yes and
/// no answers as spelled there and the default (the capitalised one), if any.
fn yes_no(text: &str) -> Option<(Vec<String>, Option<String>)> {
    for (open, close) in [('[', ']'), ('(', ')')] {
        let Some(start) = text.rfind(open) else { continue };
        let Some(end) = text[start..].rfind(close) else { continue };
        let inside = &text[start + 1..start + end];
        let mut words = inside.split('/').map(str::trim);
        let (Some(yes), Some(no)) = (words.next(), words.next()) else { continue };
        let pair = (yes.to_lowercase(), no.to_lowercase());
        if !matches!((pair.0.as_str(), pair.1.as_str()), ("y", "n") | ("yes", "no")) {
            continue;
        }
        let capital = |word: &str| word.chars().all(char::is_uppercase);
        let default = match (capital(yes), capital(no)) {
            (true, false) => Some(pair.0.clone()),
            (false, true) => Some(pair.1.clone()),
            _ => None,
        };
        return Some((vec![pair.0, pair.1], default));
    }
    None
}

/// `text` without its `ESC[...m` sequences.
fn strip_sgr(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\x1b[") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        match after.find('m') {
            Some(end) => rest = &after[end + 1..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// bash prints `alias ll='ls -l'`; zsh sends `ll=ls -l`.
fn unquote_alias(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("'\\''", "'")
    } else {
        value.to_owned()
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(byte) = hex(bytes.get(i + 1..i + 3))
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(digits: Option<&[u8]>) -> Option<u8> {
    u8::from_str_radix(std::str::from_utf8(digits?).ok()?, 16).ok()
}

/// The 633;E escaping: `\\` is a backslash, `\xHH` a byte.
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\\') {
            out.push(b'\\');
            i += 2;
        } else if bytes[i] == b'\\'
            && bytes.get(i + 1) == Some(&b'x')
            && let Some(byte) = hex(bytes.get(i + 2..i + 4))
        {
            out.push(byte);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The checked-out branch (or short commit) of the repository `dir` is in.
pub fn git_branch(dir: &Path) -> Option<String> {
    let dot_git = dir.ancestors().map(|d| d.join(".git")).find(|p| p.exists())?;
    let git_dir = if dot_git.is_file() {
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let target = text.trim().strip_prefix("gitdir:")?.trim().to_owned();
        let target = Path::new(&target);
        if target.is_absolute() { target.to_path_buf() } else { dot_git.parent()?.join(target) }
    } else {
        dot_git
    };
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    match head.strip_prefix("ref: ") {
        Some(reference) => Some(reference.strip_prefix("refs/heads/").unwrap_or(reference).to_owned()),
        None => Some(head.chars().take(7).collect()),
    }
}
