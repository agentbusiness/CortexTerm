//! The plugin <-> `cortexd` protocol: one JSON object per line over the Unix socket
//! `$CORTEX_HOME/run/cortexd.sock` (mode 0600).
//!
//! The plugin sends [`Request`]s (`{"id": n, "op": "...", ...}`); the daemon answers each with a
//! [`Message::Reply`] carrying the same id and pushes [`Message::Output`], [`Message::Exit`] and
//! [`Message::Taken`] to the client that owns the terminals. Output bytes travel as standard
//! base64, already coalesced by the daemon.
//!
//! The protocol only grows: new ops and fields are additive, so a plugin keeps working with an
//! older daemon that still has living shells. [`DAEMON_VERSION`] is bumped whenever the daemon's
//! code changes; a plugin that meets an older daemon with no living shells asks it to quit and
//! starts its own (see `client`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The daemon build: bump it whenever `daemon.rs` (or what it runs) changes.
pub const DAEMON_VERSION: u32 = 4;

/// `$CORTEX_HOME`, else `~/.cortexterm`.
pub fn home() -> PathBuf {
    match std::env::var_os("CORTEX_HOME").filter(|v| !v.is_empty()) {
        Some(home) => PathBuf::from(home),
        None => PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cortexterm"),
    }
}

pub fn socket_path(home: &Path) -> PathBuf {
    home.join("run").join("cortexd.sock")
}

pub fn lock_path(home: &Path) -> PathBuf {
    home.join("run").join("cortexd.lock")
}

pub fn log_path(home: &Path) -> PathBuf {
    home.join("logs").join("cortexd.log")
}

/// How to start a shell. The plugin decides everything (arguments, the whole environment, the
/// integration); the daemon only runs it, so its behaviour does not depend on its version.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Spawn {
    /// Chosen by the plugin (`term-<hex>`, so it knows the terminal before its first output);
    /// empty: the daemon picks one.
    #[serde(default)]
    pub term_id: String,
    pub shell: String,
    pub args: Vec<String>,
    pub cwd: String,
    /// The complete environment (the daemon's own is not inherited).
    pub env: Vec<(String, String)>,
    pub cols: u16,
    pub rows: u16,
    /// Opaque to the daemon: kept with the terminal and handed back by `hello` (the plugin keeps
    /// the shell integration's nonce and what it learned about the shell here).
    #[serde(default)]
    pub meta: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// -> [`Hello`]. Every connection starts with it. A guest (`guest: true`, the probe) sees
    /// only the terminals it opens, and they are closed when it disconnects.
    Hello {
        #[serde(default)]
        guest: bool,
    },
    /// Become the owner: every terminal's output goes to this connection from now on, starting
    /// with what was produced while no owner was attached (`replay: true`). The previous owner
    /// gets [`Message::Taken`] and is disconnected. -> null
    Attach,
    /// -> [`Record`]
    Open { spawn: Spawn },
    /// Queue input (base64); the daemon writes it in order. -> null
    Write { term_id: String, data: String },
    /// -> [`Record`]
    Resize { term_id: String, cols: u16, rows: u16 },
    /// Hang up the shell's process group (and the foreground job), kill what ignores it, forget
    /// the terminal. -> [`Record`] (with the exit)
    Close { term_id: String },
    /// -> `cc_protocol::contracts::terminal::Snapshot`
    Snapshot { term_id: String, #[serde(default)] restore: bool },
    /// How the terminal reads input now and who reads it. -> [`Tty`] (version 2 and later)
    Tty { term_id: String },
    /// Replace the terminal's opaque `meta`. -> null
    Meta { term_id: String, meta: Value },
    /// Exit now; refused while a shell is alive. -> null
    Quit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub op: Op,
}

/// A terminal as the daemon knows it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Record {
    pub term_id: String,
    pub pid: u32,
    pub shell: String,
    /// The folder it was opened in.
    pub cwd: String,
    pub cols: u16,
    pub rows: u16,
    pub alive: bool,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub signal: Option<String>,
    #[serde(default)]
    pub meta: Value,
}

/// The terminal's line discipline and its foreground program, for telling a password prompt
/// (echo off, line mode) from any other quiet command.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Tty {
    /// The kernel supplied the flags (a failed read is never interpreted as raw input).
    #[serde(default)]
    pub valid: bool,
    /// A job other than the login shell owns the terminal foreground process group.
    #[serde(default)]
    pub foreground: bool,
    pub echo: bool,
    pub canonical: bool,
    /// The newest process of the foreground group (the one asking): `sudo`, `ssh`.
    #[serde(default)]
    pub program: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hello {
    pub version: u32,
    pub pid: u32,
    pub terms: Vec<Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum Message {
    Reply {
        id: u64,
        #[serde(default)]
        ok: Value,
        #[serde(default)]
        error: Option<String>,
    },
    /// Output bytes (base64). `replay`: produced while no owner was attached; the screen
    /// (`snapshot`) already shows them.
    Output {
        term_id: String,
        data: String,
        #[serde(default)]
        replay: bool,
        #[serde(default)]
        offset: Option<u64>,
        #[serde(default)]
        tty: Option<Tty>,
    },
    Exit {
        term_id: String,
        code: i32,
        #[serde(default)]
        signal: Option<String>,
    },
    /// Another client attached; this one no longer owns the terminals.
    Taken,
}
