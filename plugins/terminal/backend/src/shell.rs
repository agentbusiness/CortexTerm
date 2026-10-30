//! Shell integration, injected without touching the user's startup files (as kitty and Ghostty
//! do). The hook scripts live in the plugin's data folder (`data/shell`):
//!
//! - zsh: `ZDOTDIR` points to `data/shell/zsh`, whose `.zshenv` restores the user's `ZDOTDIR`
//!   (saved in `CORTEXTERM_ZDOTDIR`), sources their `.zshenv` and installs the hooks; zsh then
//!   reads the user's `.zprofile`, `.zshrc` and `.zlogin` as usual.
//! - bash 4.4+: `bash --posix` with `ENV=data/shell/bash/cortexterm.bash`, which turns POSIX mode
//!   off and reads the startup files bash would have read (`CORTEXTERM_BASH_LOGIN=1` for a login
//!   shell). Older bash (macOS `/bin/bash` 3.2) runs plain.
//! - fish: `data/shell` first in `XDG_DATA_DIRS` (fish reads `data/shell/fish/vendor_conf.d`; the
//!   script takes the entry out again, named by `CORTEXTERM_FISH_DIR`), and `fish_features` with
//!   `no-mark-prompt,no-query-term` (the script restores the user's value).
//!
//! Every injected shell gets `CORTEXTERM_SI=1` and `CORTEXTERM_NONCE` (the scripts move the nonce
//! into a shell variable, so programs cannot read it to fake a command line).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// How to start a shell with the integration.
pub struct Injection {
    /// Replaces the shell's arguments when set.
    pub args: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
}

/// `data/shell` beside the executable or in one of its ancestors (the package root holds
/// `data/` and `backend/target/release/cc-terminal`).
fn packaged_dir() -> Option<PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        exe.parent()?.ancestors().take(5).map(|dir| dir.join("data").join("shell")).find(|dir| dir.is_dir())
    })
    .clone()
}

/// The scripts folder: the live copy (`$CORTEX_PLUGIN_LIVE/data/shell`) when it exists, else the
/// packaged one.
pub fn scripts_dir() -> Option<PathBuf> {
    if let Some(live) = std::env::var_os("CORTEX_PLUGIN_LIVE").filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(live).join("data").join("shell");
        if dir.is_dir() {
            return Some(dir);
        }
    }
    packaged_dir()
}

/// Whether the arguments are the plain interactive/login ones we know how to keep.
fn plain_args(args: Option<&[String]>) -> bool {
    args.is_none_or(|args| args.iter().all(|a| matches!(a.as_str(), "-l" | "--login" | "-i")))
}

/// The integration for `shell` started with `args` (None: a login shell), or None when the shell
/// is not one we integrate, runs a custom command, or the scripts are missing.
pub fn inject(shell: &str, args: Option<&[String]>, nonce: &str) -> Option<Injection> {
    if !plain_args(args) {
        return None;
    }
    let dir = scripts_dir()?;
    let login = args.is_none_or(|args| args.iter().any(|a| a == "-l" || a == "--login"));
    let name = Path::new(shell).file_name()?.to_string_lossy().trim_start_matches('-').to_owned();
    let mut env = vec![("CORTEXTERM_SI".to_owned(), "1".to_owned()), ("CORTEXTERM_NONCE".to_owned(), nonce.to_owned())];
    let mut new_args = None;
    match name.as_str() {
        "zsh" => {
            let zsh = dir.join("zsh");
            if !zsh.join(".zshenv").is_file() {
                return None;
            }
            if let Some(user) = std::env::var_os("ZDOTDIR") {
                env.push(("CORTEXTERM_ZDOTDIR".into(), user.to_string_lossy().into_owned()));
            }
            env.push(("ZDOTDIR".into(), zsh.to_string_lossy().into_owned()));
        }
        "bash" => {
            let script = dir.join("bash").join("cortexterm.bash");
            if !script.is_file() || !bash_supported(shell) {
                return None;
            }
            env.push(("ENV".into(), script.to_string_lossy().into_owned()));
            if login {
                env.push(("CORTEXTERM_BASH_LOGIN".into(), "1".into()));
            }
            new_args = Some(vec!["--posix".to_owned()]);
        }
        "fish" => {
            if !dir.join("fish").join("vendor_conf.d").is_dir() {
                return None;
            }
            // fish reads `<entry>/fish/vendor_conf.d` for every XDG_DATA_DIRS entry.
            let entry = dir.to_string_lossy().into_owned();
            let dirs = match std::env::var("XDG_DATA_DIRS") {
                Ok(dirs) if !dirs.is_empty() => format!("{entry}:{dirs}"),
                _ => entry.clone(),
            };
            env.push(("XDG_DATA_DIRS".into(), dirs));
            env.push(("CORTEXTERM_FISH_DIR".into(), entry));
            // Our script writes the marks (fish 4's own lack the nonce), and fish must not wait
            // for answers to terminal queries: nobody answers while no window shows the pane.
            let user = std::env::var("fish_features").unwrap_or_default();
            let ours = "no-mark-prompt,no-query-term";
            env.push(("fish_features".into(), if user.is_empty() { ours.into() } else { format!("{user},{ours}") }));
            env.push(("CORTEXTERM_FISH_FEATURES".into(), user));
        }
        _ => return None,
    }
    Some(Injection { args: new_args, env })
}

/// bash 4.4 or newer (PS0 and `--posix` with `ENV`); asked once per executable.
fn bash_supported(shell: &str) -> bool {
    static SEEN: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(known) = crate::lock(seen).get(shell) {
        return *known;
    }
    let supported = std::process::Command::new(shell)
        .args(["--norc", "--noprofile", "-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut parts = text.split_whitespace().map(|p| p.parse::<u32>().unwrap_or(0));
            Some((parts.next()?, parts.next().unwrap_or(0)))
        })
        .is_some_and(|version| version >= (4, 4));
    crate::lock(seen).insert(shell.to_owned(), supported);
    supported
}
