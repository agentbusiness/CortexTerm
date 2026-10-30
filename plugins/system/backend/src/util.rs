//! Small helpers: time, paths and running a command with a time limit.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

/// `~/...` for paths under the home folder.
pub fn tilde(path: &Path) -> String {
    match path.strip_prefix(home()) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// CortexTerm's home: `$CORTEX_HOME`, else `~/.cortexterm`.
pub fn cortex_home() -> PathBuf {
    std::env::var_os("CORTEX_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| home().join(".cortexterm"))
}

/// This plugin's data folder: `$CORTEX_PLUGIN_DATA`, else `<home>/plugins-data/cc-system` (the
/// frame names it after the executable). Nothing is kept in it: it holds only the probe's
/// write check, and the files earlier versions kept until `migrate` moves them into the graph.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CORTEX_PLUGIN_DATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    cortex_home().join("plugins-data").join("cc-system")
}

/// Find a program on PATH or in the usual Homebrew and system places (a GUI app's PATH is short).
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .chain(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from))
        .chain([home().join(".local/bin"), home().join(".cargo/bin")])
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// Run a program (found with [`which`] when not a path) and wait at most `timeout` for it.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> Result<Output, String> {
    run_env(program, args, &[], timeout)
}

/// [`run`] with extra environment variables.
pub fn run_env(program: &str, args: &[&str], env: &[(&str, &str)], timeout: Duration) -> Result<Output, String> {
    let exe =
        if program.contains('/') { PathBuf::from(program) } else { which(program).ok_or_else(|| format!("{program} is not installed"))? };
    // The program's own folder first on PATH, so `#!/usr/bin/env node` scripts find their interpreter.
    let mut path = exe.parent().map(|dir| dir.display().to_string()).unwrap_or_default();
    path.push_str(":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:");
    path.push_str(&std::env::var("PATH").unwrap_or_default());
    let mut child = Command::new(&exe)
        .args(args)
        .env("PATH", path)
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ANALYTICS", "1")
        .env("HOMEBREW_NO_ENV_HINTS", "1")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{program}: {error}"))?;
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} did not finish within {} s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => return Err(format!("{program}: {error}")),
        }
    };
    Ok(Output {
        ok: status.success(),
        stdout: String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned(),
        stderr: String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned(),
    })
}

/// Shorten to at most `max` characters.
pub fn shorten(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `45s`, `4m12s`, `2h05m`.
pub fn duration_text(ms: u64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

/// `2026-10-29 08:14` in local time, for Unix milliseconds.
pub fn local_time(ms: u64) -> String {
    let secs = (ms / 1000) as libc::time_t;
    // SAFETY: localtime_r only writes the tm it is given.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return String::new();
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
}
