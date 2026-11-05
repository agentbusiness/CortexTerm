//! SSH, read only: hosts from `~/.ssh/config` (following `Include`), `known_hosts` and the zsh
//! history, each with its effective settings from `ssh -G` and a reachability check; the keys in
//! `~/.ssh` and in the running agent, with hygiene notes. Nothing here writes to `~/.ssh`, and key
//! material is never read into the output.

use crate::util::{home, run, run_env, which};
use cc_protocol::contracts::system::{Addresses, SshHost, SshHosts, SshKey, SshKeys};
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

/// How long a host list and a reachability result stay fresh.
const FRESH: Duration = Duration::from_secs(60);
/// The TCP connect limit of a reachability check.
const CONNECT: Duration = Duration::from_secs(2);
/// At most this many hosts are resolved with `ssh -G`.
const MAX_HOSTS: usize = 64;

type Reach = HashMap<(String, u16), (Instant, &'static str)>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Default)]
pub struct State {
    hosts: Mutex<Option<(Instant, SshHosts)>>,
    reach: Arc<Mutex<Reach>>,
    checking: Arc<AtomicBool>,
}

impl State {
    /// The hosts with their reachability (blocking). Hosts never checked are checked now (at most
    /// about 2 s); stale results are refreshed in the background and shown until then.
    pub fn hosts(&self) -> SshHosts {
        let mut list = {
            let mut cache = lock(&self.hosts);
            match cache.as_ref() {
                Some((at, list)) if at.elapsed() < FRESH => list.clone(),
                _ => {
                    let list = discover();
                    *cache = Some((Instant::now(), list.clone()));
                    list
                }
            }
        };
        let targets: Vec<(String, u16)> =
            list.hosts.iter().filter(|h| h.reachable.is_empty()).map(|h| (h.hostname.clone(), h.port)).collect();
        let (missing, stale): (Vec<_>, Vec<_>) = {
            let reach = lock(&self.reach);
            let missing = targets.iter().filter(|t| !reach.contains_key(*t)).cloned().collect();
            let stale = targets.iter().filter(|t| reach.get(*t).is_some_and(|(at, _)| at.elapsed() >= FRESH)).cloned().collect();
            (missing, stale)
        };
        if !missing.is_empty() {
            check(&self.reach, missing);
        }
        if !stale.is_empty() && !self.checking.swap(true, Ordering::SeqCst) {
            let (reach, checking) = (self.reach.clone(), self.checking.clone());
            std::thread::spawn(move || {
                check(&reach, stale);
                checking.store(false, Ordering::SeqCst);
            });
        }
        let reach = lock(&self.reach);
        for host in list.hosts.iter_mut().filter(|h| h.reachable.is_empty()) {
            host.reachable = reach.get(&(host.hostname.clone(), host.port)).map(|(_, state)| *state).unwrap_or("unknown").to_owned();
        }
        list
    }

    /// The keys in `~/.ssh` and in the agent (blocking).
    pub fn keys(&self) -> SshKeys {
        let hosts = self.hosts();
        let mut keys = file_keys();
        let agent = agent_keys(&hosts.agent_socket);
        for key in &mut keys {
            key.in_agent = agent.iter().any(|a| a.fingerprint == key.fingerprint);
        }
        for held in agent {
            if !keys.iter().any(|k| k.fingerprint == held.fingerprint) {
                keys.push(held);
            }
        }
        for key in &mut keys {
            key.used_by = hosts.hosts.iter().filter(|h| h.identity.contains(&key.path)).map(|h| h.alias.clone()).collect();
        }
        SshKeys { keys }
    }
}

/// TCP-connect to each target (in parallel, about 2 s at most) and record up or down.
fn check(reach: &Mutex<Reach>, targets: Vec<(String, u16)>) {
    let (tx, rx) = mpsc::channel();
    let count = targets.len();
    for target in targets {
        let tx = tx.clone();
        // A thread each: name lookups block, and a late answer is simply dropped.
        std::thread::spawn(move || {
            let up = (target.0.as_str(), target.1)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .is_some_and(|addr| TcpStream::connect_timeout(&addr, CONNECT).is_ok());
            let _ = tx.send((target, if up { "up" } else { "down" }));
        });
    }
    drop(tx);
    let deadline = Instant::now() + CONNECT + Duration::from_millis(500);
    for _ in 0..count {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else { break };
        let Ok((target, state)) = rx.recv_timeout(left) else { break };
        lock(reach).insert(target, (Instant::now(), state));
    }
}

/// A host before `ssh -G` fills in its settings.
struct Seed {
    alias: String,
    source: &'static str,
    defined_at: Option<String>,
    last_used: u64,
    /// The user typed in history (`ssh deploy@box`).
    user: Option<String>,
}

fn discover() -> SshHosts {
    let dir = home().join(".ssh");
    let mut seeds: Vec<Seed> = Vec::new();
    let mut config = Vec::new();
    read_config(&dir.join("config"), &dir, 0, &mut config);
    for (alias, defined_at) in config {
        if !seeds.iter().any(|s| s.alias == alias) {
            seeds.push(Seed { alias, source: "config", defined_at: Some(defined_at), last_used: 0, user: None });
        }
    }
    let mut typed = history();
    typed.sort_by(|a, b| b.2.cmp(&a.2));
    for (host, user, at) in typed {
        match seeds.iter_mut().find(|s| s.alias == host) {
            Some(seed) => seed.last_used = seed.last_used.max(at),
            None => seeds.push(Seed { alias: host, source: "history", defined_at: None, last_used: at, user }),
        }
    }
    for host in known_hosts(&dir.join("known_hosts")) {
        if !seeds.iter().any(|s| s.alias == host) {
            seeds.push(Seed { alias: host, source: "known_hosts", defined_at: None, last_used: 0, user: None });
        }
    }
    seeds.truncate(MAX_HOSTS);

    // `ssh -G` sixteen at a time.
    let settings: Vec<HashMap<String, Vec<String>>> = seeds
        .chunks(16)
        .flat_map(|chunk| {
            std::thread::scope(|scope| {
                let jobs: Vec<_> = chunk.iter().map(|seed| scope.spawn(|| effective(&seed.alias))).collect();
                jobs.into_iter().map(|job| job.join().unwrap_or_default()).collect::<Vec<_>>()
            })
        })
        .collect();

    let mosh = which("mosh").is_some();
    let me = std::env::var("USER").unwrap_or_default();
    let mut agent_setting = None;
    let mut hosts: Vec<SshHost> = Vec::new();
    for (seed, set) in seeds.into_iter().zip(settings) {
        let one = |key: &str| set.get(key).and_then(|v| v.first()).cloned().filter(|v| !v.is_empty() && v != "none");
        if seed.source == "config" && agent_setting.is_none() {
            agent_setting = set.get("identityagent").and_then(|v| v.first()).cloned();
        }
        let hostname = one("hostname").unwrap_or_else(|| seed.alias.clone());
        // A known_hosts name a config entry already covers is the same machine.
        if seed.source == "known_hosts" && hosts.iter().any(|h| h.hostname == hostname) {
            continue;
        }
        let proxy_jump = one("proxyjump");
        let proxied = proxy_jump.is_some() || one("proxycommand").is_some();
        hosts.push(SshHost {
            hostname,
            user: seed.user.or_else(|| one("user")).unwrap_or_else(|| me.clone()),
            port: one("port").and_then(|p| p.parse().ok()).unwrap_or(22),
            identity: set
                .get("identityfile")
                .into_iter()
                .flatten()
                .map(|path| expand(path))
                .filter(|path| path.is_file())
                .map(|path| path.display().to_string())
                .collect(),
            proxy_jump,
            source: seed.source.into(),
            defined_at: seed.defined_at,
            last_used: seed.last_used,
            // Filled from the reachability checks; a proxied host cannot be checked by a connect.
            reachable: if proxied { "unknown".into() } else { String::new() },
            mosh,
            alias: seed.alias,
        });
    }

    let login = login_socket();
    let socket = match agent_setting.as_deref() {
        Some("none") => String::new(),
        Some("SSH_AUTH_SOCK" | "$SSH_AUTH_SOCK") | None => login.to_owned(),
        Some(path) => expand(path).display().to_string(),
    };
    SshHosts { hosts, agent: agent_kind(&socket).into(), agent_socket: socket }
}

/// `~/x` to a path under the home folder.
fn expand(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(path),
    }
}

/// `ssh -G <alias>`: the effective settings, keyword -> values.
fn effective(alias: &str) -> HashMap<String, Vec<String>> {
    let mut set: HashMap<String, Vec<String>> = HashMap::new();
    if alias.starts_with('-') {
        return set;
    }
    let Ok(out) = run("ssh", &["-G", alias], Duration::from_secs(5)) else { return set };
    if !out.ok {
        return set;
    }
    for line in out.stdout.lines() {
        if let Some((key, value)) = line.split_once(' ') {
            set.entry(key.to_owned()).or_default().push(value.trim().to_owned());
        }
    }
    set
}

/// Words of a config line, honouring double quotes.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// Host aliases (no wildcard-only patterns) with `file:line`, following `Include` (globs,
/// relative to `~/.ssh`).
fn read_config(path: &Path, ssh_dir: &Path, depth: u32, out: &mut Vec<(String, String)>) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    if depth > 8 {
        return;
    }
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line.split_once(|c: char| c.is_whitespace() || c == '=').unwrap_or((line, ""));
        let rest = rest.trim().trim_start_matches('=').trim();
        match key.to_ascii_lowercase().as_str() {
            "host" => {
                for pattern in words(rest) {
                    if !pattern.contains(['*', '?', '!']) {
                        out.push((pattern, format!("{}:{}", crate::util::tilde(path), number + 1)));
                    }
                }
            }
            "include" => {
                for arg in words(rest) {
                    let pattern = if arg.starts_with('/') || arg.starts_with("~/") { expand(&arg) } else { ssh_dir.join(&arg) };
                    for file in glob(&pattern) {
                        read_config(&file, ssh_dir, depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// The files a glob pattern names, sorted.
fn glob(pattern: &Path) -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let Ok(pattern) = std::ffi::CString::new(pattern.as_os_str().as_bytes()) else { return Vec::new() };
    let mut found = Vec::new();
    // SAFETY: a zeroed glob_t is the documented initial state; globfree releases what glob fills.
    unsafe {
        let mut matches: libc::glob_t = std::mem::zeroed();
        if libc::glob(pattern.as_ptr(), 0, None, &mut matches) == 0 {
            for i in 0..matches.gl_pathc {
                let entry = *matches.gl_pathv.add(i);
                if !entry.is_null() {
                    found.push(PathBuf::from(std::ffi::OsStr::from_bytes(std::ffi::CStr::from_ptr(entry).to_bytes())));
                }
            }
        }
        libc::globfree(&mut matches);
    }
    found.into_iter().filter(|p| p.is_file()).collect()
}

/// Plain (unhashed) host names in known_hosts, first name of each line.
fn known_hosts(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut names: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') || line.starts_with('|') {
            continue;
        }
        let Some(first) = line.split_whitespace().next().and_then(|field| field.split(',').next()) else { continue };
        let name = first.strip_prefix('[').and_then(|rest| rest.split_once(']')).map(|(host, _)| host).unwrap_or(first);
        if valid_host(name) && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    names
}

fn valid_host(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// `(host, user, last used in Unix ms)` for every `ssh <host>` in the zsh history.
fn history() -> Vec<(String, Option<String>, u64)> {
    let Ok(bytes) = std::fs::read(home().join(".zsh_history")) else { return Vec::new() };
    let text = String::from_utf8_lossy(&bytes);
    let mut seen: HashMap<String, (Option<String>, u64)> = HashMap::new();
    for line in text.lines() {
        // Extended history: `: <start>:<elapsed>;<command>`.
        let (at, command) = match line.strip_prefix(": ").and_then(|rest| rest.split_once(';')) {
            Some((stamp, command)) => (stamp.split(':').next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0) * 1000, command),
            None => (0, line),
        };
        let Some((host, user)) = destination(command.trim()) else { continue };
        let entry = seen.entry(host).or_insert((None, 0));
        if at >= entry.1 {
            *entry = (user.or(entry.0.take()), at);
        }
    }
    seen.into_iter().map(|(host, (user, at))| (host, user, at)).collect()
}

/// The destination of an `ssh ...` command line: host and user.
fn destination(command: &str) -> Option<(String, Option<String>)> {
    let mut args = command.strip_prefix("ssh ")?.split_whitespace();
    let mut user = None;
    while let Some(arg) = args.next() {
        if let Some(flags) = arg.strip_prefix('-') {
            let letter = flags.chars().next()?;
            // Only print or control the configuration, or talk to a master: no destination to keep.
            if matches!(letter, 'G' | 'V' | 'Q' | 'O') {
                return None;
            }
            if "BbcDEeFIiJLlmOoPpQRSWw".contains(letter) {
                let value = if flags.len() > 1 { Some(flags[1..].to_owned()) } else { args.next().map(str::to_owned) };
                if letter == 'l' {
                    user = value;
                }
            }
            continue;
        }
        let target = arg.strip_prefix("ssh://").unwrap_or(arg);
        let (typed_user, host) = match target.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_owned()), h),
            None => (None, target),
        };
        let host = if arg.starts_with("ssh://") { host.split(':').next().unwrap_or(host) } else { host };
        return valid_host(host).then(|| (host.to_owned(), typed_user.or(user)));
    }
    None
}

/// `SSH_AUTH_SOCK` as the user's login shell sets it (asked once), else launchd's, else ours.
fn login_socket() -> &'static str {
    static SOCKET: OnceLock<String> = OnceLock::new();
    SOCKET.get_or_init(|| {
        let shell = std::env::var("SHELL").ok().filter(|s| s.starts_with('/')).unwrap_or_else(|| "/bin/zsh".into());
        let marker = "__CORTEX_SSH_AUTH_SOCK__";
        let script = format!("printf '\\n{marker}%s\\n' \"$SSH_AUTH_SOCK\"");
        let from_shell = run(&shell, &["-ilc", &script], Duration::from_secs(5))
            .ok()
            .and_then(|out| out.stdout.lines().find_map(|l| l.strip_prefix(marker).map(str::to_owned)))
            .filter(|s| !s.is_empty());
        from_shell
            .or_else(|| {
                run("/bin/launchctl", &["getenv", "SSH_AUTH_SOCK"], Duration::from_secs(3))
                    .ok()
                    .map(|out| out.stdout.trim().to_owned())
                    .filter(|s| !s.is_empty())
            })
            .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
            .unwrap_or_default()
    })
}

/// 1password | secretive | macos | other | none
fn agent_kind(socket: &str) -> &'static str {
    if socket.is_empty() || !Path::new(socket).exists() {
        "none"
    } else if socket.contains("2BUA8C4S2C.com.1password") {
        "1password"
    } else if socket.contains("com.maxgoedjen.Secretive") {
        "secretive"
    } else if socket.contains("/com.apple.launchd.") {
        "macos"
    } else {
        "other"
    }
}

/// Group or others may read or write it.
pub fn too_open(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o077 != 0).unwrap_or(false)
}

/// `<bits> <fingerprint> <comment...> (<TYPE>)` from `ssh-keygen -l` and `ssh-add -l`.
fn parse_listing(line: &str) -> Option<(u32, String, String, String)> {
    let mut parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let kind = parts.pop()?.trim_start_matches('(').trim_end_matches(')').to_lowercase();
    let bits = parts[0].parse().ok()?;
    let fingerprint = parts[1].to_owned();
    Some((bits, fingerprint, parts[2..].join(" "), kind))
}

/// The private keys in `~/.ssh`: files with a matching `.pub` or that read as a private key.
pub fn file_keys() -> Vec<SshKey> {
    let dir = home().join(".ssh");
    let Some(keygen) = which("ssh-keygen").map(|k| k.display().to_string()) else { return Vec::new() };
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    paths.sort();
    let candidates: Vec<(PathBuf, PathBuf)> = paths
        .into_iter()
        .filter(|path| path.is_file() && path.extension().is_none_or(|e| e != "pub"))
        .filter_map(|path| {
            let mut public = path.clone().into_os_string();
            public.push(".pub");
            let public = PathBuf::from(public);
            (public.is_file() || looks_private(&path)).then_some((path, public))
        })
        .collect();
    std::thread::scope(|scope| {
        let jobs: Vec<_> = candidates.iter().map(|(path, public)| scope.spawn(|| file_key(&keygen, path, public))).collect();
        jobs.into_iter().filter_map(|job| job.join().ok().flatten()).collect()
    })
}

fn looks_private(path: &Path) -> bool {
    let mut head = [0u8; 64];
    let read = std::fs::File::open(path).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).unwrap_or(0);
    let head = String::from_utf8_lossy(&head[..read]);
    head.starts_with("-----BEGIN") && head.contains("PRIVATE KEY")
}

fn file_key(keygen: &str, path: &Path, public: &Path) -> Option<SshKey> {
    let target = if public.is_file() { public } else { path };
    let out = run(keygen, &["-l", "-f", &target.display().to_string()], Duration::from_secs(10)).ok().filter(|o| o.ok)?;
    let (bits, fingerprint, comment, kind) = parse_listing(out.stdout.lines().next()?)?;
    // Deriving the public key with an empty passphrase works only when the key has none. Its
    // output (the public key) is dropped.
    let passphrase = match run(keygen, &["-y", "-P", "", "-f", &path.display().to_string()], Duration::from_secs(10)) {
        Ok(out) if out.ok => Some(false),
        Ok(out) if out.stderr.to_lowercase().contains("passphrase") => Some(true),
        _ => None,
    };
    let mut key = SshKey { path: path.display().to_string(), kind, bits, fingerprint, comment, passphrase, ..Default::default() };
    grade(&mut key, too_open(path));
    Some(key)
}

/// The keys the agent at `socket` holds, as agent-only keys (`agent:<comment>`).
fn agent_keys(socket: &str) -> Vec<SshKey> {
    if socket.is_empty() {
        return Vec::new();
    }
    let Ok(out) = run_env("ssh-add", &["-l"], &[("SSH_AUTH_SOCK", socket)], Duration::from_secs(5)) else { return Vec::new() };
    if !out.ok {
        return Vec::new();
    }
    out.stdout
        .lines()
        .filter_map(parse_listing)
        .map(|(bits, fingerprint, comment, kind)| {
            let mut key =
                SshKey { path: format!("agent:{comment}"), kind, bits, fingerprint, comment, in_agent: true, ..Default::default() };
            grade(&mut key, false);
            key
        })
        .collect()
}

/// bad: DSA, RSA under 2048 bits. weak: RSA under 3072 bits, no passphrase, readable by others.
fn grade(key: &mut SshKey, open: bool) {
    let (mut bad, mut weak) = (false, false);
    match key.kind.as_str() {
        "dsa" => {
            bad = true;
            key.notes.push("DSA is broken and refused by current OpenSSH".into());
        }
        "rsa" if key.bits < 2048 => {
            bad = true;
            key.notes.push(format!("RSA {} bits is too short", key.bits));
        }
        "rsa" if key.bits < 3072 => {
            weak = true;
            key.notes.push(format!("RSA {} bits; 3072 or Ed25519 is recommended", key.bits));
        }
        _ => {}
    }
    // A security key's file is only a handle; it needs the device, not a passphrase.
    if key.passphrase == Some(false) && !key.kind.ends_with("-sk") {
        weak = true;
        key.notes.push("no passphrase".into());
    }
    if open {
        weak = true;
        key.notes.push("other users can read it (chmod 600)".into());
    }
    key.health = if bad { "bad" } else if weak { "weak" } else { "good" }.into();
}

/// This machine's host name and interface addresses: what an `ssh` to it would name.
pub fn addresses() -> Addresses {
    let mut name = [0u8; 256];
    // gethostname writes at most `len` bytes into the buffer it is given.
    let hostname = if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } == 0 {
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        String::from_utf8_lossy(&name[..end]).into_owned()
    } else {
        String::new()
    };
    let addresses = crate::protection_sensors::local_addresses().iter().map(|ip| ip.to_string()).collect();
    Addresses { hostname, addresses }
}
