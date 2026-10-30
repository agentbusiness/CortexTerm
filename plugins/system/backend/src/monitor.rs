//! Monitor mode: one process's files and network, watched without sudo. Every 2 s its open files
//! and sockets are read (`lsof`, the process and, when asked, its children); what came and went
//! is logged, condensed into hosts, folders and listening ports, and a few rules note what is
//! worth a look (secrets read, raw IPs on odd ports, persistence written, and what every Mac
//! stealer does in its first minute: a program that is not the browser opening browser passwords,
//! the keychain or wallets, and command lines that ask for or test the login password, read the
//! keychain or upload a zip from /tmp). The model is shown the
//! condensed report when asked to review it; it explains, it never decides.
//!
//! Without sudo nothing sees a file opened and closed between two reads; the report says it is
//! a sample, not a trace.

use crate::procs::Snapshot;
use crate::util::{home, now_ms};
use cc_protocol::contracts::system::{MonitorEvent, MonitorFolder, MonitorHost, MonitorReport, OpenFile};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

const EVENTS: usize = 500;
/// Stop on its own after an hour; the log stays.
const MAX_MS: u64 = 60 * 60 * 1000;

pub struct Monitor {
    pub report: MonitorReport,
    events: VecDeque<MonitorEvent>,
    open: HashMap<String, (u32, OpenFile)>,
    hosts: BTreeMap<String, MonitorHost>,
    folders: BTreeMap<String, (BTreeSet<String>, bool)>,
    listening: BTreeSet<String>,
    flagged: HashSet<String>,
    first: bool,
    /// pid -> its program's path, read once when the pid is first seen.
    programs: HashMap<u32, String>,
}

impl Monitor {
    pub fn new(pid: u32, children: bool) -> Self {
        Monitor {
            report: MonitorReport { pid, on: true, children, started: now_ms(), ..Default::default() },
            events: VecDeque::new(),
            open: HashMap::new(),
            hosts: BTreeMap::new(),
            folders: BTreeMap::new(),
            listening: BTreeSet::new(),
            flagged: HashSet::new(),
            first: true,
            programs: HashMap::new(),
        }
    }

    /// The pids to read this time: the process, and its descendants when asked.
    pub fn pids(&self, snapshot: &Snapshot) -> Vec<u32> {
        let root = self.report.pid;
        let mut pids = vec![root];
        if self.report.children {
            let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
            for entry in &snapshot.entries {
                kids.entry(entry.proc.ppid).or_default().push(entry.proc.pid);
            }
            let mut at = 0;
            while at < pids.len() && pids.len() < 64 {
                if let Some(list) = kids.get(&pids[at]) {
                    pids.extend(list.iter().copied().filter(|pid| *pid != root));
                }
                at += 1;
            }
        }
        pids
    }

    /// Fold one read in: what is open now against what was open before.
    pub fn poll(&mut self, read: HashMap<u32, Vec<OpenFile>>) {
        let at = now_ms();
        self.report.polls += 1;
        if !read.contains_key(&self.report.pid) {
            self.report.failed += 1;
        }
        let new: Vec<u32> = read.keys().copied().filter(|pid| !self.programs.contains_key(pid)).collect();
        self.meet(&new);
        let mut now: HashMap<String, (u32, OpenFile)> = HashMap::new();
        for (pid, files) in read {
            for file in files {
                // The program's own mappings and the root folder say nothing new.
                if !(file.fd.chars().all(|c| c.is_ascii_digit()) || file.fd == "cwd") {
                    continue;
                }
                now.insert(format!("{pid}|{}|{}|{}", file.fd, file.kind, file.name), (pid, file));
            }
        }
        let opened: Vec<(u32, OpenFile)> = now.iter().filter(|(key, _)| !self.open.contains_key(*key)).map(|(_, v)| v.clone()).collect();
        let closed: Vec<(u32, OpenFile)> = self.open.iter().filter(|(key, _)| !now.contains_key(*key)).map(|(_, v)| v.clone()).collect();
        for (pid, file) in opened {
            self.learn(at, pid, &file);
            self.push(MonitorEvent { at, pid, change: "open".into(), file });
        }
        if !self.first {
            for (pid, file) in closed {
                self.push(MonitorEvent { at, pid, change: "close".into(), file });
            }
        }
        self.first = false;
        self.open = now;
        if at.saturating_sub(self.report.started) > MAX_MS {
            self.stop("Stopped on its own after an hour.");
        }
        self.publish();
    }

    pub fn stop(&mut self, why: &str) {
        if self.report.on {
            self.report.on = false;
            self.report.stopped = Some(now_ms());
            if !why.is_empty() {
                self.report.flags.push(why.to_owned());
            }
        }
    }

    fn push(&mut self, event: MonitorEvent) {
        self.report.total_events += 1;
        self.events.push_back(event);
        while self.events.len() > EVENTS {
            self.events.pop_front();
        }
    }

    fn publish(&mut self) {
        self.report.events = self.events.iter().cloned().collect();
        let mut hosts: Vec<MonitorHost> = self.hosts.values().cloned().collect();
        hosts.sort_by(|a, b| b.connections.cmp(&a.connections).then(a.address.cmp(&b.address)));
        self.report.hosts = hosts;
        let mut folders: Vec<MonitorFolder> = self
            .folders
            .iter()
            .map(|(folder, (files, written))| MonitorFolder {
                folder: folder.clone(),
                files: files.len() as u32,
                written: *written,
                sample: files.iter().take(4).cloned().collect(),
            })
            .collect();
        folders.sort_by(|a, b| b.written.cmp(&a.written).then(b.files.cmp(&a.files)));
        self.report.folders = folders;
        self.report.listening = self.listening.iter().cloned().collect();
    }

    /// Count a newly opened file or socket, and check it against the rules.
    fn learn(&mut self, at: u64, pid: u32, file: &OpenFile) {
        match file.kind.as_str() {
            "tcp" | "udp" => {
                if file.state == "LISTEN" {
                    if self.listening.insert(file.name.clone()) && file.name.starts_with('*') {
                        let port = file.name.rsplit(':').next().unwrap_or("");
                        self.flag(format!("Listens on every network interface at :{port}, so other machines on the network can reach it."));
                    }
                    return;
                }
                let Some((_, remote)) = file.name.split_once("->") else { return };
                let host = self.hosts.entry(remote.to_owned()).or_insert_with(|| MonitorHost {
                    address: remote.to_owned(),
                    kind: file.kind.clone(),
                    first: at,
                    ..Default::default()
                });
                host.connections += 1;
                host.last = at;
                let (ip, port) = split_host(remote);
                if !private(ip) && !COMMON_PORTS.contains(&port) {
                    self.flag(format!("Connects to the public address {ip} on port {port}, which is not a usual web, mail or DNS port."));
                }
                let public = self.hosts.keys().filter(|address| !private(split_host(address).0)).map(|address| split_host(address).0).collect::<HashSet<_>>().len();
                if public == 25 {
                    self.flag("Has talked to 25 or more public addresses.".into());
                }
            }
            "file" | "dir" => {
                let path = file.name.as_str();
                let written = file.mode.contains('w') || file.mode.contains('u');
                let folder = std::path::Path::new(path).parent().map(|p| p.display().to_string()).unwrap_or_default();
                let entry = self.folders.entry(folder).or_default();
                entry.0.insert(path.to_owned());
                entry.1 |= written;
                let home = home().display().to_string();
                let short = path.strip_prefix(&home).map(|rest| format!("~{rest}")).unwrap_or_else(|| path.to_owned());
                if let Some(what) = SECRETS.iter().find(|(needle, _)| short.contains(needle)).map(|(_, what)| *what) {
                    self.flag(format!("Opened {short} ({what})."));
                }
                let program = self.programs.get(&pid).cloned().unwrap_or_default();
                if let Some((_, what, owners)) = STOLEN.iter().find(|(needle, _, _)| path.contains(needle))
                    && !owners.iter().any(|owner| program.contains(owner))
                {
                    let name = program.rsplit('/').next().filter(|n| !n.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("pid {pid}"));
                    self.flag(format!("{name}, which is not the app that owns it, opened {short} ({what}): this is what password and wallet stealers do."));
                }
                if written && let Some(what) = PERSISTENCE.iter().find(|(needle, _)| short.contains(needle)).map(|(_, what)| *what) {
                    self.flag(format!("Wrote {short} ({what})."));
                }
                if written && !path.starts_with(&home) && !TEMP.iter().any(|prefix| path.starts_with(prefix)) && !path.starts_with("/dev/") {
                    self.flag(format!("Wrote outside your home folder: {path}."));
                }
            }
            _ => {}
        }
    }

    /// Read the program and command line of newly seen pids once, and check the command line.
    fn meet(&mut self, pids: &[u32]) {
        if pids.is_empty() {
            return;
        }
        let list: Vec<sysinfo::Pid> = pids.iter().map(|pid| sysinfo::Pid::from_u32(*pid)).collect();
        let mut sys = sysinfo::System::new();
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&list),
            false,
            sysinfo::ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always).with_cmd(sysinfo::UpdateKind::Always),
        );
        for pid in pids {
            let process = sys.process(sysinfo::Pid::from_u32(*pid));
            let exe = process.and_then(|p| p.exe()).map(|p| p.display().to_string()).unwrap_or_default();
            let command = process.map(|p| p.cmd().iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
            self.programs.insert(*pid, exe);
            for (re, what) in commands() {
                if re.is_match(&command) {
                    self.flag(format!("pid {pid} {what}: {}", crate::util::shorten(&command, 160)));
                }
            }
        }
    }

    fn flag(&mut self, text: String) {
        if self.flagged.insert(text.clone()) && self.report.flags.len() < 40 {
            self.report.flags.push(text);
        }
    }
}

const COMMON_PORTS: [&str; 12] = ["80", "443", "53", "22", "853", "993", "587", "465", "5223", "123", "8443", "3478"];
const TEMP: [&str; 5] = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/", "/opt/homebrew/var/"];

/// Where secrets live, and what they are.
const SECRETS: [(&str, &str); 14] = [
    ("~/.ssh/id_", "an SSH private key"),
    ("/Library/Keychains/", "the keychain"),
    ("~/.aws/credentials", "AWS credentials"),
    ("~/.config/gcloud/", "Google Cloud credentials"),
    ("~/.kube/config", "Kubernetes credentials"),
    ("~/.netrc", "saved logins"),
    ("~/.docker/config.json", "Docker registry logins"),
    ("~/.gnupg/", "GPG keys"),
    ("/Google/Chrome/", "Chrome profile data"),
    ("/Firefox/Profiles/", "Firefox profile data"),
    ("~/Library/Cookies/", "browser cookies"),
    ("~/Library/Safari/", "Safari data"),
    ("~/Library/Messages/", "Messages"),
    ("~/Library/Mail/", "Mail"),
];

/// Browsers: they may open their own password and cookie stores.
const BROWSERS: [&str; 11] =
    ["Google Chrome", "Chromium", "Safari", "WebKit", "Firefox", "Brave Browser", "Microsoft Edge", "Arc.app", "Opera", "Vivaldi", "Orion"];

/// What stealers take, what it is, and the programs that may open it themselves.
const STOLEN: [(&str, &str, &[&str]); 19] = [
    ("/Login Data", "saved browser passwords", &BROWSERS),
    ("/Cookies", "browser cookies", &BROWSERS),
    ("/Local State", "the key to the browser's saved passwords", &BROWSERS),
    ("/logins.json", "Firefox's saved passwords", &BROWSERS),
    ("/key4.db", "the key to Firefox's saved passwords", &BROWSERS),
    ("Cookies.binarycookies", "Safari cookies", &["Safari", "WebKit", "/System/", "/usr/libexec/"]),
    ("login.keychain-db", "the login keychain", &["/System/", "/usr/libexec/", "/usr/sbin/"]),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "the MetaMask wallet", &BROWSERS),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "the Phantom wallet", &BROWSERS),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "the Trust Wallet", &BROWSERS),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "the Coinbase wallet", &BROWSERS),
    ("/Exodus/exodus.wallet", "the Exodus wallet", &["Exodus.app"]),
    ("/Electrum/wallets", "Electrum wallets", &["Electrum.app"]),
    ("/atomic/Local Storage", "the Atomic wallet", &["Atomic Wallet.app"]),
    ("/Ledger Live/", "Ledger Live data", &["Ledger Live.app"]),
    ("/Coinomi/", "the Coinomi wallet", &["Coinomi.app"]),
    ("group.com.apple.notes", "your Notes", &["Notes.app", "/System/", "/usr/libexec/"]),
    ("/Telegram Desktop/tdata", "Telegram's login session", &["Telegram.app"]),
    ("ru.keepcoder.Telegram", "Telegram's login session", &["Telegram.app"]),
];

/// Command lines that do what stealers do, and what that is.
fn commands() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"(?i)osascript.*(hidden answer|display dialog.*password)", "shows a dialog that asks for your password"),
            (r"dscl\s.*-authonly", "tests a password against your account (dscl -authonly)"),
            (r"security\s+(find-generic-password|find-internet-password)\b.*\s-w\b|security\s+dump-keychain", "reads passwords out of the keychain"),
            (r"curl\s.*(-F|--form|-d|--data[a-z-]*|-T|--upload-file|-X\s*POST)\s.*(/private)?/tmp/\S*\.zip", "uploads a zip file from /tmp"),
        ]
        .into_iter()
        .filter_map(|(pattern, what)| Regex::new(pattern).ok().map(|re| (re, what)))
        .collect()
    })
}

/// What runs again later when written.
const PERSISTENCE: [(&str, &str); 7] = [
    ("/LaunchAgents/", "a launch agent: starts at login"),
    ("/LaunchDaemons/", "a launch daemon: starts at boot"),
    ("~/.zshrc", "runs in every new shell"),
    ("~/.zprofile", "runs at login"),
    ("~/.bash_profile", "runs at login"),
    ("~/.bashrc", "runs in every new shell"),
    ("/etc/", "system configuration"),
];

/// `1.2.3.4:443` / `[::1]:80` -> (host, port).
fn split_host(address: &str) -> (&str, &str) {
    match address.rsplit_once(':') {
        Some((host, port)) => (host.trim_start_matches('[').trim_end_matches(']'), port),
        None => (address, ""),
    }
}

fn private(ip: &str) -> bool {
    if let Ok(ip) = ip.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
    }
    ip == "localhost" || ip == "*"
}
