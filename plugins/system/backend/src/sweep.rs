//! The workstation security sweep. Every check has a time limit; a missing tool is reported in
//! `skipped` with why. Fixes are only ever offered as commands, never run. Secret scans report
//! counts, never the text.

use crate::{agents, graph, intrusion, inventory, launch, malware, netsec, persist, posture, privacy, ssh};
use crate::util::{home, local_time, now_ms, plural, run, tilde, which};
use cc_protocol::BoxFuture;
use cc_protocol::contracts::system::{Finding, SweepReport};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub const LIMIT: Duration = Duration::from_secs(60);

/// One group of checks' result; every check module returns one and the sweep merges them.
/// `graph` is what the checks saw of this Mac (apps, packages, settings, start items …), written
/// with the sweep so each finding can point at the node it is about.
#[derive(Default)]
pub struct Part {
    pub findings: Vec<Finding>,
    pub checked: Vec<String>,
    pub skipped: Vec<String>,
    pub graph: graph::Batch,
    /// Per finding: how many checks were named when it was added (its check is `checked[n-1]`).
    pub at_check: Vec<usize>,
}

impl Part {
    pub fn add(&mut self, severity: &str, kind: &str, text: String, fix: Option<String>, source: &str) {
        let key = format!("{kind}:{text}");
        self.at_check.push(self.checked.len());
        self.findings.push(Finding { severity: severity.into(), kind: kind.into(), text, fix, source: source.into(), key, ignored: false, about: None });
    }

    /// The last finding added is about this node (which `graph` or the graph already holds).
    pub fn about(&mut self, label: &str, key: impl Into<String>) {
        if let Some(finding) = self.findings.last_mut() {
            finding.about = Some((label.to_owned(), key.into()));
        }
    }

    pub fn merge(&mut self, other: Part) {
        let offset = self.checked.len();
        self.at_check.extend(other.at_check.iter().map(|n| if *n == 0 { 0 } else { n + offset }));
        self.findings.extend(other.findings);
        self.checked.extend(other.checked);
        self.skipped.extend(other.skipped);
        self.graph.extend(other.graph);
    }
}

/// A global tool to look up in OSV.
pub struct Package {
    pub ecosystem: &'static str,
    pub manager: &'static str,
    pub name: String,
    pub version: String,
    pub fix: String,
}

pub fn severity_of(text: &str) -> &'static str {
    match text.to_ascii_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "high",
        "MEDIUM" | "MODERATE" => "medium",
        "LOW" => "low",
        _ => "medium",
    }
}

pub fn rank(severity: &str) -> u8 {
    match severity {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn ids_text(ids: &[String]) -> String {
    let mut text = ids.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    if ids.len() > 3 {
        text.push_str(&format!(" and {} more", ids.len() - 3));
    }
    text
}

async fn blocking(f: fn() -> Part) -> Part {
    tokio::task::spawn_blocking(f).await.unwrap_or_default()
}

/// The parts of the sweep a check can ask for by name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    Settings,
    Updates,
    Apps,
    Packages,
    Malware,
    Persistence,
    Privacy,
    Intrusion,
    Network,
    Agents,
    Ssh,
    Secrets,
}

use Area::*;

impl Area {
    pub const ALL: [Area; 12] = [Settings, Updates, Apps, Packages, Malware, Persistence, Privacy, Intrusion, Network, Agents, Ssh, Secrets];

    pub fn name(self) -> &'static str {
        match self {
            Settings => "settings",
            Updates => "updates",
            Apps => "apps",
            Packages => "packages",
            Malware => "malware",
            Persistence => "persistence",
            Privacy => "privacy",
            Intrusion => "intrusion",
            Network => "network",
            Agents => "agents",
            Ssh => "ssh",
            Secrets => "secrets",
        }
    }

    /// What it covers, in one line.
    pub fn about(self) -> &'static str {
        match self {
            Settings => "Mac settings: FileVault, firewall, SIP, Gatekeeper, screen lock, sharing, profiles, sudo",
            Updates => "macOS and Safari patch level, apps out of date, runtimes past end of life",
            Apps => "everything in updates, plus app signatures, dylib hijacking, browser and editor extensions, Docker images",
            Packages => "Homebrew vulnerabilities and outdated packages, global npm/pipx/cargo tools and project lockfiles in OSV",
            Malware => "YARA scan with Apple's XProtect and CortexTerm's rules, recent downloads, known campaigns",
            Persistence => "what starts by itself: launch agents and daemons, login items, changes since the last sweep",
            Privacy => "camera, microphone, screen recording and keyboard access; who is listening now",
            Intrusion => "the system log: logins, sudo, new users, remote sessions",
            Network => "this network: router, DNS, Wi-Fi, devices, UPnP, internet exposure, the network watcher's notes",
            Agents => "AI agents: permission prompts off, MCP servers and their secrets, skills and instruction files",
            Ssh => "SSH keys: strength, passphrase, permissions",
            Secrets => "secrets in shell history, credentials in config files and projects' .env files",
        }
    }

    pub fn aliases(self) -> &'static [&'static str] {
        match self {
            Settings => &["mac", "posture", "firewall", "filevault", "gatekeeper", "sip", "setting"],
            Updates => &["update", "patch", "patches", "outdated", "softwareupdate"],
            Apps => &["app", "applications", "software", "inventory", "extensions"],
            Packages => &["package", "deps", "dependencies", "brew", "homebrew", "npm", "pip", "pipx", "cargo", "lockfiles", "osv"],
            Malware => &["virus", "viruses", "yara", "xprotect", "stealer", "stealers"],
            Persistence => &["launch", "launchagents", "login-items", "autostart", "startup"],
            Privacy => &["tcc", "camera", "microphone", "keylogger", "permissions"],
            Intrusion => &["intrusions", "logs", "log", "logins"],
            Network => &["net", "lan", "wifi", "wi-fi", "dns", "vpn", "router"],
            Agents => &["agent", "ai", "mcp", "skills"],
            Ssh => &["ssh-keys", "keys"],
            Secrets => &["secret", "credentials", "history", "tokens", "env"],
        }
    }

    /// Area names or aliases, any case; `all` is every area. Unknown names are an error.
    pub fn parse(names: &[String]) -> Result<Vec<Area>, String> {
        let mut areas = Vec::new();
        let mut unknown = Vec::new();
        for name in names.iter().flat_map(|n| n.split(',')).map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()) {
            let found: Vec<Area> = if matches!(name.as_str(), "all" | "everything" | "sweep") {
                Area::ALL.to_vec()
            } else {
                Area::ALL.into_iter().filter(|a| a.name() == name || a.aliases().contains(&name.as_str())).take(1).collect()
            };
            if found.is_empty() {
                unknown.push(name);
            }
            for area in found {
                if !areas.contains(&area) {
                    areas.push(area);
                }
            }
        }
        if !unknown.is_empty() {
            return Err(format!("unknown area {}; the areas are {} or all", unknown.join(", "), Area::ALL.map(Area::name).join(", ")));
        }
        if areas.is_empty() {
            return Err(format!("which areas: {} or all", Area::ALL.map(Area::name).join(", ")));
        }
        Ok(areas)
    }

    /// The area a finding comes from: its kind, and its source where kinds are shared.
    pub fn of(finding: &Finding) -> Area {
        match finding.kind.as_str() {
            "posture" => Settings,
            "secret" => Secrets,
            "ssh" => Ssh,
            "network" | "lan" => Network,
            "malware" => Malware,
            "persistence" => Persistence,
            "privacy" => Privacy,
            "intrusion" => Intrusion,
            "agent" => Agents,
            _ => match finding.source.as_str() {
                "brew vulns" | "brew outdated" | "osv" => Packages,
                "SOFA" | "app versions" | "vendor versions" | "electron" | "endoflife.date" => Updates,
                _ => Apps,
            },
        }
    }

    /// The findings this area reports (`apps` includes `updates`).
    pub fn covers(self, finding: &Finding) -> bool {
        let of = Area::of(finding);
        of == self || (self == Apps && of == Updates)
    }
}

/// Run the whole sweep: its report, and what it saw of this Mac for the graph.
pub async fn run_sweep() -> (SweepReport, graph::Batch) {
    run_areas(&Area::ALL, None, &SweepReport::default()).await
}

/// Run the checks of some areas, each group of checks side by side. With `within`, a group that
/// has not finished by then contributes `last`'s findings for its areas instead (when there is a
/// `last`), and `checked` says so. Also what the checks saw of this Mac, as graph units.
pub async fn run_areas(areas: &[Area], within: Option<Duration>, last: &SweepReport) -> (SweepReport, graph::Batch) {
    let started = Instant::now();
    let has = |area: Area| areas.contains(&area);
    let scope = inventory::Scope { updates: has(Updates) || has(Apps), apps: has(Apps), deps: has(Packages), secrets: has(Secrets) };
    let mut groups: Vec<(Vec<Area>, BoxFuture<'static, Part>)> = Vec::new();
    let mut group = |area: Area, work: BoxFuture<'static, Part>| {
        if has(area) {
            groups.push((vec![area], work));
        }
    };
    group(Packages, Box::pin(packages()));
    group(Settings, Box::pin(blocking(posture::checks)));
    group(Network, Box::pin(netsec::checks()));
    group(Malware, Box::pin(blocking(malware::checks)));
    group(Persistence, Box::pin(async { merged(tokio::join!(blocking(persist::checks), blocking(launch_checks))) }));
    group(Privacy, Box::pin(blocking(privacy::checks)));
    group(Intrusion, Box::pin(blocking(intrusion::checks)));
    group(Agents, Box::pin(blocking(agents::checks)));
    group(Ssh, Box::pin(blocking(ssh_checks)));
    group(Secrets, Box::pin(blocking(history_checks)));
    // One inventory run serves every area that needs it.
    if scope.any() {
        let served = areas.iter().copied().filter(|a| matches!(a, Updates | Apps | Packages | Secrets)).collect();
        groups.insert(groups.len().min(1), (served, Box::pin(inventory::checks(scope))));
    }

    let deadline = within.map(|d| tokio::time::Instant::now() + d);
    let mut tasks = tokio::task::JoinSet::new();
    let mut served: Vec<Vec<Area>> = Vec::new();
    for (i, (group_areas, work)) in groups.into_iter().enumerate() {
        served.push(group_areas);
        tasks.spawn(async move {
            let part = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, work).await.ok(),
                None => Some(work.await),
            };
            (i, part)
        });
    }
    let mut parts: Vec<Option<Part>> = served.iter().map(|_| None).collect();
    while let Some(done) = tasks.join_next().await {
        if let Ok((i, part)) = done {
            parts[i] = part;
        }
    }

    let mut all = Part::default();
    let mut late: Vec<Area> = Vec::new();
    for (i, part) in parts.into_iter().enumerate() {
        match part {
            Some(part) => all.merge(part),
            None => {
                for area in &served[i] {
                    if !late.contains(area) {
                        late.push(*area);
                    }
                }
            }
        }
    }
    let seconds = within.map(|d| d.as_secs()).unwrap_or(0);
    for area in &late {
        let name = area.name();
        if last.at == 0 {
            all.skipped.push(format!("{name}: did not finish within {seconds} s and there is no earlier sweep to fall back on (run `macsec check {name} --full`)"));
        } else {
            all.checked.push(format!(
                "{name}: from the sweep of {} (a fresh run takes longer; run `macsec check {name} --full`)",
                local_time(last.at)
            ));
        }
    }
    if last.at != 0 {
        all.findings.extend(last.findings.iter().filter(|f| late.iter().any(|a| a.covers(f))).cloned());
    }
    all.findings.sort_by_key(|f| rank(&f.severity));
    let report = SweepReport {
        at: now_ms(),
        duration_ms: started.elapsed().as_millis() as u64,
        findings: all.findings,
        checked: all.checked,
        skipped: all.skipped,
    };
    (report, all.graph)
}

fn merged((a, b): (Part, Part)) -> Part {
    let mut part = a;
    part.merge(b);
    part
}

/// The report with the findings in `ignored` marked (older reports get their keys here).
pub fn mark(mut report: SweepReport, ignored: &[String]) -> SweepReport {
    for finding in &mut report.findings {
        if finding.key.is_empty() {
            finding.key = format!("{}:{}", finding.kind, finding.text);
        }
        finding.ignored = ignored.contains(&finding.key);
    }
    report
}

/// Homebrew (vulns and outdated), and the global npm, pipx and cargo tools in OSV.
async fn packages() -> Part {
    let (brew, tools) = tokio::join!(blocking(brew_checks), tokio::task::spawn_blocking(global_tools));
    let mut all = brew;
    if let Ok((part, packages)) = tools {
        all.merge(part);
        if !packages.is_empty() {
            let osv = match tokio::time::timeout(LIMIT, osv(&packages)).await {
                Ok(Ok(part)) => part,
                Ok(Err(error)) => Part { skipped: vec![format!("OSV lookup of global tools: {error}")], ..Default::default() },
                Err(_) => Part { skipped: vec!["OSV lookup of global tools: no answer within 60 s".into()], ..Default::default() },
            };
            all.merge(osv);
        }
    }
    all
}

fn brew_checks() -> Part {
    let mut part = Part::default();
    let Some(brew) = which("brew") else {
        part.skipped.push("brew vulns: Homebrew is not installed".into());
        part.skipped.push("brew outdated: Homebrew is not installed".into());
        return part;
    };
    let brew = brew.display().to_string();
    let (formulae, casks) = inventory::homebrew();
    part.graph.extend(inventory::homebrew_graph(&formulae, &casks));

    match run(&brew, &["vulns", "--help"], Duration::from_secs(30)) {
        Ok(out) if out.ok => match run(&brew, &["vulns", "--json"], Duration::from_secs(120)) {
            Ok(out) => match serde_json::from_str::<Value>(&out.stdout) {
                Ok(report) => {
                    part.checked.push("brew vulns".into());
                    brew_vulns(&mut part, &report);
                }
                Err(_) => {
                    part.skipped.push(format!("brew vulns: unreadable output ({})", out.stderr.lines().last().unwrap_or("no message")))
                }
            },
            Err(error) => part.skipped.push(format!("brew vulns: {error}")),
        },
        _ => part.skipped.push("brew vulns: this Homebrew has no vulns command (brew update adds it)".into()),
    }

    match run(&brew, &["outdated", "--json=v2"], LIMIT) {
        Ok(out) => match serde_json::from_str::<Value>(&out.stdout) {
            Ok(report) => {
                part.checked.push("brew outdated".into());
                let names: Vec<String> = ["formulae", "casks"]
                    .iter()
                    .filter_map(|key| report.get(*key).and_then(Value::as_array))
                    .flatten()
                    .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect();
                if !names.is_empty() {
                    let mut list = names.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
                    if names.len() > 10 {
                        list.push_str(&format!(" and {} more", names.len() - 10));
                    }
                    part.add(
                        "info",
                        "outdated",
                        format!("{} out of date: {list}.", plural(names.len(), "Homebrew package is", "Homebrew packages are")),
                        Some("brew upgrade".into()),
                        "brew outdated",
                    );
                }
            }
            Err(_) => part.skipped.push("brew outdated: unreadable output".into()),
        },
        Err(error) => part.skipped.push(format!("brew outdated: {error}")),
    }
    part
}

/// One finding per formula, rated by its worst vulnerability.
fn brew_vulns(part: &mut Part, report: &Value) {
    for item in report.get("findings").and_then(Value::as_array).into_iter().flatten() {
        let formula = item.get("formula").and_then(Value::as_str).unwrap_or("");
        if formula.is_empty() {
            continue;
        }
        let version = item.get("version").and_then(Value::as_str).unwrap_or("");
        let vulns: Vec<&Value> = item.get("vulnerabilities").and_then(Value::as_array).into_iter().flatten().collect();
        if vulns.is_empty() {
            continue;
        }
        let ids: Vec<String> = vulns.iter().filter_map(|v| v.get("id").and_then(Value::as_str).map(str::to_owned)).collect();
        let worst = vulns
            .iter()
            .map(|v| severity_of(v.get("severity").and_then(Value::as_str).unwrap_or("")))
            .min_by_key(|s| rank(s))
            .unwrap_or("medium");
        let fixed = vulns.iter().any(|v| v.get("fixed_versions").and_then(Value::as_array).is_some_and(|a| !a.is_empty()));
        part.add(
            worst,
            "vuln",
            format!(
                "{formula} {version} has {} ({}){}.",
                plural(ids.len(), "known vulnerability", "known vulnerabilities"),
                ids_text(&ids),
                if fixed { "; a fixed version is available" } else { "; no fixed release yet" }
            ),
            fixed.then(|| format!("brew upgrade {formula}")),
            "brew vulns",
        );
        part.about("Formula", formula);
    }
}

/// Globally installed npm, pipx and cargo tools. Blocking.
pub fn global_tools() -> (Part, Vec<Package>) {
    let mut part = Part::default();
    let mut packages = Vec::new();
    match which("npm") {
        None => part.skipped.push("global npm tools: npm is not installed".into()),
        Some(npm) => match run(&npm.display().to_string(), &["ls", "-g", "--json", "--depth=0"], LIMIT) {
            Ok(out) => match serde_json::from_str::<Value>(&out.stdout) {
                Ok(tree) => {
                    part.checked.push("global npm tools (OSV)".into());
                    for (name, info) in tree.get("dependencies").and_then(Value::as_object).into_iter().flatten() {
                        if let Some(version) = info.get("version").and_then(Value::as_str) {
                            packages.push(Package {
                                ecosystem: "npm",
                                manager: "npm",
                                name: name.clone(),
                                version: version.to_owned(),
                                fix: format!("npm install -g {name}@latest"),
                            });
                        }
                    }
                }
                Err(_) => part.skipped.push("global npm tools: unreadable npm output".into()),
            },
            Err(error) => part.skipped.push(format!("global npm tools: {error}")),
        },
    }
    match which("pipx") {
        None => part.skipped.push("pipx tools: pipx is not installed".into()),
        Some(pipx) => match run(&pipx.display().to_string(), &["list", "--json"], LIMIT) {
            Ok(out) => match serde_json::from_str::<Value>(&out.stdout) {
                Ok(list) => {
                    part.checked.push("pipx tools (OSV)".into());
                    for venv in list.get("venvs").and_then(Value::as_object).into_iter().flat_map(|m| m.values()) {
                        let main = &venv["metadata"]["main_package"];
                        if let (Some(name), Some(version)) =
                            (main.get("package").and_then(Value::as_str), main.get("package_version").and_then(Value::as_str))
                        {
                            packages.push(Package {
                                ecosystem: "PyPI",
                                manager: "pipx",
                                name: name.to_owned(),
                                version: version.to_owned(),
                                fix: format!("pipx upgrade {name}"),
                            });
                        }
                    }
                }
                Err(_) => part.skipped.push("pipx tools: unreadable pipx output".into()),
            },
            Err(error) => part.skipped.push(format!("pipx tools: {error}")),
        },
    }
    // cargo install keeps its list in ~/.cargo/.crates2.json: "name version (source)" keys.
    match std::fs::read(home().join(".cargo/.crates2.json")).map(|b| serde_json::from_slice::<Value>(&b)) {
        Ok(Ok(list)) => {
            part.checked.push("cargo tools (OSV)".into());
            for key in list["installs"].as_object().into_iter().flat_map(|m| m.keys()) {
                let mut words = key.split(' ');
                if let (Some(name), Some(version), Some(source)) = (words.next(), words.next(), words.next())
                    && source.contains("registry+")
                {
                    packages.push(Package {
                        ecosystem: "crates.io",
                        manager: "cargo",
                        name: name.to_owned(),
                        version: version.to_owned(),
                        fix: format!("cargo install {name}"),
                    });
                }
            }
        }
        Ok(Err(_)) => part.skipped.push("cargo tools: unreadable ~/.cargo/.crates2.json".into()),
        Err(_) => part.skipped.push("cargo tools: nothing installed with cargo install".into()),
    }
    part.graph.extend(inventory::tools_graph(&packages));
    (part, packages)
}

/// Look the tools up in OSV (one batch query, then the details of each hit for its severity).
async fn osv(packages: &[Package]) -> Result<Part, String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| e.to_string())?;
    let queries: Vec<Value> =
        packages.iter().map(|p| json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version})).collect();
    let body = serde_json::to_vec(&json!({"queries": queries})).map_err(|e| e.to_string())?;
    let response = client
        .post("https://api.osv.dev/v1/querybatch")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("api.osv.dev: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("api.osv.dev answered {}", response.status()));
    }
    let answer = json_of(response).await?;
    let mut part = Part::default();
    let mut details_left = 40;
    for (package, result) in packages.iter().zip(answer.get("results").and_then(Value::as_array).into_iter().flatten()) {
        let ids: Vec<String> = result
            .get("vulns")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v["id"].as_str().map(str::to_owned))
            .collect();
        if ids.is_empty() {
            continue;
        }
        let mut worst = "medium";
        let mut rated = false;
        for id in ids.iter().take(5) {
            if details_left == 0 {
                break;
            }
            details_left -= 1;
            let Ok(response) = client.get(format!("https://api.osv.dev/v1/vulns/{id}")).send().await else { continue };
            let Ok(vuln) = json_of(response).await else { continue };
            let label =
                vuln["database_specific"]["severity"].as_str().or_else(|| vuln["affected"][0]["ecosystem_specific"]["severity"].as_str());
            if let Some(label) = label {
                let severity = severity_of(label);
                if !rated || rank(severity) < rank(worst) {
                    worst = severity;
                    rated = true;
                }
            }
        }
        part.add(
            worst,
            "vuln",
            format!(
                "The global {} tool {} {} has {} ({}).",
                package.manager,
                package.name,
                package.version,
                plural(ids.len(), "known vulnerability", "known vulnerabilities"),
                ids_text(&ids)
            ),
            Some(package.fix.clone()),
            "osv",
        );
        part.about("Package", format!("{}:{}", package.ecosystem, package.name));
    }
    Ok(part)
}

async fn json_of(response: reqwest::Response) -> Result<Value, String> {
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0)
}

/// SSH keys: algorithm and size, passphrase, and file permissions.
fn ssh_checks() -> Part {
    let mut part = Part::default();
    let dir = home().join(".ssh");
    if !dir.is_dir() {
        part.skipped.push("ssh keys: there is no ~/.ssh folder".into());
        return part;
    }
    part.checked.push("~/.ssh permissions".into());
    if mode(&dir) & 0o077 != 0 {
        part.add("medium", "ssh", "Other users of this Mac can open ~/.ssh.".into(), Some("chmod 700 ~/.ssh".into()), "ssh");
    }
    if which("ssh-keygen").is_none() {
        part.skipped.push("ssh key strength: ssh-keygen is not installed".into());
        return part;
    }
    part.checked.push("ssh keys".into());
    let new_key = || Some("ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519".to_owned());
    for key in ssh::file_keys() {
        let path = Path::new(&key.path);
        let shown = tilde(path);
        if ssh::too_open(path) {
            part.add(
                "high",
                "ssh",
                format!("The private key {shown} can be read by other users of this Mac."),
                Some(format!("chmod 600 {shown}")),
                "ssh",
            );
        }
        let bits = key.bits;
        match key.kind.as_str() {
            "dsa" => part.add(
                "high",
                "ssh",
                format!("The key {shown} is a DSA key, which is broken and refused by current OpenSSH."),
                new_key(),
                "ssh",
            ),
            "rsa" if bits < 2048 => {
                part.add("high", "ssh", format!("The key {shown} is a {bits}-bit RSA key, which is too short to be safe."), new_key(), "ssh")
            }
            "rsa" if bits < 3072 => part.add(
                "low",
                "ssh",
                format!("The key {shown} is a {bits}-bit RSA key; 3072 bits or an Ed25519 key is recommended."),
                new_key(),
                "ssh",
            ),
            _ => {}
        }
        if key.passphrase == Some(false) && !key.kind.ends_with("-sk") {
            part.add("low", "ssh", format!("The private key {shown} has no passphrase."), Some(format!("ssh-keygen -p -f {shown}")), "ssh");
        }
    }
    part
}

/// The patterns of secrets the sweep looks for: (what it is, pattern).
pub fn secret_patterns() -> Vec<(&'static str, Regex)> {
    [
        ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}"),
        ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("API key", r"(?i)\b(?:api|secret|token)[_-]?key\b\s*[=:]\s*['\x22]?[^\s'\x22]{16,}"),
        ("API key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}"),
    ]
    .into_iter()
    .filter_map(|(label, pattern)| Regex::new(pattern).ok().map(|re| (label, re)))
    .collect()
}

/// Lines in the shell history that look like secrets (counts only).
fn history_checks() -> Part {
    let mut part = Part::default();
    let patterns = secret_patterns();
    for (file, label) in [(".zsh_history", "zsh history"), (".bash_history", "bash history")] {
        let path = home().join(file);
        let Ok(bytes) = std::fs::read(&path) else {
            part.skipped.push(format!("secrets in {label}: there is no ~/{file}"));
            continue;
        };
        part.checked.push(format!("secrets in {label}"));
        let text = String::from_utf8_lossy(&bytes);
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        let mut lines = 0;
        for line in text.lines() {
            let mut hit = false;
            for (kind, re) in &patterns {
                if re.is_match(line) {
                    *counts.entry(kind).or_default() += 1;
                    hit = true;
                }
            }
            lines += usize::from(hit);
        }
        if lines > 0 {
            let what = counts.iter().map(|(kind, n)| plural(*n, kind, &format!("{kind}s"))).collect::<Vec<_>>().join(", ");
            part.add(
                "high",
                "secret",
                format!(
                    "~/{file} holds {} that look like secrets ({what}); rotate those credentials and delete the lines.",
                    plural(lines, "line", "lines")
                ),
                None,
                label,
            );
        }
    }
    part
}

/// Launch agents and daemons that start unsigned, ad-hoc signed, quarantined or missing programs.
fn launch_checks() -> Part {
    let mut part = Part::default();
    if launch::folders().is_empty() {
        part.skipped.push("launch agents: not a Mac".into());
        return part;
    }
    part.checked.push("launch agents and daemons".into());
    for item in launch::all() {
        let severity = match (item.unsigned(), item.quarantined) {
            _ if item.program.is_empty() => continue,
            (true, true) => "high",
            (true, false) => "medium",
            (false, true) => "low",
            _ if item.signature == "missing" => "low",
            _ => continue,
        };
        part.add(
            severity,
            "persistence",
            format!("The {} {} in {} starts {}, {}.", item.what(), item.label, item.folder(), item.program, item.verdict()),
            None,
            "launch agents",
        );
    }
    part
}
