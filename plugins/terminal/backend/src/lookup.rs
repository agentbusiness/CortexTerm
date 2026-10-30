//! What the paste guard looks up on the network, never from `terminal.assess` (which stays fast
//! and offline):
//!
//! - `terminal.script.fetch`: the script a `curl … | sh` would run, downloaded (as curl, capped,
//!   never run) and scanned ([`crate::threat`]), so it can be read and explained before it runs;
//! - `terminal.packages.check`: the packages an install command names, looked up in OSV in one
//!   batch: `MAL-` ids are known malware, the others known vulnerabilities of the named version.

use crate::assess::{Word, parse};
use crate::threat;
use cc_protocol::contracts::terminal::{Package, PackageCheck, Script};
use serde_json::{Value, json};
use std::time::Duration;

/// The script kept for reading and scanning.
const SCRIPT_TEXT: usize = 200 * 1024;
/// Downloading stops here (an installer that big is counted, not kept).
const SCRIPT_MAX: u64 = 20 * 1024 * 1024;
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(20);
const OSV_TIMEOUT: Duration = Duration::from_secs(8);
/// At most this many packages per check.
const MAX_PACKAGES: usize = 30;

/// Download the script at `url` as curl would (the user agent matters: some servers hand a
/// browser something else), keep the first 200 KB and scan it.
pub async fn fetch_script(url: &str) -> Result<Script, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(format!("`{url}` is not a web address"));
    }
    let client = reqwest::Client::builder()
        .timeout(SCRIPT_TIMEOUT)
        .user_agent("curl/8.7.1")
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = client.get(url).send().await.map_err(|e| format!("{url}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let final_url = response.url().to_string();
    let mut kept: Vec<u8> = Vec::new();
    let mut bytes = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|e| format!("{url}: {e}"))? {
        bytes += chunk.len() as u64;
        if kept.len() < SCRIPT_TEXT {
            kept.extend_from_slice(&chunk[..chunk.len().min(SCRIPT_TEXT - kept.len())]);
        }
        if bytes >= SCRIPT_MAX {
            break;
        }
    }
    let text = String::from_utf8_lossy(&kept).into_owned();
    let threats = threat::scan(&text, false);
    Ok(Script { url: final_url, truncated: bytes > kept.len() as u64, text, bytes, threats })
}

/// The packages `text` installs by name, then what OSV knows about them.
pub async fn check_packages(text: &str) -> PackageCheck {
    let mut packages = installs(text);
    packages.truncate(MAX_PACKAGES);
    if packages.is_empty() {
        return PackageCheck::default();
    }
    match osv(&mut packages).await {
        Ok(()) => PackageCheck { packages, error: None },
        Err(error) => PackageCheck { packages, error: Some(error) },
    }
}

async fn osv(packages: &mut [Package]) -> Result<(), String> {
    let queries: Vec<Value> = packages
        .iter()
        .map(|p| {
            let mut query = json!({"package": {"name": p.name, "ecosystem": p.ecosystem}});
            if let Some(version) = &p.version {
                query["version"] = json!(version);
            }
            query
        })
        .collect();
    let client = reqwest::Client::builder().timeout(OSV_TIMEOUT).build().map_err(|e| e.to_string())?;
    let response = client
        .post("https://api.osv.dev/v1/querybatch")
        .header("content-type", "application/json")
        .body(json!({"queries": queries}).to_string())
        .send()
        .await
        .map_err(|e| format!("api.osv.dev: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("api.osv.dev answered {}", response.status()));
    }
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    let answer: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    for (package, result) in packages.iter_mut().zip(answer["results"].as_array().into_iter().flatten()) {
        for id in result["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str()) {
            if id.starts_with("MAL-") {
                package.malicious.push(id.to_owned());
            } else if package.version.is_some() {
                // Without a version every vulnerability the package ever had would be listed.
                package.vulns.push(id.to_owned());
            }
        }
    }
    Ok(())
}

/// The packages an install command names: npm, pnpm, yarn, bun (add, install, npx and friends),
/// pip, uv, pipx, cargo and gem. Paths, URLs and git sources are not packages OSV knows.
pub fn installs(text: &str) -> Vec<Package> {
    let Ok(cmds) = parse(text) else { return Vec::new() };
    let mut out: Vec<Package> = Vec::new();
    for cmd in &cmds {
        let mut words: &[Word] = &cmd.words;
        while words.first().is_some_and(|w| w.text.contains('=') && !w.text.starts_with('-') || matches!(w.text.as_str(), "sudo" | "env" | "command" | "time" | "nohup")) {
            words = &words[1..];
        }
        let Some(first) = words.first() else { continue };
        let name = first.text.rsplit('/').next().unwrap_or("");
        let args: Vec<&str> = words[1..].iter().map(|w| w.text.as_str()).collect();
        let sub = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
        let after_sub = |skip: usize| -> Vec<&str> {
            let at = args.iter().position(|a| *a == sub).map_or(args.len(), |i| i + 1 + skip);
            args.get(at..).unwrap_or(&[]).to_vec()
        };
        let (ecosystem, names, values): (&str, Vec<&str>, &[&str]) = match name {
            "npm" | "pnpm" | "yarn" | "bun" if matches!(sub, "install" | "i" | "add") => {
                ("npm", after_sub(0), &["--registry", "--prefix", "-w", "--workspace", "--filter", "--cwd"])
            }
            "npm" | "pnpm" | "yarn" | "bun" if matches!(sub, "exec" | "dlx" | "x") => ("npm", after_sub(0).into_iter().take(1).collect(), &["--package", "-p"]),
            "npx" | "bunx" | "pnpx" => ("npm", args.iter().copied().filter(|a| !a.starts_with('-')).take(1).collect(), &["--package", "-p"]),
            "pip" | "pip3" | "pipx" if matches!(sub, "install" | "run" | "inject") => {
                ("PyPI", after_sub(0), &["-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--python"])
            }
            "python" | "python3" if args.windows(2).any(|w| w == ["-m", "pip"]) => {
                let at = args.iter().position(|a| *a == "install").map_or(args.len(), |i| i + 1);
                ("PyPI", args.get(at..).unwrap_or(&[]).to_vec(), &["-r", "--requirement", "-c", "-e", "-i", "--index-url", "--extra-index-url", "-t"])
            }
            "uv" if sub == "pip" && after_sub(0).first() == Some(&"install") => ("PyPI", after_sub(1), &["-r", "--requirement", "-c", "-e", "-i", "--index-url", "--python", "-p"]),
            "uv" if sub == "tool" && matches!(after_sub(0).first(), Some(&"install" | &"run")) => ("PyPI", after_sub(1).into_iter().filter(|a| !a.starts_with('-')).take(1).collect(), &["--python", "--from"]),
            "uv" if sub == "add" => ("PyPI", after_sub(0), &["--python", "-p", "--group", "--optional", "--package"]),
            "uvx" => ("PyPI", args.iter().copied().filter(|a| !a.starts_with('-')).take(1).collect(), &["--python", "--from"]),
            "cargo" if matches!(sub, "install" | "add") => ("crates.io", after_sub(0), &["--version", "--vers", "--git", "--path", "--root", "--branch", "--tag", "--rev", "--features", "-F", "--registry", "--index", "-p", "--package"]),
            "gem" if sub == "install" => ("RubyGems", after_sub(0), &["-v", "--version", "-i", "--install-dir", "--source"]),
            _ => continue,
        };
        // Option values are not packages; `cargo install x --version 1.2` names its version.
        let version_flag = args.iter().position(|a| matches!(*a, "--version" | "--vers" | "-v") && ecosystem != "npm").and_then(|i| args.get(i + 1)).map(|v| (*v).to_owned());
        let mut skip_next = false;
        for word in names {
            if skip_next {
                skip_next = false;
                continue;
            }
            if word.starts_with('-') {
                skip_next = values.contains(&word);
                continue;
            }
            let looks_local = word.starts_with('.') || word.starts_with('/') || word.starts_with('~') || word.contains("://") || word.contains(':')
                || word.ends_with(".whl") || word.ends_with(".tgz") || word.ends_with(".tar.gz") || (ecosystem == "npm" && !word.starts_with('@') && word.contains('/'));
            if looks_local || word.is_empty() {
                continue;
            }
            if let Some(package) = package(ecosystem, word, version_flag.clone())
                && !out.iter().any(|p| p.ecosystem == package.ecosystem && p.name == package.name)
            {
                out.push(package);
            }
        }
    }
    out
}

/// `name@1.2.3`, `@scope/name@1`, `name==1.2`, `name[extra]>=2`, `name@1.0` (cargo).
fn package(ecosystem: &str, word: &str, version_flag: Option<String>) -> Option<Package> {
    let (name, version) = match ecosystem {
        "PyPI" => {
            let end = word.find(['=', '<', '>', '!', '~', ';', '[', ' ']).unwrap_or(word.len());
            let version = word.split_once("==").map(|(_, v)| v.trim().to_owned());
            (word[..end].to_owned(), version)
        }
        _ => match word.get(1..).and_then(|rest| rest.rfind('@')) {
            Some(at) => (word[..at + 1].to_owned(), Some(word[at + 2..].to_owned())),
            None => (word.to_owned(), None),
        },
    };
    // An exact version only: `^1.2` or `latest` is not one OSV can check.
    let version = version.or(version_flag).filter(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit()) && !v.contains(['^', '~', '*', '>', '<', ' ']));
    let name = if ecosystem == "PyPI" { name.to_lowercase().replace('_', "-") } else { name };
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "@/._-".contains(c))).then(|| Package { ecosystem: ecosystem.into(), name, version, ..Package::default() })
}
