//! Mac settings that matter (posture): disk encryption, SIP, Gatekeeper, firewall, screen lock,
//! sharing, profiles, trusted certificates, DNS and proxy, sudo, extensions, XProtect and update
//! settings. Read-only and without prompts: nothing here runs as root, and fixes are only offered.

use crate::inventory::{cached_feed, days, today, version_cmp};
use crate::sweep::Part;
use crate::util::{home, plural, run, which};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_secs(15);

/// Run one tool; a failure goes into `skipped` with why. Returns stdout and stderr together.
fn read(part: &mut Part, label: &str, program: &str, args: &[&str]) -> Option<String> {
    match run(program, args, STEP) {
        Ok(out) => Some(format!("{}\n{}", out.stdout, out.stderr)),
        Err(error) => {
            part.skipped.push(format!("{label}: {error}"));
            None
        }
    }
}

fn plist_dict(path: &str) -> Option<plist::Dictionary> {
    plist::Value::from_file(path).ok()?.into_dictionary()
}

fn names(list: &[String]) -> String {
    let mut text = list.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    if list.len() > 5 {
        text.push_str(&format!(" and {} more", list.len() - 5));
    }
    text
}

/// Every posture check. Blocking; about 15 s at worst per tool.
pub fn checks() -> Part {
    let mut part = Part::default();
    if !cfg!(target_os = "macos") {
        part.skipped.push("Mac settings: not a Mac".into());
        return part;
    }
    let started = Instant::now();
    basics(&mut part);
    screen_lock(&mut part);
    sharing(&mut part);
    profiles(&mut part);
    certificates(&mut part);
    network_settings(&mut part);
    sudo(&mut part);
    extensions(&mut part);
    xprotect(&mut part);
    updates(&mut part);
    settings(&mut part);
    tracing::debug!("posture checks took {} ms", started.elapsed().as_millis());
    part
}

/// Each setting checked as `(:MacSetting {key, name, value*: ok | flagged, checked_ms})
/// -[:OF]->(:Machine)`, its findings about it.
fn settings(part: &mut Part) {
    let Some(machine) = crate::graph::machine() else { return };
    let key_of = |name: &str| -> String {
        let name = name.split(" (").next().unwrap_or(name).to_lowercase();
        name.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty()).collect::<Vec<_>>().join("_")
    };
    let now = crate::util::now_ms();
    let mut flagged = vec![false; part.checked.len()];
    for (i, n) in part.at_check.clone().into_iter().enumerate() {
        if n > 0 && n <= part.checked.len() {
            flagged[n - 1] = true;
            part.findings[i].about = Some(("MacSetting".into(), key_of(&part.checked[n - 1])));
        }
    }
    for (name, flagged) in part.checked.clone().iter().zip(flagged) {
        use crate::graph::Props;
        let key = key_of(name);
        if key.is_empty() {
            continue;
        }
        let unit = part.graph.unit();
        unit.node("MacSetting", key.clone()).p("name", name.split(" (").next().unwrap_or(name)).p("checked_ms", now).t("value", if flagged { "flagged" } else { "ok" });
        unit.edge(crate::graph::r("MacSetting", key), "OF", machine.clone());
    }
}

/// FileVault, SIP, Gatekeeper, the firewall and its stealth mode.
fn basics(part: &mut Part) {
    if let Some(text) = read(part, "FileVault", "/usr/bin/fdesetup", &["status"]) {
        part.checked.push("FileVault".into());
        if text.contains("FileVault is Off") {
            part.add(
                "high",
                "posture",
                "FileVault is off: anyone who gets hold of this Mac can read its disk.".into(),
                Some("sudo fdesetup enable".into()),
                "fdesetup",
            );
        } else if !text.contains("FileVault is On") {
            part.skipped.push(format!("FileVault: unknown answer ({})", text.trim().lines().next().unwrap_or("")));
        }
    }
    if let Some(text) = read(part, "System Integrity Protection", "/usr/bin/csrutil", &["status"]) {
        part.checked.push("System Integrity Protection".into());
        if text.contains("status: disabled") || text.contains("Custom Configuration") {
            part.add(
                "high",
                "posture",
                "System Integrity Protection is off or weakened, so malware can change protected system files. Turn it back on from Recovery with `csrutil enable`.".into(),
                None,
                "csrutil",
            );
        }
    }
    if let Some(text) = read(part, "Gatekeeper", "/usr/sbin/spctl", &["--status"]) {
        part.checked.push("Gatekeeper".into());
        if text.contains("assessments disabled") {
            part.add(
                "high",
                "posture",
                "Gatekeeper is off: apps from anywhere open without any check.".into(),
                Some("sudo spctl --global-enable".into()),
                "spctl",
            );
        }
    }
    let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    let mut firewall_on = false;
    if let Some(text) = read(part, "firewall", fw, &["--getglobalstate"]) {
        part.checked.push("firewall".into());
        firewall_on = !text.contains("disabled");
        if !firewall_on {
            part.add(
                "medium",
                "posture",
                "The macOS firewall is off, so any program can accept connections from the network.".into(),
                Some(format!("sudo {fw} --setglobalstate on")),
                "firewall",
            );
        }
    }
    if let Some(text) = read(part, "firewall stealth mode", fw, &["--getstealthmode"]) {
        part.checked.push("firewall stealth mode".into());
        // Stealth mode only matters once the firewall is on.
        if firewall_on && text.contains("is off") {
            part.add(
                "low",
                "posture",
                "Firewall stealth mode is off, so this Mac answers probes from the network.".into(),
                Some(format!("sudo {fw} --setstealthmode on")),
                "firewall",
            );
        }
    }
}

/// Password after sleep or screen saver, and automatic login.
fn screen_lock(part: &mut Part) {
    // sysadminctl writes its answer to stderr, e.g. "screenLock delay is 5 seconds" or "screenLock is off".
    if let Some(text) = read(part, "screen lock", "/usr/sbin/sysadminctl", &["-screenLock", "status"]) {
        part.checked.push("screen lock".into());
        let fix = Some("sysadminctl -screenLock immediate -password -".to_owned());
        if text.contains("screenLock is off") {
            part.add("medium", "posture", "The Mac does not ask for the password after sleep or the screen saver.".into(), fix, "sysadminctl");
        } else if let Some(seconds) = text
            .split("screenLock delay is ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())
            && seconds > 300
        {
            part.add(
                "low",
                "posture",
                format!("The Mac asks for the password only {} minutes after sleep or the screen saver.", seconds / 60),
                fix,
                "sysadminctl",
            );
        }
    }
    part.checked.push("automatic login".into());
    let auto = plist_dict("/Library/Preferences/com.apple.loginwindow.plist")
        .and_then(|d| d.get("autoLoginUser").and_then(|v| v.as_string()).map(str::to_owned));
    if let Some(user) = auto {
        part.add(
            "high",
            "posture",
            format!("The Mac logs in automatically as {user}, without asking for a password at start-up."),
            Some("sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser && sudo rm -f /etc/kcpassword".into()),
            "loginwindow",
        );
    }
}

/// TCP ports listening on a non-local address.
fn listening() -> Option<BTreeSet<u16>> {
    let out = run("/usr/sbin/netstat", &["-an", "-p", "tcp"], STEP).ok()?;
    Some(
        out.stdout
            .lines()
            .filter(|l| l.ends_with("LISTEN") || l.contains(" LISTEN "))
            .filter_map(|l| l.split_whitespace().nth(3))
            .filter(|local| !local.starts_with("127.") && !local.starts_with("::1"))
            .filter_map(|local| local.rsplit('.').next()?.parse().ok())
            .collect(),
    )
}

/// A system launchd job is loaded.
fn loaded(label: &str) -> bool {
    run("/bin/launchctl", &["print", &format!("system/{label}")], STEP).is_ok_and(|out| out.ok)
}

/// Remote Login, Screen Sharing, Remote Management, File Sharing, Internet Sharing and AirDrop,
/// cross-checked with the ports that really listen.
fn sharing(part: &mut Part) {
    let ports = listening();
    if ports.is_none() {
        part.skipped.push("listening ports for sharing: netstat gave no answer".into());
    }
    let open = |port: u16| ports.as_ref().is_some_and(|p| p.contains(&port));
    part.checked.push("sharing services".into());
    let settings = "System Settings > General > Sharing";
    if loaded("com.openssh.sshd") || open(22) {
        part.add(
            "medium",
            "posture",
            "Remote Login (SSH) is on: anyone on the network can try to log in to this Mac.".into(),
            Some("sudo systemsetup -setremotelogin off".into()),
            "sharing",
        );
    }
    if loaded("com.apple.screensharing") || open(5900) {
        part.add(
            "medium",
            "posture",
            format!("Screen Sharing is on: others on the network can ask to see and control this screen. Turn it off in {settings} if not needed."),
            None,
            "sharing",
        );
    }
    let ard = run("/usr/bin/pgrep", &["-x", "ARDAgent"], STEP).is_ok_and(|out| out.ok);
    if ard || open(3283) {
        part.add(
            "medium",
            "posture",
            "Remote Management (Apple Remote Desktop) is on: an administrator elsewhere can control this Mac.".into(),
            Some("sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop".into()),
            "sharing",
        );
    }
    if loaded("com.apple.smbd") || open(445) {
        part.add(
            "low",
            "posture",
            format!("File Sharing is on: shared folders on this Mac can be opened from the network. Turn it off in {settings} if not needed."),
            None,
            "sharing",
        );
    }
    let nat = plist_dict("/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
        .and_then(|d| d.get("NAT").and_then(|v| v.as_dictionary()).and_then(|n| n.get("Enabled")).and_then(plist_int));
    if nat == Some(1) {
        part.add(
            "medium",
            "posture",
            format!("Internet Sharing is on: this Mac shares its connection with other devices. Turn it off in {settings} if not needed."),
            None,
            "sharing",
        );
    }
    if let Ok(out) = run("/usr/bin/defaults", &["read", "com.apple.sharingd", "DiscoverableMode"], STEP)
        && out.stdout.trim() == "Everyone"
    {
        part.add(
            "low",
            "posture",
            "AirDrop accepts files from everyone nearby, not only contacts.".into(),
            Some("defaults write com.apple.sharingd DiscoverableMode -string \"Contacts Only\"".into()),
            "sharing",
        );
    }
}

fn plist_int(value: &plist::Value) -> Option<i64> {
    value.as_signed_integer().or_else(|| value.as_boolean().map(i64::from))
}

/// Configuration profiles and MDM enrollment: a profile can install a root certificate, VPN,
/// proxy or content filter and so take over the Mac's traffic.
fn profiles(part: &mut Part) {
    let mut managed = false;
    if let Some(text) = read(part, "MDM enrollment", "/usr/bin/profiles", &["status", "-type", "enrollment"]) {
        part.checked.push("MDM enrollment".into());
        managed = text.lines().any(|l| l.contains("MDM enrollment: Yes"));
        if managed {
            part.add("info", "posture", "This Mac is managed by an organisation (MDM): it can install apps, profiles and settings.".into(), None, "profiles");
        }
    }
    if let Some(text) = read(part, "configuration profiles", "/usr/bin/profiles", &["show", "-type", "configuration"]) {
        part.checked.push("configuration profiles".into());
        let payloads = [
            ("com.apple.security.root", "a root certificate"),
            ("com.apple.security.pkcs1", "a certificate"),
            ("com.apple.vpn.managed", "a VPN"),
            ("com.apple.proxy", "a proxy"),
            ("com.apple.webcontent-filter", "a content filter"),
            ("com.apple.dnsSettings.managed", "DNS settings"),
            ("com.apple.dnsProxy.managed", "a DNS proxy"),
        ];
        let found: Vec<&str> = payloads.iter().filter(|(id, _)| text.contains(id)).map(|(_, what)| *what).collect();
        let count = text.lines().filter(|l| l.contains("attribute: profileIdentifier:")).count();
        if !found.is_empty() {
            part.add(
                if managed { "low" } else { "high" },
                "posture",
                format!(
                    "Installed configuration profiles set {}{}. Check that you know who installed them (System Settings > General > Device Management).",
                    found.join(", "),
                    if managed { "" } else { " on a Mac that no organisation manages" }
                ),
                None,
                "profiles",
            );
        } else if count > 0 && !managed {
            part.add(
                "low",
                "posture",
                format!("{} installed on a Mac that no organisation manages.", plural(count, "configuration profile is", "configuration profiles are")),
                None,
                "profiles",
            );
        }
    }
    let managed_prefs = Path::new("/Library/Managed Preferences");
    if managed_prefs.is_dir() && !managed {
        let domains: Vec<String> = std::fs::read_dir(managed_prefs)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.path().file_stem().map(|s| s.to_string_lossy().into_owned()))
            .filter(|n| !n.starts_with('.'))
            .collect();
        if !domains.is_empty() {
            part.add(
                "low",
                "posture",
                format!("Managed settings are imposed on this Mac without MDM enrollment: {}.", names(&domains)),
                None,
                "profiles",
            );
        }
    }
}

/// Certificates the admin or user marked as trusted (an interception proxy's root CA lets it
/// read HTTPS traffic).
fn certificates(part: &mut Part) {
    let interceptors = ["charles", "mitmproxy", "fiddler", "burp", "proxyman", "portswigger", "zscaler", "netskope", "kaspersky", "avast", "avg", "eset", "bitdefender", "superfish", "komodia"];
    for (args, domain) in [(vec!["dump-trust-settings", "-d"], "an administrator"), (vec!["dump-trust-settings"], "you")] {
        let Some(text) = read(part, "trusted certificates", "/usr/bin/security", &args) else { continue };
        part.checked.push(format!("certificates trusted by {domain}"));
        let certs: Vec<String> =
            text.lines().filter_map(|l| l.strip_prefix("Cert ").and_then(|r| r.split_once(": ")).map(|(_, name)| name.trim().to_owned())).collect();
        if certs.is_empty() {
            continue;
        }
        let suspicious = certs.iter().any(|c| interceptors.iter().any(|i| c.to_lowercase().contains(i)));
        part.add(
            if suspicious { "medium" } else { "low" },
            "posture",
            format!(
                "{} marked as trusted by {domain}: {}. A trusted certificate that is not Apple's can be used to read encrypted web traffic; remove any you do not recognise in Keychain Access.",
                plural(certs.len(), "certificate is", "certificates are"),
                names(&certs)
            ),
            None,
            "trust settings",
        );
    }
}

/// Proxy settings, per-domain resolvers and changes to /etc/hosts.
fn network_settings(part: &mut Part) {
    if let Some(text) = read(part, "proxy settings", "/usr/sbin/scutil", &["--proxy"]) {
        part.checked.push("proxy settings".into());
        let value = |key: &str| {
            text.lines().find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.trim().strip_prefix(':')).map(|v| v.trim().to_owned()))
        };
        let mut proxies = Vec::new();
        for (enable, host, port, what) in [
            ("HTTPEnable", "HTTPProxy", "HTTPPort", "web"),
            ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "secure web"),
            ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS"),
        ] {
            if value(enable).as_deref() == Some("1") {
                proxies.push(format!("{what} proxy {}:{}", value(host).unwrap_or_default(), value(port).unwrap_or_default()));
            }
        }
        if value("ProxyAutoConfigEnable").as_deref() == Some("1") {
            proxies.push(format!("auto-config {}", value("ProxyAutoConfigURLString").unwrap_or_default()));
        }
        if !proxies.is_empty() {
            part.add(
                "medium",
                "posture",
                format!("Traffic goes through a proxy ({}). Make sure you set it up yourself; malware uses proxies to watch traffic.", proxies.join(", ")),
                None,
                "scutil",
            );
        }
    }
    part.checked.push("per-domain DNS resolvers".into());
    let resolvers: Vec<String> = std::fs::read_dir("/etc/resolver")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    if !resolvers.is_empty() {
        part.add(
            "low",
            "posture",
            format!("/etc/resolver sends DNS for {} to its own server ({}). VPNs and Docker do this; anything else is worth a look.", plural(resolvers.len(), "domain", "domains"), names(&resolvers)),
            None,
            "resolver",
        );
    }
    match std::fs::read_to_string("/etc/hosts") {
        Err(error) => part.skipped.push(format!("/etc/hosts: {error}")),
        Ok(text) => {
            part.checked.push("/etc/hosts".into());
            let defaults = ["localhost", "broadcasthost"];
            let extra: Vec<&str> = text
                .lines()
                .map(|l| l.split('#').next().unwrap_or("").trim())
                .filter(|l| !l.is_empty())
                .filter(|l| !l.split_whitespace().skip(1).all(|name| defaults.contains(&name)))
                .collect();
            let sensitive = ["apple.com", "icloud", "mzstatic", "microsoft", "google", "github", "brew.sh", "osv.dev", "virustotal", "malwarebytes", "objective-see"];
            let blocked: Vec<&str> = extra.iter().copied().filter(|l| sensitive.iter().any(|s| l.contains(s))).collect();
            if !blocked.is_empty() {
                part.add(
                    "medium",
                    "posture",
                    format!("/etc/hosts redirects {} for update or security sites; malware does this to block updates.", plural(blocked.len(), "name", "names")),
                    Some("sudo nano /etc/hosts".into()),
                    "hosts",
                );
            } else if !extra.is_empty() {
                part.add("info", "posture", format!("/etc/hosts has {} beyond the defaults.", plural(extra.len(), "entry", "entries")), None, "hosts");
            }
        }
    }
}

/// Passwordless sudo (`sudo -n -l` never prompts), and whether Touch ID unlocks sudo.
fn sudo(part: &mut Part) {
    match run("/usr/bin/sudo", &["-n", "-l"], STEP) {
        Err(error) => part.skipped.push(format!("passwordless sudo: {error}")),
        Ok(out) => {
            part.checked.push("passwordless sudo".into());
            if out.stdout.lines().any(|l| l.contains("NOPASSWD") && (l.contains("ALL") || l.contains("/bin/sh") || l.contains("/bin/bash") || l.contains("/bin/zsh"))) {
                part.add(
                    "high",
                    "posture",
                    "sudo works without a password, so any script you run can become root.".into(),
                    Some("sudo visudo".into()),
                    "sudo",
                );
            }
        }
    }
    let touch_id = std::fs::read_to_string("/etc/pam.d/sudo_local")
        .is_ok_and(|t| t.lines().any(|l| !l.trim_start().starts_with('#') && l.contains("pam_tid.so")));
    part.checked.push(format!("Touch ID for sudo ({})", if touch_id { "on" } else { "off" }));
}

/// System extensions, third-party kernel extensions, and an outbound firewall.
fn extensions(part: &mut Part) {
    let mut sysext = String::new();
    if let Some(text) = read(part, "system extensions", "/usr/bin/systemextensionsctl", &["list"]) {
        part.checked.push("system extensions".into());
        let active: Vec<String> = text
            .lines()
            .filter(|l| l.contains("[activated enabled]"))
            .filter_map(|l| {
                let fields: Vec<&str> = l.split('\t').map(str::trim).filter(|f| !f.is_empty()).collect();
                // ... teamID bundleID (version) name [state]
                fields.iter().rev().nth(1).map(|name| name.to_string())
            })
            .collect();
        if !active.is_empty() {
            part.add(
                "info",
                "posture",
                format!("{} running: {}.", plural(active.len(), "system extension is", "system extensions are"), names(&active)),
                None,
                "systemextensionsctl",
            );
        }
        sysext = text.to_lowercase();
    }
    if let Some(text) = read(part, "kernel extensions", "/usr/bin/kmutil", &["showloaded", "--list-only"]) {
        part.checked.push("kernel extensions".into());
        let third: Vec<String> = text
            .lines()
            .filter_map(|l| l.split_whitespace().nth(5))
            .filter(|id| id.contains('.') && !id.starts_with("com.apple."))
            .map(str::to_owned)
            .collect();
        if !third.is_empty() {
            let apple_silicon = cfg!(target_arch = "aarch64");
            part.add(
                if apple_silicon { "medium" } else { "low" },
                "posture",
                format!(
                    "{} loaded: {}.{}",
                    plural(third.len(), "third-party kernel extension is", "third-party kernel extensions are"),
                    names(&third),
                    if apple_silicon { " On Apple silicon this means the Mac runs with Reduced Security." } else { "" }
                ),
                None,
                "kmutil",
            );
        }
    }
    part.checked.push("outbound firewall".into());
    let apps = ["LuLu.app", "Little Snitch.app", "Radio Silence.app", "Vallum.app", "Hands Off!.app", "Murus.app"];
    let installed = apps.iter().any(|app| Path::new("/Applications").join(app).exists() || home().join("Applications").join(app).exists())
        || ["lulu", "little snitch", "littlesnitch", "radio silence", "vallum"].iter().any(|n| sysext.contains(n));
    if !installed {
        part.add(
            "info",
            "posture",
            "No outbound firewall is installed, so nothing asks before a program connects out. LuLu (free, open source) shows each new connection.".into(),
            which("brew").map(|_| "brew install --cask lulu".to_owned()),
            "outbound firewall",
        );
    }
}

/// XProtect's signature version against SOFA's current one (from the cached feed), else its age.
fn xprotect(part: &mut Part) {
    let Some(text) = read(part, "XProtect", "/usr/bin/xprotect", &["version"]) else { return };
    let version = text.split("Version:").nth(1).and_then(|r| r.split_whitespace().next()).and_then(|v| v.parse::<u64>().ok());
    let installed = text.split("Installed:").nth(1).and_then(|r| days(r.trim()));
    let Some(version) = version else {
        part.skipped.push("XProtect: unknown answer from xprotect version".into());
        return;
    };
    part.checked.push(format!("XProtect ({version})"));
    let sofa: Option<Value> = cached_feed("sofa-macos.json").and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let current = sofa.as_ref().and_then(|s| {
        let data = &s["XProtectPlistConfigData"];
        Some((data["com.apple.XProtect"].as_str()?.parse::<u64>().ok()?, days(data["ReleaseDate"].as_str()?)?))
    });
    let fix = Some("sudo softwareupdate --background-critical".to_owned());
    match current {
        // Apple rolls updates out over a few days, so only a version older than that counts.
        Some((latest, released)) if version < latest && today() - released > 3 => part.add(
            "medium",
            "posture",
            format!("XProtect, Apple's built-in malware scanner, has signatures {version}; {latest} has been out for {} days, so its updates may be broken.", today() - released),
            fix,
            "xprotect",
        ),
        Some(_) => {}
        None => match installed {
            Some(day) if today() - day > 30 => part.add(
                "low",
                "posture",
                format!("XProtect, Apple's built-in malware scanner, last updated its signatures {} days ago; its updates may be broken.", today() - day),
                fix,
                "xprotect",
            ),
            Some(_) => {}
            None => part.skipped.push("XProtect freshness: unknown install date and no SOFA feed cached yet".into()),
        },
    }
}

/// Automatic and background security updates (point 17), and how long a macOS update has waited
/// (point 16). Keys that are absent mean the default, which is on.
fn updates(part: &mut Part) {
    let path = "/Library/Preferences/com.apple.SoftwareUpdate.plist";
    let Some(prefs) = plist_dict(path) else {
        part.skipped.push("update settings: cannot read /Library/Preferences/com.apple.SoftwareUpdate.plist".into());
        return;
    };
    let managed = plist_dict("/Library/Managed Preferences/com.apple.SoftwareUpdate.plist").unwrap_or_default();
    let flag = |key: &str| managed.get(key).or_else(|| prefs.get(key)).and_then(plist_int);
    part.checked.push("automatic update settings".into());
    let set = |key: &str| format!("sudo defaults write {path} {key} -bool true");
    for (key, severity, text) in [
        ("AutomaticCheckEnabled", "medium", "The Mac does not check for updates by itself."),
        ("CriticalUpdateInstall", "high", "Critical security updates are not installed automatically."),
        ("ConfigDataInstall", "high", "Apple's security data updates (XProtect malware signatures) are turned off."),
        ("AutomaticDownload", "low", "Updates are not downloaded automatically, so they wait longer to be installed."),
    ] {
        if flag(key) == Some(0) {
            part.add(severity, "posture", text.into(), Some(set(key)), "softwareupdate");
        }
    }

    // FirstOfferDateDictionary: "MSU_UPDATE_25G332_patch_26.7.2_minor" -> first offered.
    let Some(current) = run("/usr/bin/sw_vers", &["-productVersion"], STEP).ok().map(|o| o.stdout.trim().to_owned()) else {
        part.skipped.push("days an update has waited: sw_vers gave no answer".into());
        return;
    };
    let major = current.split('.').next().unwrap_or("").to_owned();
    let offers = prefs.get("FirstOfferDateDictionary").and_then(|v| v.as_dictionary());
    let mut waiting: Vec<(String, i64)> = offers
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.ends_with("_minor"))
        .filter_map(|(key, value)| {
            let version = key.trim_end_matches("_minor").rsplit('_').next()?.to_owned();
            let offered = (std::time::SystemTime::from(value.as_date()?).duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() / 86_400) as i64;
            let newer = version.split('.').next() == Some(major.as_str()) && version_cmp(&version, &current) == Some(Ordering::Greater);
            newer.then_some((version, offered))
        })
        .collect();
    part.checked.push("days an update has waited".into());
    waiting.sort_by(|a, b| version_cmp(&a.0, &b.0).unwrap_or(Ordering::Equal));
    if let (Some(first), Some(last)) = (waiting.iter().min_by_key(|w| w.1), waiting.last()) {
        let waited = today() - first.1;
        if waited >= 3 {
            part.add(
                if waited >= 14 { "medium" } else { "low" },
                "posture",
                format!(
                    "macOS {} is available and updates have waited {waited} days (since macOS {} was first offered). This Mac runs {current}.",
                    last.0, first.0
                ),
                Some("open x-apple.systempreferences:com.apple.Software-Update-Settings.extension".into()),
                "softwareupdate",
            );
        }
    }
}
