//! The paste guard (`terminal.scan`, and part of `terminal.assess`): what a command, a script or a
//! skill's shell block would really do, in plain code. The model explains a finding; it never
//! decides one.
//!
//! - Layers: the text, then what it hides, decoded to depth 4: base64 and hex words, `\x..` and
//!   octal escapes, the scripts of `sh -c`, `eval`, `osascript -e`, `python -c` and friends, the
//!   commands inside `$(...)` and backticks, AppleScript's `do shell script`, Unicode tag text.
//! - Rules: the macOS stealer and ClickFix shapes as data ([`RULES`]: fake password prompts,
//!   quarantine removal, keychain reads, reverse shells, AI agents without their checks,
//!   `applescript://` and privacy-settings links, ...), then the commands: a download piped or
//!   substituted into a shell or an interpreter, or saved and then run, a decoder piped into a
//!   shell, a quarantine flag removed and the file opened, and secrets flowing into the network
//!   (`cat .env | curl -d @- …`, `curl -F f=@~/.ssh/id_rsa …`).
//! - Paste-and-run: a script run straight from the internet is high (held, refused without the
//!   person) unless its parsed address is an official installer ([`OFFICIAL_INSTALLERS`]: medium,
//!   the person approves); the text names the host, says what makes it suspect (bare IP, short
//!   link, paste or file site, tunnel, look-alike or borrowed name, `.zip`), and the safe way.
//! - Hidden text: zero-width and direction characters, Unicode tags, terminal escape codes, and
//!   look-alike letters in web addresses.
//!
//! [`clean`] is the other half: output text without escape codes or hidden characters, the same
//! for the person and the model.

use crate::assess::{Cmd, Word, parse};
use base64::Engine;
use cc_protocol::contracts::terminal::Threat;
use regex::Regex;
use std::sync::OnceLock;

/// How deep hidden layers are followed.
const MAX_DEPTH: usize = 4;
/// At most this many layers are scanned (a pathological input stops here).
const MAX_LAYERS: usize = 64;
/// Words shorter than this are not tried as base64 or hex.
const MIN_ENCODED: usize = 16;

/// `(rule, severity, pattern, what it does)`: one line per stealer or ClickFix shape.
pub const RULES: &[(&str, &str, &str, &str)] = &[
    ("fake-password-prompt", "high", r"(?is)display\s+dialog.{0,400}hidden\s+answer", "Shows a fake macOS password dialog to capture your password."),
    ("quarantine-removed", "high", r"(?i)\bxattr\b[^\n;|&]*\s-[a-z]*[dc][a-z]*\b[^\n;|&]*com\.apple\.quarantine", "Removes the quarantine flag, so macOS does not check the downloaded app before it opens."),
    ("quarantine-cleared", "medium", r"(?i)\bxattr\s+(-[a-z]*\s+)*-[a-z]*c[a-z]*\s", "Clears every extended attribute, the quarantine flag with them, so macOS does not check the app."),
    ("disk-image-from-temp", "high", r"(?i)\bhdiutil\s+(attach|mount)\b[^\n;|&]*(/tmp/|/private/tmp/|/var/folders/|/var/tmp/|\$TMPDIR|/Users/Shared/|Downloads/)", "Opens a disk image from a temporary or download folder, the way stealers install themselves."),
    ("runnable-in-temp", "high", r"(?i)\bchmod\s+(-[a-z]+\s+)*([ugoa]*\+[rws]*x[rwxs]*|[0-7]*[1357][0-7]*)\s+[^\n;|&]*?['\x22]?(/tmp/|/private/tmp/|/var/tmp/|/var/folders/|\$TMPDIR|/Users/Shared/)", "Makes a file in a temporary folder runnable, the way downloaded malware is started."),
    ("password-check", "high", r"(?i)\bdscl\b[^\n;|&]*\s-?authonly\b", "Checks a password against your account, which stealers do to confirm the password they phished."),
    ("keychain-read", "high", r"(?i)\bsecurity\s+find-(generic|internet)-password\b[^\n;|&]*\s-[a-z]*[wg][a-z]*\b", "Reads a saved password out of your keychain."),
    ("keychain-dump", "high", r"(?i)\bsecurity\s+(dump-keychain|export)\b", "Copies everything out of your keychain."),
    ("keychain-unlock", "high", r"(?i)\bsecurity\s+(unlock-keychain|set-keychain-settings)\b[^\n;|&]*\s-p\b", "Unlocks your keychain with a password written into the command."),
    ("reverse-shell", "high", r"/dev/(tcp|udp)/", "Opens a remote shell: someone else could type commands on this Mac."),
    ("reverse-shell", "high", r"(?i)\b(nc|ncat|netcat)\b[^\n;|&]*\s-[a-z]*[ec]\s", "Opens a remote shell: someone else could type commands on this Mac."),
    ("reverse-shell", "high", r"(?i)\b(ba|z)?sh\s+-i\b[^\n;|]*[<>]&", "Opens a remote shell: someone else could type commands on this Mac."),
    ("reverse-shell", "high", r"(?i)\bsocat\b[^\n;|&]*\bexec:", "Opens a remote shell: someone else could type commands on this Mac."),
    ("ai-agent-unchecked", "high", r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--trust-all-tools|--allow-all-tools|--approval-mode[= ]yolo", "Starts an AI agent with its safety checks off, so it can read files and run commands without asking."),
    ("decode-to-shell", "high", r"(?s)\b(eval|source|\.|(ba|z|da|k)?sh(\s+-[a-z]*c)?)\s+['\x22]?(\$\(|`|<\()[^)`]*\b(base64\s+(-d|-D|--decode)|xxd\s+-r|openssl\b[^)`]*\s-d)", "Decodes hidden text and runs it as commands."),
    ("decode-to-shell", "high", r"(?is)\b(exec|eval|Function)\s*\(\s*(base64\.b64decode|__import__\(\s*['\x22](base64|zlib|codecs)|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|atob\s*\(|Buffer\.from\s*\(|Base64\.decode64)", "Decodes hidden code and runs it, so what runs is not what is shown."),
    ("applescript-link", "high", r"(?i)\bopen\b[^\n;|&]*?['\x22]?applescript://", "Opens an applescript:// link, which loads a script into Script Editor ready to run; fake fix pages use it to get past Terminal."),
    ("privacy-settings-link", "high", r"(?i)\bopen\b[^\n;|&]*?['\x22]?x-apple\.systempreferences:[^\s'\x22]*Privacy", "Opens a privacy page of System Settings, the way fake fix pages walk you into giving a program full access to your files or screen."),
    ("run-from-temp", "high", r"(?m)(^|[;&|]\s*|\bexec\s+|\bnohup\s+|\bopen\s+)['\x22]?(/tmp/|/private/tmp/|/var/tmp/|\$TMPDIR/?|/Users/Shared/)[^\s'\x22]+", "Runs a program from a temporary folder, where downloaded malware is started from."),
    ("security-off", "high", r"(?i)\bspctl\s+--master-disable\b|\bspctl\s+--global-disable\b|\bcsrutil\s+disable\b", "Turns off a macOS protection (Gatekeeper or System Integrity Protection)."),
];

/// Hosts malware sends stolen data to (or serves itself from).
const EXFIL_HOSTS: &[&str] = &[
    "api.telegram.org", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "pastebin.com", "paste.ee", "transfer.sh",
    "gofile.io", "file.io", "0x0.st", "temp.sh", "bashupload.com", "webhook.site", "pipedream.net", "requestbin", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "trycloudflare.com", "anonfiles", "catbox.moe", "filebin.net",
];

/// What a file path holds that should never leave the Mac: (path part, plain name). A part with a
/// `/` matches anywhere in the path; one without matches a whole path component.
const SECRETS: &[(&str, &str)] = &[
    (".ssh", "your SSH keys"),
    ("id_rsa", "an SSH key"),
    ("id_ed25519", "an SSH key"),
    ("id_ecdsa", "an SSH key"),
    (".aws", "your AWS keys"),
    (".config/gcloud", "your Google Cloud keys"),
    (".azure", "your Azure keys"),
    (".kube", "your Kubernetes credentials"),
    (".docker/config.json", "your Docker logins"),
    (".npmrc", "your npm tokens"),
    (".pypirc", "your PyPI tokens"),
    (".netrc", "your saved logins"),
    (".git-credentials", "your git passwords"),
    (".config/gh", "your GitHub tokens"),
    (".gnupg", "your GPG keys"),
    (".env", "a secrets file (.env)"),
    ("Library/Keychains", "your keychains"),
    ("Login Data", "browser passwords"),
    ("Cookies", "browser cookies"),
    ("key4.db", "Firefox passwords"),
    ("logins.json", "Firefox passwords"),
    ("Local State", "the browsers' encryption keys"),
    ("wallet.dat", "a crypto wallet"),
    ("Application Support/Exodus", "a crypto wallet"),
    ("Application Support/Electrum", "a crypto wallet"),
    ("Application Support/Google/Chrome", "your Chrome profile (saved passwords and cookies)"),
    ("Application Support/BraveSoftware", "your Brave profile (saved passwords and cookies)"),
    ("Application Support/Microsoft Edge", "your Edge profile (saved passwords and cookies)"),
    ("Application Support/Firefox", "your Firefox profile (saved passwords and cookies)"),
    ("Library/Cookies", "your cookies"),
    ("Library/Safari", "your Safari data"),
    ("group.com.apple.notes", "your Notes"),
];

const DOWNLOADERS: &[&str] = &["curl", "wget", "fetch", "aria2c", "http", "https", "xh"];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish", "tcsh", "csh"];
const INTERPRETERS: &[&str] = &["python", "python3", "perl", "ruby", "node", "php", "osascript", "lua", "deno", "bun"];
const NETWORK_SINKS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp"];
/// Wrappers that run the command after their options.
const WRAPPERS: &[&str] = &["sudo", "doas", "env", "nohup", "nice", "time", "command", "builtin", "exec", "caffeinate", "stdbuf", "setsid", "unbuffer", "xargs", "arch"];

/// The official install scripts people are told to pipe into a shell, matched after the address is
/// parsed (never as text): `(host, path)`. A path ending in `/` is a prefix, an empty one the site's
/// root, any other the exact path; only over https (or no scheme). Run in one go, they are the ordinary "runs code from the internet";
/// any other address is the paste-and-run lure.
const OFFICIAL_INSTALLERS: &[(&str, &str)] = &[
    ("raw.githubusercontent.com", "/homebrew/install/"),
    ("sh.rustup.rs", ""),
    ("raw.githubusercontent.com", "/nvm-sh/nvm/"),
    ("bun.sh", "/install"),
    ("deno.land", "/install.sh"),
    ("deno.land", "/x/install/install.sh"),
    ("astral.sh", "/uv/"),
    ("astral.sh", "/ruff/"),
    ("get.pnpm.io", "/install.sh"),
    ("install.ohmyz.sh", ""),
    ("raw.githubusercontent.com", "/ohmyzsh/ohmyzsh/"),
    ("install.python-poetry.org", ""),
    ("sdk.cloud.google.com", ""),
    ("claude.ai", "/install.sh"),
    ("opencode.ai", "/install"),
    ("ollama.com", "/install.sh"),
    ("starship.rs", "/install.sh"),
    ("tailscale.com", "/install.sh"),
    ("get.docker.com", ""),
];

/// Sites that say why a script from them is suspect: (domain, why). A domain matches itself and
/// its subdomains.
const SUSPECT_SITES: &[(&[&str], &str)] = &[
    (&["bit.ly", "bitly.com", "tinyurl.com", "t.co", "is.gd", "v.gd", "goo.gl", "rb.gy", "cutt.ly", "ow.ly", "buff.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id"],
     "It is a link shortener, which hides the real address."),
    (&["pastebin.com", "paste.ee", "rentry.co", "rentry.org", "hastebin.com", "termbin.com", "dpaste.org", "dpaste.com", "paste.rs", "controlc.com", "justpaste.it", "gist.githubusercontent.com"],
     "It is a paste site, where anyone can post a script."),
    (&["transfer.sh", "0x0.st", "temp.sh", "bashupload.com", "gofile.io", "file.io", "catbox.moe", "filebin.net", "tmpfiles.org", "pixeldrain.com", "mediafire.com", "mega.nz", "dropboxusercontent.com", "anonfiles.com", "files.fm"],
     "It is a file-sharing site, where anyone can upload."),
    (&["ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "trycloudflare.com", "loca.lt", "serveo.net", "localtunnel.me"],
     "It is a temporary tunnel to someone's own computer."),
];

/// Names a fake page borrows: (word in the host, the real owner's domains, whose name).
const IMITATED: &[(&str, &[&str], &str)] = &[
    ("homebrew", &["brew.sh", "github.com", "githubusercontent.com"], "Homebrew"),
    ("brew", &["brew.sh", "github.com", "githubusercontent.com"], "Homebrew"),
    ("github", &["github.com", "githubusercontent.com", "github.io", "githubassets.com"], "GitHub"),
    ("rustup", &["rustup.rs", "rust-lang.org"], "Rust"),
    ("ohmyz", &["ohmyz.sh"], "Oh My Zsh"),
    ("poetry", &["python-poetry.org"], "Poetry"),
    ("tailscale", &["tailscale.com"], "Tailscale"),
    ("ollama", &["ollama.com", "ollama.ai"], "Ollama"),
    ("pnpm", &["pnpm.io"], "pnpm"),
    ("docker", &["docker.com", "docker.io"], "Docker"),
    ("claude", &["claude.ai", "claude.com", "anthropic.com"], "Claude"),
    ("anthropic", &["anthropic.com", "claude.ai", "claude.com"], "Anthropic"),
    ("apple", &["apple.com", "icloud.com"], "Apple"),
    ("icloud", &["apple.com", "icloud.com"], "Apple"),
];

/// Downloader flags whose value is the next word (so it is not the address).
const VALUE_FLAGS: &[&str] = &[
    "--output", "--output-document", "--header", "--user-agent", "--user", "--data", "--data-binary", "--data-raw", "--form",
    "--referer", "--proxy", "--request", "--cookie", "--cookie-jar", "--max-time", "--connect-timeout", "--retry", "--write-out",
    "--upload-file", "--config", "--directory-prefix", "--resolve", "--connect-to",
];

fn compiled() -> &'static [(usize, Regex)] {
    static RULE_SET: OnceLock<Vec<(usize, Regex)>> = OnceLock::new();
    RULE_SET.get_or_init(|| RULES.iter().enumerate().filter_map(|(i, rule)| Regex::new(rule.2).ok().map(|re| (i, re))).collect())
}

fn re(pattern: &'static str, slot: &'static OnceLock<Regex>) -> &'static Regex {
    slot.get_or_init(|| Regex::new(pattern).expect("a valid built-in pattern"))
}

// ---------------------------------------------------------------------------------------------
// Findings

struct Findings {
    threats: Vec<Threat>,
}

impl Findings {
    /// Add a finding once per rule; one found inside hidden layers is high and says so.
    fn add(&mut self, rule: &str, severity: &str, text: impl Into<String>, hidden: bool) {
        let mut text = text.into();
        let severity = if hidden { "high" } else { severity };
        if hidden {
            text = format!("{} (hidden in encoded text)", text.trim_end_matches('.'));
        }
        if let Some(known) = self.threats.iter_mut().find(|t| t.rule == rule) {
            // The graver case of a rule says it in its own words.
            if severity == "high" && known.severity != "high" {
                known.severity = "high".into();
                known.text = text;
            }
            return;
        }
        self.threats.push(Threat { rule: rule.into(), severity: severity.into(), text });
    }
}

/// One text to scan, and whether it was decoded (not merely nested).
struct Layer {
    text: String,
    depth: usize,
    decoded: bool,
}

/// Scan a command, script or shell block. `pasted`: it came from the clipboard, so encoded and
/// many-step commands and a download run at once read as the stronger warning.
pub fn scan(text: &str, pasted: bool) -> Vec<Threat> {
    let mut found = Findings { threats: Vec::new() };
    hidden_text(text, &mut found);
    let mut layers = vec![Layer { text: text.to_owned(), depth: 0, decoded: false }];
    let mut at = 0;
    let mut decoded_commands = false;
    while at < layers.len() {
        let (text, depth, decoded) = (layers[at].text.clone(), layers[at].depth, layers[at].decoded);
        at += 1;
        rules(&text, decoded, pasted, &mut found);
        if decoded && looks_like_commands(&text) {
            decoded_commands = true;
        }
        if depth < MAX_DEPTH && layers.len() < MAX_LAYERS {
            for (inner, is_decoded) in inner_layers(&text) {
                if layers.len() >= MAX_LAYERS {
                    break;
                }
                if !layers.iter().any(|l| l.text == inner) {
                    layers.push(Layer { text: inner, depth: depth + 1, decoded: decoded || is_decoded });
                }
            }
        }
    }
    if decoded_commands {
        let severity = if pasted { "high" } else { "medium" };
        found.add("encoded", severity, "Hides commands in encoded text (base64 or hex), so what runs is not what is shown.", false);
    }
    if pasted {
        let commands = parse(text).map(|cmds| cmds.len()).unwrap_or(0);
        let downloads = parse(text).map(|cmds| cmds.iter().any(|c| DOWNLOADERS.contains(&program(c).0))).unwrap_or(false);
        if commands >= 4 && downloads {
            found.add("pasted-script", "medium", format!("Pasted from elsewhere, it runs {commands} commands at once and downloads; most Mac malware arrives as a pasted command."), false);
        }
    }
    // High first, then in the order found.
    found.threats.sort_by_key(|t| t.severity != "high");
    found.threats
}

/// A decoded text that reads as shell commands, not as data.
fn looks_like_commands(text: &str) -> bool {
    static WORDS: OnceLock<Regex> = OnceLock::new();
    re(r"\b(curl|wget|sh|bash|zsh|osascript|python3?|perl|chmod|nc|eval|xattr|security|rm|open|hdiutil|launchctl|base64|dscl)\b", &WORDS)
        .is_match(text)
}

// ---------------------------------------------------------------------------------------------
// Layers

/// What `text` holds inside it: (text, decoded).
fn inner_layers(text: &str) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    // Scripts given to a shell or an interpreter, and command substitutions.
    if let Ok(cmds) = parse(text) {
        for cmd in &cmds {
            let (name, args) = program(cmd);
            let script_flag: &[&str] = match name {
                _ if SHELLS.contains(&name) => &["-c"],
                "osascript" => &["-e"],
                "python" | "python3" => &["-c"],
                "perl" | "ruby" | "node" | "php" | "lua" => &["-e", "-r"],
                "su" => &["-c"],
                _ => &[],
            };
            if name == "eval" {
                out.push((args.iter().map(|w| w.text.as_str()).collect::<Vec<_>>().join(" "), false));
            }
            for (i, word) in args.iter().enumerate() {
                let flag = word.text.as_str();
                let takes = script_flag.contains(&flag)
                    || (SHELLS.contains(&name) && flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c'));
                if takes && let Some(script) = args.get(i + 1) {
                    out.push((script.text.clone(), false));
                }
            }
            for word in cmd.words.iter().chain(cmd.redirects.iter().map(|(_, w)| w)) {
                if word.subst {
                    out.extend(substitutions(&word.text).into_iter().map(|s| (s, false)));
                }
            }
        }
        // Text echoed into a shell is the script it runs (`echo "curl … | sh" | sh`).
        for (at, cmd) in cmds.iter().enumerate() {
            let (name, args) = program(cmd);
            let feeds_shell = cmds.get(at + 1).is_some_and(|next| next.piped_in && runs_stdin(next));
            if matches!(name, "echo" | "printf" | "print") && feeds_shell {
                out.push((args.iter().filter(|w| !w.text.starts_with('-')).map(|w| w.text.as_str()).collect::<Vec<_>>().join(" "), false));
            }
        }
    }
    // AppleScript running shell commands.
    static DO_SHELL: OnceLock<Regex> = OnceLock::new();
    for capture in re(r#"(?i)do\s+shell\s+script\s+"((?:[^"\\]|\\.)*)""#, &DO_SHELL).captures_iter(text) {
        out.push((capture[1].replace("\\\"", "\""), false));
    }
    // Escapes: \x63\x75..., \143\165...
    static HEX_ESCAPES: OnceLock<Regex> = OnceLock::new();
    for found in re(r"(\\x[0-9a-fA-F]{2}){4,}", &HEX_ESCAPES).find_iter(text) {
        let bytes: Vec<u8> = found.as_str().split("\\x").filter(|h| !h.is_empty()).filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
        if let Some(text) = printable(&bytes) {
            out.push((text, true));
        }
    }
    static OCTAL_ESCAPES: OnceLock<Regex> = OnceLock::new();
    for found in re(r"(\\[0-3][0-7]{2}){4,}", &OCTAL_ESCAPES).find_iter(text) {
        let bytes: Vec<u8> = found.as_str().split('\\').filter(|o| !o.is_empty()).filter_map(|o| u8::from_str_radix(o, 8).ok()).collect();
        if let Some(text) = printable(&bytes) {
            out.push((text, true));
        }
    }
    // Base64 and hex words.
    static ENCODED: OnceLock<Regex> = OnceLock::new();
    for found in re(r"[A-Za-z0-9+/_-]{16,}={0,2}", &ENCODED).find_iter(text) {
        let word = found.as_str();
        if word.len() < MIN_ENCODED {
            continue;
        }
        if word.len() % 2 == 0
            && word.chars().all(|c| c.is_ascii_hexdigit())
            && let Some(text) = (0..word.len()).step_by(2).map(|i| u8::from_str_radix(&word[i..i + 2], 16).ok()).collect::<Option<Vec<u8>>>().and_then(|b| printable(&b))
        {
            out.push((text, true));
            continue;
        }
        if let Some(text) = base64_text(word) {
            out.push((text, true));
        }
    }
    // Text written in Unicode tag characters (invisible).
    let tags: String = text.chars().filter_map(|c| (0xE0020..=0xE007E).contains(&(c as u32)).then(|| char::from_u32(c as u32 - 0xE0000)).flatten()).collect();
    if !tags.is_empty() {
        out.push((tags, true));
    }
    out.retain(|(t, _)| !t.trim().is_empty() && t != text);
    out
}

/// The commands inside `$(...)` and backticks of a word.
fn substitutions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && chars.get(i + 1) == Some(&'(') && chars.get(i + 2) != Some(&'(') {
            let mut depth = 0;
            let mut j = i + 1;
            while j < chars.len() {
                match chars[j] {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            out.push(chars[i + 2..j.min(chars.len())].iter().collect());
            i = j;
        } else if chars[i] == '`' {
            let end = chars[i + 1..].iter().position(|c| *c == '`').map_or(chars.len(), |p| i + 1 + p);
            out.push(chars[i + 1..end].iter().collect());
            i = end;
        }
        i += 1;
    }
    out
}

fn base64_text(word: &str) -> Option<String> {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    let config = GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let alphabet = if word.contains(['-', '_']) { &base64::alphabet::URL_SAFE } else { &base64::alphabet::STANDARD };
    let trimmed = word.trim_end_matches('=');
    let usable = if trimmed.len() % 4 == 1 { &trimmed[..trimmed.len() - 1] } else { trimmed };
    let bytes = GeneralPurpose::new(alphabet, config).decode(usable).ok()?;
    // A gzip stream inside: say so rather than unpack it.
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some("gzip compressed data, decompressed and run".into());
    }
    printable(&bytes)
}

/// The bytes as text, when they read as text (not random bytes of a hash or a key).
fn printable(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let total = text.chars().count();
    if total < 6 {
        return None;
    }
    let readable = text.chars().filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\n' || *c == '\t').count();
    (readable * 100 / total >= 95 && text.contains([' ', '/', ';', '|'])).then(|| text.to_owned())
}

// ---------------------------------------------------------------------------------------------
// Rules

/// A command's program (wrappers and assignments skipped) and its arguments.
fn program(cmd: &Cmd) -> (&str, &[Word]) {
    let mut words: &[Word] = &cmd.words;
    loop {
        while words.first().is_some_and(|w| is_assignment(&w.text)) {
            words = &words[1..];
        }
        let Some(first) = words.first() else { return ("", &[]) };
        let name = first.text.rsplit('/').next().unwrap_or("");
        if !WRAPPERS.contains(&name) {
            return (name, &words[1..]);
        }
        let mut rest = &words[1..];
        while rest.first().is_some_and(|w| w.text.starts_with('-')) {
            rest = &rest[1..];
        }
        // A bare `env` prints the environment: it is the program then.
        if rest.is_empty() {
            return (name, rest);
        }
        words = rest;
    }
}

/// A shell or an interpreter that runs what comes in on its standard input.
fn runs_stdin(cmd: &Cmd) -> bool {
    let (name, args) = program(cmd);
    let script_arg = args.iter().any(|w| !w.text.starts_with('-'));
    (SHELLS.contains(&name) && (!script_arg || args.iter().any(|w| w.text == "-s" || w.text == "-")))
        || (INTERPRETERS.contains(&name) && (!script_arg || args.iter().any(|w| w.text == "-")))
        || (name == "source" || name == ".") && args.iter().any(|w| w.text == "/dev/stdin")
}

/// `-fsSL`: one or more short flags together.
fn short_flags(text: &str) -> bool {
    text.len() > 1 && text.starts_with('-') && !text.starts_with("--") && text[1..].chars().all(|c| c.is_ascii_alphabetic())
}

fn is_assignment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.starts_with(|c: char| c.is_ascii_digit()))
}

/// The secrets a word names, by their plain name.
fn secret_in(text: &str) -> Option<&'static str> {
    // The whole word first: a quoted path may hold spaces (`Application Support/…/Login Data`).
    for (whole, piece) in std::iter::once((true, text)).chain(text.split(|c: char| c.is_whitespace() || "\"'()`;|<>,".contains(c)).map(|p| (false, p))) {
        let path = piece.rsplit('@').next().unwrap_or(piece);
        let path = if path.contains('=') && !path.contains('/') { path.rsplit('=').next().unwrap_or(path) } else { path };
        // A public key is meant to be shared.
        if path.ends_with(".pub") {
            continue;
        }
        for (part, name) in SECRETS {
            let hit = if whole && !part.contains(['/', ' ']) {
                false
            } else if part.contains('/') {
                path.contains(part)
            } else {
                path.split('/').any(|component| component == *part || (*part == ".env" && component.starts_with(".env.") && !component.ends_with(".example")))
            };
            if hit {
                return Some(name);
            }
        }
    }
    None
}

/// The host of the first URL in a command's words.
fn host(words: &[Word]) -> Option<String> {
    words.iter().find_map(|w| {
        let rest = w.text.split_once("://").map(|(_, rest)| rest)?;
        Some(rest.split(['/', ':', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("").to_lowercase())
    })
}

/// A public raw IPv4 address (not this Mac or a private network).
fn public_ip(host: &str) -> bool {
    let parts: Vec<u8> = host.split('.').filter_map(|p| p.parse().ok()).collect();
    parts.len() == 4
        && host.split('.').count() == 4
        && !matches!(parts[..], [127, ..] | [10, ..] | [192, 168, ..] | [169, 254, ..] | [0, ..])
        && !(parts[0] == 172 && (16..=31).contains(&parts[1]))
}

/// A command that sends data out: `Some(reads standard input)`.
fn uploads(name: &str, args: &[Word]) -> Option<bool> {
    let text: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
    match name {
        "curl" => {
            let sends = text.iter().any(|t| {
                matches!(*t, "-d" | "-F" | "-T" | "--json" | "--form" | "--upload-file")
                    || t.starts_with("--data")
                    || t.starts_with("--form")
                    || (t.starts_with("-d") && t.len() > 2 && !t.starts_with("--"))
                    || (t.starts_with("-F") && t.len() > 2)
            });
            sends.then(|| text.iter().any(|t| t.ends_with("@-") || *t == "-" || *t == "@/dev/stdin"))
        }
        "wget" => text.iter().any(|t| t.starts_with("--post-file") || t.starts_with("--post-data") || t.starts_with("--body-file")).then_some(false),
        "nc" | "ncat" | "netcat" | "socat" | "telnet" => Some(true),
        "scp" | "rsync" | "sftp" | "ftp" => text.iter().any(|t| t.contains(':') && !t.starts_with('-')).then_some(false),
        "ssh" => Some(true),
        _ => None,
    }
}

/// The secret a network command sends itself (not one it only uses, like `ssh -i ~/.ssh/key`).
fn sent_secret(name: &str, args: &[Word], redirects: &[(String, Word)]) -> Option<&'static str> {
    let input = redirects.iter().filter(|(op, _)| op == "<").find_map(|(_, w)| secret_in(&w.text));
    let after = |i: usize, flags: &[&str]| i > 0 && flags.contains(&args[i - 1].text.as_str());
    match name {
        "curl" => {
            const DATA: &[&str] = &["-d", "-F", "-T", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "--form", "--form-string", "--json", "--upload-file"];
            let sent = args.iter().enumerate().find_map(|(i, w)| {
                let attached = DATA.iter().any(|flag| w.text.len() > flag.len() && w.text.starts_with(flag) && (flag.len() == 2 || w.text[flag.len()..].starts_with('=')));
                (after(i, DATA) || attached).then(|| secret_in(&w.text)).flatten()
            });
            sent.or(if uploads(name, args) == Some(true) { input } else { None })
        }
        "wget" => args.iter().enumerate().find_map(|(i, w)| {
            (after(i, &["--post-file", "--body-file"]) || w.text.starts_with("--post-file=") || w.text.starts_with("--body-file=")).then(|| secret_in(&w.text)).flatten()
        }),
        "scp" | "rsync" | "sftp" if uploads(name, args).is_some() => {
            const VALUES: &[&str] = &["-i", "-F", "-o", "-e", "-P", "-S", "-J", "--rsh", "-c"];
            args.iter().enumerate().find_map(|(i, w)| (!w.text.starts_with('-') && !after(i, VALUES) && !w.text.contains(':')).then(|| secret_in(&w.text)).flatten())
        }
        "nc" | "ncat" | "netcat" | "socat" | "telnet" => input,
        _ => None,
    }
}

fn rules(text: &str, decoded: bool, pasted: bool, found: &mut Findings) {
    for (index, regex) in compiled() {
        if regex.is_match(text) {
            let (rule, severity, _, sentence) = RULES[*index];
            found.add(rule, severity, sentence, decoded);
        }
    }
    // A download substituted into a shell or an interpreter: `sh -c "$(curl …)"`, `bash <(curl …)`,
    // `osascript -e "$(curl …)"`, `eval "$(curl …)"`. Read from the text: `<(…)` does not parse.
    static FETCH_SUBST: OnceLock<Regex> = OnceLock::new();
    let fetch_subst = re(
        r#"(?m)(?:^|[\s;&|(/'"`])(?:eval|source|\.|(?:ba|z|da|k)?sh|python[0-9.]*|perl|ruby|node|php|osascript)(?:\s+-(?:l\s+\w+|[A-Za-z-]+))*\s+['"]?(?:\$\(|`|<\()\s*(?:sudo\s+)?(?:curl|wget|fetch)\b([^)`]*)"#,
        &FETCH_SUBST,
    );
    for capture in fetch_subst.captures_iter(text) {
        let url = parse(&capture[1]).ok().and_then(|cmds| cmds.first().and_then(|cmd| url_in(&cmd.words)).map(str::to_owned));
        fetched_and_run(found, "pipe-to-shell", url.as_deref(), None, pasted, decoded);
    }
    let Ok(cmds) = parse(text) else { return };
    // In order: a download saved to a file, or a quarantine flag removed, then that file run.
    let mut saved: Vec<(String, Option<String>)> = Vec::new();
    let mut unchecked: Vec<String> = Vec::new();
    for cmd in &cmds {
        let (name, args) = program(cmd);
        if DOWNLOADERS.contains(&name) {
            let url = url_in(args).map(str::to_owned);
            if let Some(file) = saved_file(name, args, &cmd.redirects, url.as_deref()) {
                saved.push((file, url));
            }
            continue;
        }
        let stripping = name == "xattr" && args.iter().any(|w| short_flags(&w.text) && w.text.contains(['c', 'd']));
        if stripping && (args.iter().any(|w| w.text == "com.apple.quarantine") || args.iter().any(|w| short_flags(&w.text) && w.text.contains('c'))) {
            unchecked.extend(args.iter().filter(|w| !w.text.starts_with('-') && w.text != "com.apple.quarantine").map(|w| w.text.clone()));
            continue;
        }
        let Some(ran) = ran_file(cmd) else { continue };
        if let Some((file, url)) = saved.iter().find(|(file, _)| same_file(file, &ran)) {
            fetched_and_run(found, "download-and-run", url.as_deref(), Some(file), pasted, decoded);
        }
        if let Some(file) = unchecked.iter().find(|file| same_file(file, &ran)) {
            let file = file.rsplit('/').find(|part| !part.is_empty()).unwrap_or(file);
            found.add(
                "quarantine-then-run",
                "high",
                format!("Removes macOS's download check from {file} and then opens it, so Gatekeeper never looks at it. Fake installers ask for exactly this; open it from Finder instead, and macOS checks it first."),
                decoded,
            );
        }
    }
    // Pipelines: commands joined by `|`.
    let mut pipelines: Vec<Vec<&Cmd>> = Vec::new();
    for cmd in &cmds {
        match pipelines.last_mut() {
            Some(last) if cmd.piped_in => last.push(cmd),
            _ => pipelines.push(vec![cmd]),
        }
    }
    let mut secret_named: Option<&'static str> = None;
    let mut exfil_host: Option<String> = None;
    for cmd in &cmds {
        let (name, args) = program(cmd);
        if NETWORK_SINKS.contains(&name) || DOWNLOADERS.contains(&name) {
            let host = host(args);
            if let Some(host) = &host {
                if let Some(known) = EXFIL_HOSTS.iter().find(|h| args.iter().any(|w| w.text.contains(**h))) {
                    exfil_host = Some((*known).to_owned());
                    found.add("exfil-host", "medium", format!("Talks to {known}, a service malware often uses to send stolen data."), decoded);
                }
                if public_ip(host) {
                    found.add("raw-ip", "medium", format!("Connects to a bare IP address ({host}) instead of a named site, as malware servers do."), decoded);
                }
                if host.starts_with("xn--") || host.contains(".xn--") {
                    found.add("lookalike-domain", "medium", format!("Uses an encoded international web address ({host}), which can imitate a known site."), decoded);
                }
            }
            let sent = sent_secret(name, args, &cmd.redirects);
            if let Some(what) = sent {
                let to = host.map(|h| format!(" to {h}")).unwrap_or_default();
                found.add("secrets-sent", "high", format!("Sends {what}{to} over the network."), decoded);
            } else if let Some(drop) = &exfil_host
                && uploads(name, args).is_some()
            {
                found.add("upload-exfil-host", "high", format!("Uploads data to {drop}, a service malware uses to collect stolen files."), decoded);
            }
        } else if let Some(what) = args.iter().chain(cmd.redirects.iter().map(|(_, w)| w)).find_map(|w| secret_in(&w.text)) {
            secret_named = secret_named.or(Some(what));
        } else if name == "security" && reads_keychain(args) {
            secret_named = secret_named.or(Some("your keychain passwords"));
        }
    }
    // A secret collected anywhere and an upload to a known drop service anywhere in the same text.
    if let (Some(what), Some(host)) = (secret_named, &exfil_host) {
        found.add("secrets-sent", "high", format!("Collects {what} and sends them to {host}."), decoded);
    }
    for pipeline in &pipelines {
        let mut source: Option<&'static str> = None;
        let mut downloaded: Option<Option<String>> = None;
        let mut decoder = false;
        for cmd in pipeline {
            let (name, args) = program(cmd);
            let runs_stdin = runs_stdin(cmd);
            if runs_stdin && let Some(url) = &downloaded {
                fetched_and_run(found, "pipe-to-shell", url.as_deref(), None, pasted, decoded);
            }
            if runs_stdin && decoder {
                found.add("decode-to-shell", "high", "Decodes hidden text and runs it as commands.", decoded);
            }
            if let Some(what) = source
                && uploads(name, args) == Some(true)
            {
                let to = host(args).map(|h| format!(" to {h}")).unwrap_or_default();
                found.add("secrets-sent", "high", format!("Sends {what}{to} over the network."), decoded);
            }
            if DOWNLOADERS.contains(&name) {
                downloaded = Some(url_in(args).map(str::to_owned));
            }
            static ESCAPES: OnceLock<Regex> = OnceLock::new();
            let decodes = (name == "base64" && args.iter().any(|w| matches!(w.text.as_str(), "-d" | "-D" | "--decode") || (short_flags(&w.text) && w.text.contains(['d', 'D']))))
                || (name == "xxd" && args.iter().any(|w| w.text.starts_with("-r")))
                || (name == "openssl" && args.iter().any(|w| w.text == "-d"))
                || (matches!(name, "printf" | "echo" | "print") && args.iter().any(|w| re(r"\\(x[0-9a-fA-F]{2}|[0-7]{3}|u[0-9a-fA-F]{4})", &ESCAPES).is_match(&w.text)))
                || matches!(name, "gunzip" | "zcat" | "uudecode" | "rev");
            decoder |= decodes;
            let named = if NETWORK_SINKS.contains(&name) { None } else { args.iter().chain(cmd.redirects.iter().map(|(_, w)| w)).find_map(|w| secret_in(&w.text)) };
            if named.is_some() {
                source = source.or(named);
            } else if matches!(name, "env" | "printenv") && args.is_empty() {
                source = source.or(Some("your environment variables (tokens and keys)"));
            } else if name == "security" && reads_keychain(args) {
                source = source.or(Some("your keychain passwords"));
            }
        }
    }
}

/// `security find-…-password -w` (or `-wa`, `-g`) and `dump-keychain`: prints saved passwords.
fn reads_keychain(args: &[Word]) -> bool {
    args.iter().any(|w| w.text == "dump-keychain" || (short_flags(&w.text) && w.text.contains(['w', 'g'])))
}

// ---------------------------------------------------------------------------------------------
// Downloaded and run

/// The address a downloader fetches: the first word with `://`, else the first operand that
/// reads as a host (`curl sh.rustup.rs`), skipping flags and their values.
fn url_in(args: &[Word]) -> Option<&str> {
    if let Some(word) = args.iter().find(|w| w.text.contains("://")) {
        return Some(&word.text);
    }
    let mut skip = false;
    for word in args {
        let text = word.text.as_str();
        if std::mem::take(&mut skip) {
            continue;
        }
        if text.starts_with('-') {
            skip = VALUE_FLAGS.contains(&text) || (short_flags(text) && text.ends_with(['o', 'O', 'H', 'A', 'u', 'd', 'F', 'e', 'x', 'X', 'b', 'm', 'w', 'T', 'K', 'P', 'U']));
            continue;
        }
        let head = text.split('/').next().unwrap_or("");
        if head.contains('.') && !head.starts_with(['.', '-']) && head.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':')) {
            return Some(text);
        }
    }
    None
}

/// A web address taken apart: host (lowercase, without user, port or final dot) and path (without
/// query), so a match is never by substring (`brew.sh@evil.example`, `brew.sh.evil.example`).
struct Url {
    host: String,
    path: String,
    http: bool,
    /// `https://brew.sh@evil.example/`: the name before `@` is not where it goes.
    masked: bool,
}

fn parse_url(text: &str) -> Option<Url> {
    let text = text.trim_matches(|c: char| "'\"()`;".contains(c));
    let (scheme, rest) = match text.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => (String::new(), text),
    };
    if !matches!(scheme.as_str(), "" | "http" | "https" | "ftp") {
        return None;
    }
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let masked = rest[..end].contains('@');
    let authority = rest[..end].rsplit('@').next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    let host = host.trim_end_matches('.').to_lowercase();
    let path = rest[end..].split(['?', '#']).next().unwrap_or("").to_owned();
    (!host.is_empty()).then_some(Url { host, path, http: scheme == "http", masked })
}

/// `host` is `domain` or one of its subdomains.
fn under(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.'))
}

/// A host written as an IP address (dotted, one number, hex, or IPv6).
fn ip_literal(host: &str) -> bool {
    host.contains(':')
        || host.chars().all(|c| c.is_ascii_digit())
        || host.starts_with("0x")
        || (host.split('.').count() == 4 && host.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_hexdigit() || c == 'x')))
}

/// The host as a person should read it: letters from another alphabet named, not drawn.
fn visible(host: &str) -> String {
    host.chars()
        .map(|c| {
            if c.is_ascii() {
                return c.to_string();
            }
            let script = match c as u32 {
                0x0370..=0x03FF => "Greek ",
                0x0400..=0x052F => "Cyrillic ",
                0xFF00..=0xFFEF => "full-width ",
                0x1D400..=0x1D7FF => "math ",
                _ => "",
            };
            format!("[{script}{c} U+{:04X}]", c as u32)
        })
        .collect()
}

/// Letters to change to turn one name into the other.
fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut last = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let next = (row[j + 1] + 1).min(row[j] + 1).min(last + usize::from(ca != cb));
            last = row[j + 1];
            row[j + 1] = next;
        }
    }
    row[b.len()]
}

/// Where a script comes from: how to show it, whether it is an official installer, and what
/// makes the address suspect, when something does.
struct Origin {
    shown: String,
    official: bool,
    why: Option<String>,
}

fn origin(url: Option<&str>) -> Origin {
    let Some(url) = url.and_then(parse_url) else {
        return Origin { shown: "an address only known when it runs".into(), official: false, why: None };
    };
    let host = url.host.as_str();
    let path = url.path.to_lowercase();
    let official = !url.http
        && OFFICIAL_INSTALLERS.iter().any(|(h, p)| {
            *h == host
                && (p.is_empty() && path.len() <= 1 || p.ends_with('/') && path.starts_with(p) || !p.is_empty() && path == *p)
        });
    // Whose GitHub account a raw script is from.
    let shown = match url.path.split('/').nth(1).filter(|owner| !owner.is_empty()) {
        Some(owner) if matches!(host, "raw.githubusercontent.com" | "gist.githubusercontent.com" | "github.com") => format!("{}/{owner}", visible(host)),
        _ => visible(host),
    };
    let why = if official {
        None
    } else if url.masked {
        Some(format!("The name before its @ is a disguise: it really goes to {}.", visible(host)))
    } else if !host.is_ascii() {
        Some("Its address uses look-alike letters from another alphabet, so it imitates a site you know.".to_owned())
    } else if host.starts_with("xn--") || host.contains(".xn--") {
        Some("Its address is an encoded international name (xn--), which can imitate a site you know.".to_owned())
    } else if ip_literal(host) {
        Some("It is a bare IP address, not a named site.".to_owned())
    } else if let Some(real) = OFFICIAL_INSTALLERS.iter().map(|(h, _)| *h).find(|real| real.len() >= 8 && (1..=2).contains(&distance(host, real))) {
        Some(format!("Its address is a letter or two away from {real}, so it imitates it."))
    } else if let Some((_, _, name)) = IMITATED.iter().find(|(word, owners, _)| {
        let named = if word.len() < 5 { host.split(['.', '-']).any(|label| label == *word) } else { host.contains(word) };
        named && !owners.iter().any(|owner| under(host, owner))
    }) {
        Some(format!("Its address borrows {name}'s name but is not {name}'s site."))
    } else if let Some((_, why)) = SUSPECT_SITES.iter().find(|(domains, _)| domains.iter().any(|d| under(host, d))) {
        Some((*why).to_owned())
    } else if host.ends_with(".zip") || host.ends_with(".mov") {
        Some("Its address ends like a file name (.zip, .mov), which makes it easy to misread.".to_owned())
    } else if url.http {
        Some("It comes over plain http, so anyone on the network can change it on the way.".to_owned())
    } else {
        None
    };
    Origin { shown, official, why }
}

/// A script or program downloaded and run in one go. From an official installer address it is the
/// ordinary "runs code from the internet" (medium: the person approves it). From anywhere else
/// it is the paste-and-run lure Mac password stealers use (high: held, and refused without the
/// person). `saved_as`: it was saved to that file first, then run.
fn fetched_and_run(found: &mut Findings, rule: &str, url: Option<&str>, saved_as: Option<&str>, pasted: bool, decoded: bool) {
    let origin = origin(url);
    let shown = &origin.shown;
    if origin.official {
        // Saved first, the person can read it: nothing to warn about.
        if saved_as.is_none() {
            found.add(rule, "medium", format!("Downloads the installer from {shown}, its official address, and runs it at once without showing it."), decoded);
        }
        return;
    }
    let what = match saved_as {
        Some(file) => format!("Downloads a program from {shown}, saves it as {} and runs it.", file.rsplit('/').find(|p| !p.is_empty()).unwrap_or(file)),
        None => format!("Downloads a script from {shown} and runs it without saving it."),
    };
    let why = origin.why.map(|why| format!(" {why}")).unwrap_or_default();
    let pasted = if pasted { " It was pasted, as those pages ask." } else { "" };
    found.add(
        rule,
        "high",
        format!("{what}{why} This is how Mac password stealers get in: a web page asks you to paste one command into Terminal.{pasted} Safer: download it and read it first, or install from the program's official site."),
        decoded,
    );
}

/// The file a downloader saves to (`-o`, `-O`, `--output`, `> file`, wget's own name).
fn saved_file(name: &str, args: &[Word], redirects: &[(String, Word)], url: Option<&str>) -> Option<String> {
    let remote_name = || url.and_then(parse_url).and_then(|u| u.path.rsplit('/').next().filter(|n| !n.is_empty()).map(str::to_owned));
    let (output, remote) = match name {
        "curl" => ('o', Some('O')),
        "wget" => ('O', None),
        _ => return redirects.iter().find(|(op, _)| op == ">" || op == ">|").map(|(_, w)| w.text.clone()),
    };
    let long = if name == "curl" { "--output" } else { "--output-document" };
    for (i, word) in args.iter().enumerate() {
        let text = word.text.as_str();
        let file = if text == long || (short_flags(text) && text.ends_with(output)) {
            args.get(i + 1).map(|w| w.text.as_str())
        } else if let Some(value) = text.strip_prefix(long).and_then(|rest| rest.strip_prefix('=')) {
            Some(value)
        } else if text.len() > 2 && text.starts_with(['-']) && text[1..].starts_with(output) && !short_flags(text) {
            Some(&text[2..])
        } else if remote.is_some_and(|flag| text == "--remote-name" || (short_flags(text) && text.contains(flag))) {
            return remote_name();
        } else {
            None
        };
        if let Some(file) = file {
            return (file != "-").then(|| file.to_owned());
        }
    }
    if let Some((_, target)) = redirects.iter().find(|(op, _)| op == ">" || op == ">|") {
        return Some(target.text.clone());
    }
    // wget saves under the address's own name.
    (name == "wget").then(remote_name).flatten()
}

/// The file a command runs or opens: the program itself, a shell's or interpreter's script, what
/// `open`, `installer` or `hdiutil attach` is given.
fn ran_file(cmd: &Cmd) -> Option<String> {
    let (name, args) = program(cmd);
    if name.is_empty() {
        return None;
    }
    let operand = |from: usize| args.iter().skip(from).find(|w| !w.text.starts_with('-')).map(|w| w.text.clone());
    if SHELLS.contains(&name) || INTERPRETERS.contains(&name) || matches!(name, "source" | "." | "open" | "installer") {
        return operand(0);
    }
    if name == "hdiutil" {
        return args.first().filter(|w| matches!(w.text.as_str(), "attach" | "mount")).and_then(|_| operand(1));
    }
    cmd.words.get(cmd.words.len() - args.len() - 1).map(|w| w.text.clone())
}

/// The same file, as far as one command line can tell (`./tool` and `tool`, any case).
fn same_file(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.trim_start_matches("./").trim_end_matches('/').to_lowercase();
    let (a, b) = (norm(a), norm(b));
    let base = |s: &str| s.rsplit('/').next().unwrap_or("").to_owned();
    !a.is_empty() && (a == b || ((!a.contains('/') || !b.contains('/')) && base(&a) == base(&b)))
}

// ---------------------------------------------------------------------------------------------
// Hidden text

/// Zero-width and invisible formatting characters.
fn zero_width(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' | '\u{180E}' | '\u{00AD}' | '\u{034F}' | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}')
}

/// Characters that change the direction text is drawn in.
fn bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}

fn tag(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// Invisible characters of any of those kinds.
pub fn invisible(c: char) -> bool {
    zero_width(c) || bidi(c) || tag(c)
}

/// Control characters that are not plain layout (tab, newline).
fn control(c: char) -> bool {
    (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || ('\u{80}'..='\u{9F}').contains(&c)
}

fn hidden_text(text: &str, found: &mut Findings) {
    if text.chars().any(tag) {
        let hidden: String = text.chars().filter_map(|c| tag(c).then(|| char::from_u32(c as u32 - 0xE0000)).flatten()).filter(|c| !c.is_control()).collect();
        let shown: String = hidden.chars().take(80).collect();
        found.add("hidden-text", "high", format!("Holds invisible text only a program can read: \u{201C}{shown}\u{201D}."), false);
    }
    if text.chars().any(bidi) {
        found.add("direction-marks", "high", "Holds characters that reverse how the text is drawn, so it reads differently from what runs.", false);
    }
    if text.chars().any(zero_width) {
        found.add("zero-width", "high", "Holds invisible zero-width characters, so what you see is not exactly what runs.", false);
    }
    if text.contains('\u{1b}') || text.chars().any(control) || text.contains("\r") && text.split('\r').skip(1).any(|rest| !rest.starts_with('\n')) {
        found.add("terminal-codes", "high", "Holds terminal control codes that can hide part of the command from view.", false);
    }
    // Web addresses with look-alike letters (Cyrillic `а` for Latin `a`).
    static URL_HOSTS: OnceLock<Regex> = OnceLock::new();
    for capture in re(r"(?i)[a-z][a-z0-9+.-]*://([^/\s:'\x22?#@]+)", &URL_HOSTS).captures_iter(text) {
        let host = &capture[1];
        if host.is_ascii() {
            continue;
        }
        // Latin mixed with Greek or Cyrillic, or full-width and mathematical letters.
        let latin = host.chars().any(|c| c.is_ascii_alphabetic());
        let other = host.chars().any(|c| matches!(c as u32, 0x0370..=0x052F));
        let odd = host.chars().any(|c| matches!(c as u32, 0xFF00..=0xFFEF | 0x1D400..=0x1D7FF));
        if (latin && other) || odd {
            found.add("lookalike-domain", "high", format!("The web address {} uses look-alike letters from another alphabet, so it may imitate a site you know.", visible(host)), false);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Output for the model

/// Terminal output as plain text: escape sequences (colours, cursor moves, titles) removed, other
/// control characters and invisible Unicode dropped. Returns the text and whether anything hidden
/// (not an ordinary colour code) was taken out.
pub fn clean(text: &str) -> (String, bool) {
    clean_keeping(text, false)
}

/// The same, keeping the colour codes (`ESC[...m`), for the coloured copy of a line.
pub fn clean_ansi(text: &str) -> String {
    clean_keeping(text, true).0
}

fn clean_keeping(text: &str, sgr: bool) -> (String, bool) {
    if text.is_ascii() && !text.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
        return (text.to_owned(), false);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut hidden = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1b}' {
            match chars.get(i + 1) {
                Some('[') => {
                    let mut j = i + 2;
                    while j < chars.len() && !('\u{40}'..='\u{7e}').contains(&chars[j]) {
                        j += 1;
                    }
                    if sgr && chars.get(j) == Some(&'m') {
                        out.extend(&chars[i..=j]);
                    } else if chars.get(j) != Some(&'m') {
                        hidden = true;
                    }
                    i = j + 1;
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    // OSC and string sequences end with BEL or ESC \.
                    let mut j = i + 2;
                    while j < chars.len() && chars[j] != '\u{7}' && !(chars[j] == '\u{1b}' && chars.get(j + 1) == Some(&'\\')) {
                        j += 1;
                    }
                    hidden = true;
                    i = if chars.get(j) == Some(&'\u{1b}') { j + 2 } else { j + 1 };
                }
                Some(_) => {
                    hidden = true;
                    i += 2;
                }
                None => i += 1,
            }
            continue;
        }
        if c == '\t' || !(control(c) || c == '\r' || c == '\n' || c == '\u{7f}' || invisible(c)) {
            out.push(c);
        } else {
            hidden = true;
        }
        i += 1;
    }
    (out, hidden)
}
