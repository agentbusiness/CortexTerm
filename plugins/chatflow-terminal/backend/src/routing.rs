//! App-local skill selection. The complete catalog stays in the host, not in the prompt.
//! No model call, embedding service, or change to skills@1 is needed to find a task card.

use cc_protocol::contracts::{model::ChatMessage, skills::SkillInfo};
use std::collections::BTreeSet;

pub type Entry = (String, SkillInfo);
pub const SHORTLIST: usize = 5;
pub const MAX_SKILL_BYTES: usize = 12_000;
pub const MAX_SKILL_READS: usize = 2;
pub const MAX_LOOKUPS: usize = 4;

#[derive(Debug, Clone)]
pub struct Choice {
    pub index: usize,
    pub score: usize,
    pub explicit: bool,
}

pub fn key(entry: &Entry) -> String {
    format!("{}/{}", entry.0, entry.1.name)
}

/// Qualified names never collide. A short name is accepted only when it is unique.
pub fn resolve(entries: &[Entry], name: &str) -> Option<usize> {
    if let Some(index) = entries.iter().position(|entry| key(entry) == name) {
        return Some(index);
    }
    let mut found = entries.iter().enumerate().filter(|(_, entry)| entry.1.name == name);
    let index = found.next()?.0;
    found.next().is_none().then_some(index)
}

fn canonical(word: &str) -> &str {
    match word {
        "postgresql" | "psql" | "pg" | "pgdump" | "pgrestore" => "postgres",
        "mariadb" | "mysqld" | "mysqldump" => "mysql",
        "sqlite3" => "sqlite",
        "mongodb" | "mongosh" | "mongod" | "bson" => "mongo",
        "cypher" => "neo4j",
        "cql" | "cqlsh" | "nodetool" => "cassandra",
        "valkey" => "redis",
        "karka" | "kraft" => "kafka",
        "elasticsearch" | "opensearch" | "esql" => "elastic",
        "pgvector" | "qdrant" | "weaviate" | "milvus" | "chromadb" | "embeddings" => "vector",
        "ngix" | "ngnix" => "nginx",
        "containers" | "container" | "podman" => "docker",
        "k8s" | "kubectl" | "helm" => "kubernetes",
        "opentofu" | "tofu" => "terraform",
        "amazon" => "aws",
        "googlecloud" => "gcp",
        "minio" | "r2" => "s3",
        "twenty" | "espocrm" | "suitecrm" => "crm",
        "erpnext" | "odoo" => "erp",
        "wordpress" | "ghost" | "strapi" | "directus" => "cms",
        "keycloak" | "authentik" | "oidc" | "sso" => "identity",
        "prometheus" | "grafana" | "loki" | "opentelemetry" | "otel" => "observability",
        "llamacpp" => "llama",
        "openwebui" => "webui",
        "flowise" | "langflow" => "dify",
        "retrieval" => "rag",
        "python3" | "pip" | "pip3" | "venv" | "uv" | "pipx" => "python",
        "nodejs" | "npm" | "pnpm" | "yarn" | "nvm" => "node",
        "yml" => "yaml",
        "json5" => "jsonc",
        "dotenv" => "env",
        "tsv" => "csv",
        "ndjson" => "jsonl",
        "sshd" | "scp" | "sftp" => "ssh",
        "launchctl" | "launchagents" | "launchdaemons" => "launchd",
        "systemctl" | "journalctl" => "systemd",
        "installing" | "installation" | "installed" | "setup" | "provision" => "install",
        "connecting" | "connection" | "connections" | "refused" | "unreachable" => "connect",
        "authentication" | "credentials" | "password" | "login" | "grants" | "roles" => "auth",
        "queries" | "select" | "joins" => "query",
        "aggregation" | "pipeline" => "aggregate",
        "tables" | "columns" | "schemas" | "migration" | "migrations" => "schema",
        "indexes" | "indexing" => "index",
        "slow" | "latency" | "tuning" | "optimize" | "optimise" => "performance",
        "blocked" | "blocking" | "deadlock" | "deadlocks" | "locks" => "lock",
        "backups" | "dump" | "restore" | "restoring" | "recovery" => "backup",
        "replicas" | "replica" | "standby" => "replication",
        "updating" | "update" | "upgrading" => "upgrade",
        "configuration" | "configure" | "configured" | "settings" => "config",
        "editing" | "modify" | "replace" | "change" => "edit",
        "files" | "paths" | "folders" | "directories" => "file",
        "searching" | "locate" => "find",
        "permissions" | "ownership" | "chmod" | "chown" => "permission",
        "processes" | "pid" | "cpu" => "process",
        "ram" | "swap" | "oom" => "memory",
        "ports" | "listener" | "listening" => "port",
        "logging" | "logs" => "log",
        "certificates" | "certificate" | "https" | "ssl" => "tls",
        "firewalls" | "ufw" | "nftables" | "iptables" | "firewalld" => "firewall",
        "services" | "daemon" | "daemons" => "service",
        "start" | "starting" | "restart" | "restarting" | "stopped" | "crash" | "crashes" | "crashing" => "startup",
        "deploying" | "deployment" | "deployments" => "deploy",
        "scheduling" | "scheduled" | "cron" | "crontab" | "timers" => "schedule",
        "scripts" | "scripting" | "automation" => "script",
        other => other,
    }
}

fn words(text: &str) -> BTreeSet<String> {
    text.chars().take(12_000).collect::<String>().to_lowercase().replace("open web ui", "webui")
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| word.len() > 1)
        .map(canonical)
        .filter(|word| !matches!(*word, "the" | "and" | "for" | "with" | "from" | "this" | "that" | "what" | "which" | "how" | "can" | "you" | "please" | "help" | "want" | "need" | "does" | "have" | "has" | "not" | "its" | "are" | "was" | "use" | "using" | "user" | "their" | "them" | "read" | "run" | "when" | "why" | "into" | "before" | "after" | "only" | "one" | "all"))
        .map(str::to_owned).collect()
}

fn product(word: &str) -> bool {
    matches!(word, "postgres" | "mysql" | "sqlite" | "mongo" | "neo4j" | "cassandra" | "redis" | "kafka" | "rabbitmq" | "nats" | "elastic" | "vector" | "nginx" | "haproxy" | "docker" | "kubernetes" | "terraform" | "ansible" | "aws" | "azure" | "gcp" | "s3" | "crm" | "erp" | "cms" | "identity" | "observability" | "ollama" | "llama" | "vllm" | "webui" | "dify" | "n8n" | "mcp" | "rag" | "git" | "python" | "node" | "toml" | "yaml" | "json" | "jsonc" | "jsonl" | "xml" | "ini" | "env" | "plist" | "hcl" | "csv" | "ssh" | "systemd" | "launchd")
}

fn platform(query: &BTreeSet<String>, context: &str) -> Option<&'static str> {
    let linux = query.iter().any(|s| matches!(s.as_str(), "linux" | "ubuntu" | "debian" | "fedora" | "alpine" | "rhel" | "centos"));
    let mac = query.iter().any(|s| matches!(s.as_str(), "mac" | "macos" | "darwin" | "osx"));
    if linux && mac { return None; }
    if linux { return Some("linux"); }
    if mac { return Some("macos"); }
    // A remote target's OS is unknown until checked; the client OS does not establish it.
    if query.iter().any(|s| matches!(s.as_str(), "remote" | "server" | "vps" | "ssh")) { return None; }
    if context.starts_with("Runner system: macOS") { Some("macos") }
    else if context.starts_with("Runner system: Linux") { Some("linux") }
    else { None }
}

pub fn select(query: &str, context: &str, entries: &[Entry]) -> Vec<Choice> {
    let query_words = words(query);
    let context_words = words(context);
    let products: BTreeSet<_> = query_words.iter().filter(|word| product(word)).cloned().collect();
    let os = platform(&query_words, context);
    let lower = query.to_lowercase();
    let compose_task = query_words.contains("compose") && (
        query_words.iter().any(|word| matches!(word.as_str(), "docker" | "stack" | "startup" | "up" | "down" | "service"))
        || lower.contains("compose.yaml") || lower.contains("compose.yml")
        || context.lines().any(|line| line.starts_with("The command:") && (line.contains("docker compose") || line.contains("podman compose")))
    );
    let mut choices = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let name_words = words(&entry.1.name);
        let summary_words = words(&entry.1.summary);
        let explicit = lower.split_whitespace().any(|word| word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '/') == entry.1.name || word == key(entry));
        let mac_only = entry.0 == "skills-mac-security" || entry.1.name == "macos" || entry.1.name.ends_with("-macos");
        let linux_only = entry.1.name.ends_with("-linux");
        if !explicit && ((mac_only && os != Some("macos")) || (linux_only && os == Some("macos"))) { continue; }
        let own_products: BTreeSet<_> = name_words.iter().filter(|word| product(word)).cloned().collect();
        if !explicit && !products.is_empty() && !own_products.is_empty() && own_products.is_disjoint(&products) { continue; }
        let mut score = if explicit { 10_000 } else { 0 };
        for word in &query_words {
            if name_words.contains(word) { score += if product(word) { 36 } else { 14 }; }
            if summary_words.contains(word) { score += if product(word) { 12 } else { 3 }; }
        }
        if query_words.contains("startup") && (own_products.is_empty() || !own_products.is_disjoint(&products)) {
            if entry.1.name.starts_with("db-") && entry.1.name.ends_with("-install") { score += 28; }
            if entry.1.name.starts_with("db-") && entry.1.name.ends_with("-connect") { score += 12; }
            if matches!(entry.1.name.as_str(), "system-services-linux" | "system-services-macos" | "web-nginx" | "web-haproxy" | "ai-serving" | "docker") { score += 18; }
        }
        if compose_task && entry.1.name == "web-compose" { score += 48; }
        if query_words.contains("hba") && entry.1.name == "db-postgres-auth" { score += 48; }
        if products.contains("redis") && query_words.iter().any(|word| matches!(word.as_str(), "scan" | "keys" | "ttl" | "expire" | "hash" | "stream")) && entry.1.name == "cache-redis-data" { score += 36; }
        if (query_words.contains("edit") || query_words.contains("config")) && entry.1.name == "config-edit" { score += 40; }
        // Current wording outranks old commands. Context only breaks an already relevant tie.
        if score > 0 {
            score += name_words.intersection(&context_words).count().min(4);
            if entry.1.name.starts_with("config-") && !query_words.contains("config") && !query_words.contains("edit") { score = score.saturating_sub(12); }
            if score > 0 { choices.push(Choice { index, score, explicit }); }
        }
    }
    choices.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| key(&entries[a.index]).cmp(&key(&entries[b.index]))));
    choices.truncate(SHORTLIST);
    choices
}

pub fn automatic(choices: &[Choice]) -> Option<usize> {
    let first = choices.first()?;
    let next = choices.get(1).map_or(0, |choice| choice.score);
    (first.explicit || (first.score >= 28 && first.score >= next + 8)).then_some(first.index)
}

pub fn listing(entries: &[Entry], choices: &[Choice]) -> String {
    if choices.is_empty() { return "No close skill match. Use skill with name search and query a few task words if needed.".into(); }
    choices.iter().map(|choice| {
        let entry = &entries[choice.index];
        format!("- {}: {}", key(entry), entry.1.summary.chars().take(200).collect::<String>())
    }).collect::<Vec<_>>().join("\n")
}

pub fn configuration_request(query: &str, choices: &[Choice], entries: &[Entry]) -> bool {
    let tokens = words(query);
    tokens.contains("config") || tokens.contains("edit") || choices.iter().any(|choice| entries[choice.index].1.name.starts_with("config-"))
}

pub fn relevance(query: &str, description: &str) -> usize {
    words(query).intersection(&words(description)).count()
}

pub fn command_hint(context: &str) -> &str {
    context.lines().find(|line| line.starts_with("The command:")).unwrap_or("")
}

/// Explicitly mark omitted data; never cut instructions or claim an omitted result was checked.
pub fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit { return text.to_owned(); }
    let mut start = limit.saturating_mul(2) / 3;
    while !text.is_char_boundary(start) { start -= 1; }
    let mut end = text.len().saturating_sub(limit / 3);
    while !text.is_char_boundary(end) { end += 1; }
    format!("{}\n[Data omitted to fit context. Missing text is not evidence of absence.]\n{}", &text[..start], &text[end..])
}

/// Shrink observations in place so journal/replay lesson indices and tool-call pairs stay valid.
/// Instructions, the current request and the latest check remain intact; recalled memory is
/// shortened only when nothing else is left to shrink.
pub fn shrink(messages: &mut [ChatMessage]) -> bool {
    if let Some(current) = messages.iter().position(|message| message.role == "user" && message.content.starts_with("Current terminal context")) {
        if let Some(message) = messages[1..current].iter_mut().find(|message| {
            message.role != "system" && !message.content.starts_with("Saved CortexTerm memory") && message.content.len() > 120
        }) {
            message.content = "[Earlier exchange omitted to fit this task. Current evidence follows.]".into();
            return true;
        }
    }
    let latest = messages.iter().rposition(|message| message.role == "tool");
    for (index, message) in messages.iter_mut().enumerate() {
        if message.role == "tool" && message.name.as_deref() != Some("skill") && Some(index) != latest && message.content.len() > 1100 {
            message.content = bounded(&message.content, 800);
            return true;
        }
    }
    // Last, the longest saved memory is shortened (a shortened item no longer counts as shown).
    if let Some(message) = messages.iter_mut().filter(|message| message.role == "user" && message.content.starts_with("Saved CortexTerm memory") && message.content.len() > 400).max_by_key(|message| message.content.len()) {
        message.content = bounded(&message.content, 300);
        return true;
    }
    false
}
