//! The sweep's record in the graph:
//!
//! - `(:Sweep {key: at, at, duration_ms, checked, skipped})-[:ON]->(:Machine)`, one per sweep;
//! - `(:SweepFinding {key: kind:hash, kind, severity, text, fix, source, group, tried, state*})-[:FOUND_BY {at}]->(:Sweep)`
//!   and `-[:ABOUT]->` the node it is about (an app, a package, a setting, a start item …);
//! - `state` is temporal: `open` while sweeps find it, `gone` once one (or a check after a fix) does
//!   not; `ignored` is an earlier version's "don't worry", still honoured as `expected`;
//! - `(:SweepDecision {key: decision:hash of group, verdict, group, keys, severity, at, until})-[:ON]->(:Machine)`,
//!   the person's decision about a group of findings;
//! - stream `security.findings`: `{severity, group}` for each finding the first time it is found
//!   (30 days), what the chart counts;
//! - stream `security.fixes`: `{group, text, command, gone}` for each finding checked again after a
//!   fix (30 days), what the pane shows as the fix's result.
//!
//! The last sweep, every finding's state and the decisions are loaded once at start and kept in RAM.

use crate::graph::{self, Batch, Props, r};
use crate::sweep;
use crate::util::now_ms;
use cc_protocol::contracts::system::{Decision, Finding, FixCheck, SweepReport};
use serde_json::{Value, json};
use std::collections::HashMap;

/// The verdicts a decision can carry.
pub const VERDICTS: [&str; 4] = ["expected", "false_alarm", "accepted", "vendor"];
const DAY_MS: u64 = 86_400_000;

/// A finding's node key: its kind and a hash of its words (the report's key is `kind:text`).
pub fn node_key(kind: &str, text: &str) -> String {
    graph::hashed(kind, text)
}

#[derive(Default)]
pub struct Store {
    /// The last full sweep (at 0: none yet).
    pub last: SweepReport,
    /// Node key -> (state, report key).
    states: HashMap<String, (String, String)>,
    /// Report key -> the fix command that ran and did not clear it.
    tried: HashMap<String, String>,
    decisions: Vec<Decision>,
    /// The latest checks after a fix, newest first (at most [`FIXES`]).
    fixes: Vec<FixCheck>,
}

const FIXES: usize = 20;
const FIX_STREAM: &str = "security.fixes";

impl Store {
    /// The last sweep and every finding's state, from the graph.
    pub async fn load() -> Result<Store, String> {
        let mut store = Store::default();
        let rows = graph::query("MATCH (s:Sweep) RETURN s.key, s.at, s.duration_ms, s.checked, s.skipped ORDER BY s.at DESC LIMIT 1", json!({})).await?;
        if let Some(row) = rows.first() {
            let key = graph::text(&row[0]);
            store.last = SweepReport {
                at: graph::number(&row[1]),
                duration_ms: graph::number(&row[2]),
                checked: graph::texts(&row[3]),
                skipped: graph::texts(&row[4]),
                ..Default::default()
            };
            let rows = graph::query_all(
                "MATCH (f:SweepFinding)-[:FOUND_BY]->(:Sweep {key: $k}) RETURN f.severity, f.kind, f.text, f.fix, f.source, f.key, f.group ORDER BY f.key",
                json!({"k": key}),
            )
            .await?;
            store.last.findings = rows
                .iter()
                .map(|row| {
                    let (kind, text) = (graph::text(&row[1]), graph::text(&row[2]));
                    Finding {
                        severity: graph::text(&row[0]),
                        key: format!("{kind}:{text}"),
                        kind,
                        text,
                        fix: row[3].as_str().map(str::to_owned),
                        source: graph::text(&row[4]),
                        group: graph::text(&row[6]),
                        ..Default::default()
                    }
                })
                .map(|mut finding| {
                    // Kept by an earlier version without a group: grouped by its check, as `mark` shows it.
                    if finding.group.is_empty() {
                        finding.group = sweep::group_of(&finding);
                    }
                    finding
                })
                .collect();
            store.last.findings.sort_by_key(|f| sweep::rank(&f.severity));
        }
        let rows = graph::query_all("MATCH (f:SweepFinding) RETURN f.key, f.state, f.kind, f.text, f.tried ORDER BY f.key", json!({})).await?;
        for row in rows {
            let wire = format!("{}:{}", graph::text(&row[2]), graph::text(&row[3]));
            if let Some(tried) = row[4].as_str().filter(|t| !t.is_empty()) {
                store.tried.insert(wire.clone(), tried.to_owned());
            }
            store.states.insert(graph::text(&row[0]), (graph::text(&row[1]), wire));
        }
        let rows = graph::query_all("MATCH (d:SweepDecision) RETURN d.key, d.verdict, d.group, d.keys, d.severity, d.at, d.until", json!({})).await?;
        let now = now_ms();
        let mut ended = Vec::new();
        for row in rows {
            let decision = Decision {
                verdict: graph::text(&row[1]),
                group: graph::text(&row[2]),
                keys: graph::texts(&row[3]),
                severity: graph::text(&row[4]),
                at: graph::number(&row[5]),
                until: graph::number(&row[6]),
            };
            if decision.until != 0 && decision.until <= now {
                ended.push(r("SweepDecision", graph::text(&row[0])));
            } else {
                store.decisions.push(decision);
            }
        }
        if !ended.is_empty() {
            graph::retire(ended, "ended");
        }
        let since = now.saturating_sub(30 * DAY_MS);
        for entry in graph::stream_read(FIX_STREAM, since).await?.into_iter().rev().take(FIXES) {
            store.fixes.push(FixCheck {
                at: entry.at_ms,
                group: graph::text(&entry.value["group"]),
                text: graph::text(&entry.value["text"]),
                command: graph::text(&entry.value["command"]),
                gone: entry.value["gone"].as_bool().unwrap_or(false),
            });
        }
        Ok(store)
    }

    /// The report with each finding's key, decision and tried fix filled in, and the decisions.
    pub fn mark(&self, mut report: SweepReport) -> SweepReport {
        let now = now_ms();
        let decisions: Vec<&Decision> = self.decisions.iter().filter(|d| d.until == 0 || d.until > now).collect();
        for finding in &mut report.findings {
            if finding.key.is_empty() {
                finding.key = format!("{}:{}", finding.kind, finding.text);
            }
            if finding.group.is_empty() {
                finding.group = sweep::group_of(finding);
            }
            let legacy = self.states.get(&node_key(&finding.kind, &finding.text)).is_some_and(|(state, _)| state == "ignored");
            finding.decision = match decisions.iter().find(|d| covers(d, finding)) {
                Some(d) => d.verdict.clone(),
                None if legacy => "expected".into(),
                None => String::new(),
            };
            finding.ignored = !finding.decision.is_empty();
            finding.tried = self.tried.get(&finding.key).cloned();
        }
        report.decisions = decisions.into_iter().cloned().collect();
        report.fixes = self.fixes.clone();
        report
    }

    /// Decide about a group (or take the decision back with an empty verdict). The decision
    /// covers the group's findings up to the worst one it has now, or only `keys`.
    pub fn decide(&mut self, group: &str, verdict: &str, keys: Vec<String>, days: u32) -> Result<(), String> {
        let machine = graph::machine().ok_or("memory is not reachable yet; try again in a moment")?;
        let node = graph::hashed("decision", group);
        self.decisions.retain(|d| d.group != group);
        if verdict.is_empty() {
            graph::retire(vec![r("SweepDecision", node)], "taken back");
            let mut batch = Batch::new();
            for finding in self.last.findings.iter().filter(|f| f.group == group) {
                let key = node_key(&finding.kind, &finding.text);
                if let Some(state) = self.states.get_mut(&key).filter(|(state, _)| state == "ignored") {
                    state.0 = "open".into();
                    batch.unit().node("SweepFinding", key).t("state", "open");
                }
            }
            graph::put(batch);
            return Ok(());
        }
        if !VERDICTS.contains(&verdict) {
            return Err(format!("`{verdict}` is not a verdict ({})", VERDICTS.join(", ")));
        }
        let covered: Vec<&Finding> = self.last.findings.iter().filter(|f| f.group == group && (keys.is_empty() || keys.contains(&f.key))).collect();
        let severity = covered.iter().map(|f| f.severity.as_str()).min_by_key(|s| sweep::rank(s)).unwrap_or("info").to_owned();
        let now = now_ms();
        let decision = Decision {
            verdict: verdict.into(),
            group: group.into(),
            keys,
            severity,
            at: now,
            until: if days == 0 { 0 } else { now + u64::from(days) * DAY_MS },
        };
        let mut batch = Batch::new();
        let unit = batch.unit();
        unit.node("SweepDecision", node.clone())
            .p("verdict", decision.verdict.clone())
            .p("group", decision.group.clone())
            .pl("keys", decision.keys.clone())
            .p("severity", decision.severity.clone())
            .p("at", decision.at)
            .p("until", decision.until);
        unit.edge(r("SweepDecision", node), "ON", machine);
        graph::put(batch);
        self.decisions.push(decision);
        Ok(())
    }

    /// An earlier version's "don't worry" about one finding (moved in from its files): kept as the
    /// finding's `ignored` state, which counts as `expected`.
    pub fn ignore(&mut self, wire: &str) -> Result<(), String> {
        let (kind, text) = wire.split_once(':').ok_or_else(|| format!("`{wire}` is not a finding's key (kind:text)"))?;
        let machine = graph::machine().ok_or("memory is not reachable yet; try again in a moment")?;
        let key = node_key(kind, text);
        let mut batch = Batch::new();
        let unit = batch.unit();
        let node = unit.node("SweepFinding", key.clone());
        node.t("state", "ignored");
        if !self.states.contains_key(&key) {
            node.p("kind", kind).p("text", text);
            if self.last.at != 0 {
                unit.edge(r("SweepFinding", key.clone()), "FOUND_BY", r("Sweep", self.last.at.to_string())).p("at", self.last.at);
            } else {
                unit.edge(r("SweepFinding", key.clone()), "ON", machine);
            }
        }
        graph::put(batch);
        self.states.insert(key, ("ignored".into(), wire.to_owned()));
        Ok(())
    }

    /// A fix ran: the findings a fresh check no longer finds are gone; the rest keep the command
    /// as tried. True when every one of `keys` is gone.
    pub fn verified(&mut self, keys: &[String], fresh: &SweepReport, command: &str) -> bool {
        let mut batch = Batch::new();
        let mut all_gone = true;
        // One result per group: its first finding's words, how many were checked, whether all are gone.
        let mut checks: Vec<(FixCheck, usize)> = Vec::new();
        for wire in keys {
            let Some((kind, text)) = wire.split_once(':') else { continue };
            let key = node_key(kind, text);
            let stored = self.states.contains_key(&key);
            let still = fresh.findings.iter().any(|f| &f.key == wire);
            let group = self.last.findings.iter().find(|f| &f.key == wire).map(|f| f.group.clone()).unwrap_or_default();
            match checks.iter_mut().find(|(c, _)| c.group == group) {
                Some((check, n)) => { check.gone &= !still; *n += 1; }
                None => checks.push((FixCheck { at: now_ms(), group, text: text.to_owned(), command: command.to_owned(), gone: !still }, 1)),
            }
            if still {
                all_gone = false;
                if !command.is_empty() && stored {
                    batch.unit().node("SweepFinding", key).p("tried", command.to_owned());
                    self.tried.insert(wire.clone(), command.to_owned());
                }
            } else {
                if stored {
                    batch.unit().node("SweepFinding", key.clone()).t("state", "gone");
                    self.states.insert(key, ("gone".into(), wire.clone()));
                }
                self.last.findings.retain(|f| &f.key != wire);
            }
        }
        graph::put(batch);
        let mut records = Vec::new();
        for (mut check, n) in checks {
            if n > 1 {
                check.text = format!("{} (and {} more)", check.text, n - 1);
            }
            records.push(json!({"group": check.group, "text": check.text, "command": check.command, "gone": check.gone}));
            self.fixes.insert(0, check);
        }
        self.fixes.truncate(FIXES);
        if !records.is_empty() {
            graph::append(FIX_STREAM, records, 30);
        }
        all_gone
    }

    /// Keep a full sweep: what it saw of this Mac first, then the sweep, its findings (each linked
    /// to what it is about) and the findings it no longer found.
    pub fn record(&mut self, report: &SweepReport, seen: Batch) {
        let mut batch = seen;
        let present = batch.refs();
        if let Some(machine) = graph::machine() {
            let sweep_key = report.at.to_string();
            let unit = batch.unit();
            unit.node("Sweep", sweep_key.clone()).p("at", report.at).p("duration_ms", report.duration_ms).pl("checked", report.checked.clone()).pl("skipped", report.skipped.clone());
            unit.edge(r("Sweep", sweep_key.clone()), "ON", machine);
            let mut seen_now = std::collections::HashSet::new();
            let mut first: Vec<Value> = Vec::new();
            for finding in &report.findings {
                let key = node_key(&finding.kind, &finding.text);
                if !seen_now.insert(key.clone()) {
                    continue;
                }
                if !self.states.contains_key(&key) {
                    first.push(json!({"severity": finding.severity, "group": finding.group}));
                }
                let ignored = finding.ignored || self.states.get(&key).is_some_and(|(state, _)| state == "ignored");
                let state = if ignored { "ignored" } else { "open" };
                let unit = batch.unit();
                unit.node("SweepFinding", key.clone())
                    .p("kind", finding.kind.clone())
                    .p("severity", finding.severity.clone())
                    .p("text", finding.text.clone())
                    .p("source", finding.source.clone())
                    .p("fix", finding.fix.clone().map(Value::String).unwrap_or(Value::Null))
                    .p("group", finding.group.clone())
                    .t("state", state);
                unit.edge(r("SweepFinding", key.clone()), "FOUND_BY", r("Sweep", sweep_key.clone())).p("at", report.at);
                if let Some((label, about)) = &finding.about {
                    let target = r(label, about.clone());
                    if present.contains(&target) {
                        unit.edge(r("SweepFinding", key.clone()), "ABOUT", target);
                    }
                }
                self.states.insert(key, (state.to_owned(), format!("{}:{}", finding.kind, finding.text)));
            }
            for (key, (state, _)) in self.states.iter_mut() {
                if state == "open" && !seen_now.contains(key) {
                    batch.unit().node("SweepFinding", key.clone()).t("state", "gone");
                    *state = "gone".into();
                }
            }
            graph::put(batch);
            if !first.is_empty() {
                graph::append(STREAM, first, 30);
            }
        }
        self.last = report.clone();
    }
}

/// Where first-found findings are counted.
pub const STREAM: &str = "security.findings";

fn covers(decision: &Decision, finding: &Finding) -> bool {
    decision.group == finding.group
        && if decision.keys.is_empty() { sweep::rank(&finding.severity) >= sweep::rank(&decision.severity) } else { decision.keys.contains(&finding.key) }
}
