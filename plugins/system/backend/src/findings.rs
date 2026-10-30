//! The sweep's record in the graph:
//!
//! - `(:Sweep {key: at, at, duration_ms, checked, skipped})-[:ON]->(:Machine)`, one per sweep;
//! - `(:SweepFinding {key: kind:hash, kind, severity, text, fix, source, state*})-[:FOUND_BY {at}]->(:Sweep)`
//!   and `-[:ABOUT]->` the node it is about (an app, a package, a setting, a start item …);
//! - `state` is temporal: `open` while sweeps find it, `gone` once one does not, `ignored` when the
//!   person said not to worry about it (kept, so it stays ignored when it comes back).
//!
//! The last sweep and every finding's state are loaded once at start and kept in RAM.

use crate::graph::{self, Batch, Props, r};
use crate::sweep;
use cc_protocol::contracts::system::{Finding, SweepReport};
use serde_json::{Value, json};
use std::collections::HashMap;

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
}

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
                findings: Vec::new(),
            };
            let rows = graph::query_all(
                "MATCH (f:SweepFinding)-[:FOUND_BY]->(:Sweep {key: $k}) RETURN f.severity, f.kind, f.text, f.fix, f.source, f.key ORDER BY f.key",
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
                        ignored: false,
                        about: None,
                    }
                })
                .collect();
            store.last.findings.sort_by_key(|f| sweep::rank(&f.severity));
        }
        let rows = graph::query_all("MATCH (f:SweepFinding) RETURN f.key, f.state, f.kind, f.text ORDER BY f.key", json!({})).await?;
        for row in rows {
            let wire = format!("{}:{}", graph::text(&row[2]), graph::text(&row[3]));
            store.states.insert(graph::text(&row[0]), (graph::text(&row[1]), wire));
        }
        Ok(store)
    }

    /// The report keys of the findings the person ignored.
    pub fn ignored(&self) -> Vec<String> {
        self.states.values().filter(|(state, _)| state == "ignored").map(|(_, wire)| wire.clone()).collect()
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
            for finding in &report.findings {
                let key = node_key(&finding.kind, &finding.text);
                if !seen_now.insert(key.clone()) {
                    continue;
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
        }
        self.last = report.clone();
    }

    /// The person ignores a finding (or takes that back), by its report key `kind:text`.
    pub fn ignore(&mut self, wire: &str, ignore: bool) -> Result<(), String> {
        let (kind, text) = wire.split_once(':').ok_or_else(|| format!("`{wire}` is not a finding's key (kind:text)"))?;
        let machine = graph::machine().ok_or("memory is not reachable yet; try again in a moment")?;
        let key = node_key(kind, text);
        let in_last = self.last.findings.iter().any(|f| f.key == wire);
        let state = if ignore {
            "ignored"
        } else if in_last {
            "open"
        } else {
            "gone"
        };
        let mut batch = Batch::new();
        let unit = batch.unit();
        let node = unit.node("SweepFinding", key.clone());
        node.t("state", state);
        if !self.states.contains_key(&key) {
            // Found by a check, not a stored sweep: it is written now, with what it says.
            let finding = self.last.findings.iter().find(|f| f.key == wire);
            node.p("kind", kind).p("text", text);
            if let Some(f) = finding {
                node.p("severity", f.severity.clone()).p("source", f.source.clone());
            }
            if self.last.at != 0 {
                unit.edge(r("SweepFinding", key.clone()), "FOUND_BY", r("Sweep", self.last.at.to_string())).p("at", self.last.at);
            } else {
                unit.edge(r("SweepFinding", key.clone()), "ON", machine);
            }
        }
        graph::put(batch);
        self.states.insert(key, (state.to_owned(), wire.to_owned()));
        Ok(())
    }
}
