//! The CVE watch: every three hours, without waiting for the daily sweep, the advisories that
//! matter most are checked against this Mac with the CVE cross-checker:
//!
//! - what CISA lists as exploited in the last 30 days, when its product is something installed
//!   here (Apple's always: macOS and Safari);
//! - the fixes Apple marks as actively exploited in releases newer than this Mac's;
//! - malicious-package records (OSV `MAL-`) for the project and global packages installed;
//! - every advisory the graph already says affects this Mac, to see whether it still does.
//!
//! What affects this Mac is kept in the graph as `(:Advisory)-[:AFFECTS {verdict*}]->` the app,
//! formula, package or macOS it affects (`cve::record`); only an advisory that affected nothing
//! here before raises an alert. The facts earlier versions wrote (`<id> affects this Mac`,
//! global knowledge) are looked at once more and withdrawn: the AFFECTS edges replace them.
//! Nothing is kept outside the graph.

use crate::alerts::Candidate;
use crate::cve::Batch;
use crate::inventory::{self, KEV, KEV_FILE};
use crate::util::now_ms;
use cc_protocol::Ctx;
use cc_protocol::contracts::memory::{self as memory_contract, KnowledgeItem, KnowledgeListResult};
use cc_protocol::contracts::system::{Alert, CveReport};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

const EVERY: Duration = Duration::from_secs(3 * 3600);
/// The first look, once the plugin has settled.
const FIRST: Duration = Duration::from_secs(120);
/// CISA rows this recent are checked.
const RECENT_DAYS: i64 = 30;
/// Advisories looked up in one round, a few seconds apart (NVD allows 5 in 30 s without a key).
const MOST: usize = 30;
const APART: Duration = Duration::from_secs(7);
/// Who writes the facts.
const BY: &str = "cve-watch";
const SUFFIX: &str = " affects this Mac";

/// Run the watch for as long as the plugin runs. `ctx` reaches the graph; `fire` raises an alert;
/// `resolve` closes the alerts of an advisory that no longer affects this Mac.
pub async fn run(ctx: impl Fn() -> Option<Ctx>, fire: impl Fn(Candidate), resolve: impl Fn(&str)) {
    tokio::time::sleep(FIRST).await;
    while !crate::graph::wait_ready(Duration::from_secs(3600)).await {}
    loop {
        if let Some(ctx) = ctx() {
            match round(&ctx).await {
                Ok((found, gone)) => {
                    for candidate in found {
                        fire(candidate);
                    }
                    for id in gone {
                        resolve(&format!("cve:{id}"));
                    }
                }
                Err(error) => tracing::info!("cve watch: {error}"),
            }
        }
        tokio::time::sleep(EVERY).await;
    }
}

/// One round: what to look at, each looked at, the graph brought up to date. The new alerts, and
/// the advisories that no longer affect this Mac.
async fn round(ctx: &Ctx) -> Result<(Vec<Candidate>, Vec<String>), String> {
    let known = known(ctx).await?;
    let before: BTreeSet<String> = crate::graph::query("MATCH (a:Advisory)-[e:AFFECTS]->() WHERE e.verdict = 'affected' RETURN DISTINCT a.key", json!({}))
        .await?
        .iter()
        .map(|row| crate::graph::text(&row[0]))
        .collect();
    // The CISA list is refreshed every round, not once a day as the sweep does.
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build().map_err(|e| e.to_string())?;
    let _ = inventory::feed_within(&client, KEV_FILE, KEV, inventory::keep_kev, EVERY).await;
    let batch = Batch::new().await?;

    let mut ids: Vec<String> = before.iter().cloned().chain(known.iter().map(|(id, _)| id.clone())).collect::<BTreeSet<_>>().into_iter().collect();
    let add = |id: String, ids: &mut Vec<String>| {
        if !ids.contains(&id) {
            ids.push(id);
        }
    };
    for id in batch.apple_exploited() {
        add(id, &mut ids);
    }
    let names = batch.names();
    let cutoff = today_minus(RECENT_DAYS);
    for row in batch.kev() {
        if row.added.as_str() >= cutoff.as_str() && installed_here(&row.vendor, &row.product, &names) {
            add(row.id.clone(), &mut ids);
        }
    }
    for id in malicious(batch.client(), &batch.packages()).await {
        add(id, &mut ids);
    }

    let mut found = Vec::new();
    let mut gone = Vec::new();
    let mut affected = BTreeSet::new();
    for (looked, id) in ids.iter().take(MOST).enumerate() {
        if looked > 0 {
            tokio::time::sleep(APART).await;
        }
        let Ok(report) = batch.report(id).await else { continue };
        // Unknown is not a change of mind: the edges keep their verdict until a look says otherwise.
        if report.verdict != "unknown" {
            batch.record(&report);
        }
        let fact = known.iter().find(|(known_id, _)| known_id == id).map(|(_, item)| item);
        if matches!(report.verdict.as_str(), "fixed" | "not-affected") {
            gone.push(id.clone());
        }
        if report.verdict == "affected" {
            affected.insert(id.clone());
            if !before.contains(id) && fact.is_none() {
                found.push(alert(&report));
            }
        }
        // A fact an earlier version wrote: the edges hold it now.
        if let Some(item) = fact
            && report.verdict != "unknown"
        {
            let reason = if report.verdict == "affected" {
                format!("{id}: kept as (:Advisory)-[:AFFECTS]-> edges in the graph")
            } else if report.verdict_text.is_empty() {
                format!("{id}: {}", report.verdict)
            } else {
                report.verdict_text.clone()
            };
            let params = json!({"id": item.id, "reason": reason, "by": BY});
            let _ = call(ctx, memory_contract::methods::KNOWLEDGE_WITHDRAW, params).await;
        }
    }
    tracing::info!("cve watch: {} advisories looked at, {} affect this Mac, {} new", ids.len().min(MOST), affected.len(), found.len());
    Ok((found, gone))
}

/// The facts earlier versions of the watch wrote that are still live: (advisory id, item).
async fn known(ctx: &Ctx) -> Result<Vec<(String, KnowledgeItem)>, String> {
    let list = call(ctx, memory_contract::methods::KNOWLEDGE_LIST, json!({"kind": memory_contract::knowledge::FACT})).await?;
    let list: KnowledgeListResult = serde_json::from_value(list).map_err(|e| e.to_string())?;
    Ok(list
        .items
        .into_iter()
        .filter(|item| item.by == BY && item.state == "asserted")
        .filter_map(|item| item.name.strip_suffix(SUFFIX).map(|id| (id.to_owned(), item.clone())))
        .collect())
}

fn alert(report: &CveReport) -> Candidate {
    let severity = if report.kev.is_some() || report.id.starts_with("MAL-") || report.cvss.as_ref().is_some_and(|c| c.score >= 9.0) { "high" } else { "warn" };
    Candidate {
        key: format!("cve:{}", report.id),
        alert: Alert { kind: "cve".into(), severity: severity.into(), text: report.verdict_text.clone(), actions: vec!["show".into()], ..Default::default() },
    }
}

/// Whether a CISA row's vendor and product name something installed here: Apple's always (macOS
/// and Safari are always here), Chromium's when Chrome or an Electron app may carry it, otherwise
/// a word of the product that is the name of an app, formula, tool or package.
fn installed_here(vendor: &str, product: &str, names: &BTreeSet<String>) -> bool {
    let vendor = vendor.to_lowercase();
    let product = product.to_lowercase();
    if vendor == "apple" || product.contains("chromium") || product.contains("chrome") {
        return true;
    }
    const VAGUE: &[&str] = &["multiple", "products", "product", "server", "client", "the", "and", "for", "web", "app", "management"];
    let words: Vec<&str> = product.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| w.len() >= 3 && !VAGUE.contains(w)).collect();
    names.iter().any(|name| {
        let first = name.split(|c: char| !c.is_ascii_alphanumeric()).next().unwrap_or(name);
        words.iter().any(|w| *w == name.as_str() || (first.len() >= 4 && *w == first))
    })
}

/// The `MAL-` records OSV has for the packages installed (one batch query per 1000).
async fn malicious(client: &reqwest::Client, packages: &[(String, String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in packages.chunks(1000) {
        let queries: Vec<Value> = chunk.iter().map(|(eco, name, version)| json!({"package": {"ecosystem": eco, "name": name}, "version": version})).collect();
        let body = serde_json::to_vec(&json!({"queries": queries})).unwrap_or_default();
        let request = client.post("https://api.osv.dev/v1/querybatch").header("content-type", "application/json").body(body);
        let Ok(response) = request.send().await else { continue };
        let Ok(bytes) = response.bytes().await else { continue };
        let Ok(answer) = serde_json::from_slice::<Value>(&bytes) else { continue };
        for result in answer["results"].as_array().into_iter().flatten() {
            for vuln in result["vulns"].as_array().into_iter().flatten() {
                if let Some(id) = vuln["id"].as_str().filter(|id: &&str| id.starts_with("MAL-"))
                    && !out.iter().any(|o: &String| o == id)
                {
                    out.push(id.to_owned());
                }
            }
        }
    }
    out
}

async fn call(ctx: &Ctx, method: &str, params: Value) -> Result<Value, String> {
    match tokio::time::timeout(Duration::from_secs(20), ctx.call(method, params)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{method}: {}", error.message)),
        Err(_) => Err(format!("{method}: no answer within 20 s")),
    }
}

/// `YYYY-MM-DD`, `days` before today (UTC).
fn today_minus(days: i64) -> String {
    let day = (now_ms() / 86_400_000) as i64 - days;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}
