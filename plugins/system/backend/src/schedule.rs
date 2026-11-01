//! Scheduled jobs, run in-app while the plugin runs: a shell command or the security sweep, at
//! `daily HH:MM`, `hourly`, `every N min` or `weekly <day> HH:MM` (local time). They live in the
//! graph: `(:Schedule {key: id, name, kind, command, cwd, when, enabled, alert_on, next, owner_…,
//! sandboxed, writable, approved, last_…})-[:ON]->(:Machine)`, `-[:RUNS {at}]->` the
//! `(:CommandRun)` of each command it ran (the terminal's Run: a command runs through
//! `terminal.command`, with its risk engine and sandbox, traced); a sweep it ran is on stream
//! `security.sweeps`. A deleted schedule is retired. A run missed while the app was closed runs once a minute after start. The first start
//! seeds the daily security sweep.

use crate::graph::{self, Batch, Props, r};
use crate::util::{home, now_ms};
use cc_protocol::RpcError;
use cc_protocol::contracts::service::Caller;
use cc_protocol::contracts::system::{Schedule, ScheduleList, ScheduleRun};
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

pub const SWEEP_ID: &str = "security-sweep";
/// A command gets ten minutes.
pub const TIMEOUT: Duration = Duration::from_secs(600);
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

#[derive(Debug, Clone, Copy, PartialEq)]
enum When {
    Daily(i32, i32),
    Hourly,
    Every(u64),
    /// Day of the week (0 = Sunday), hour, minute.
    Weekly(i32, i32, i32),
}

impl std::fmt::Display for When {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            When::Daily(h, m) => write!(f, "daily {h:02}:{m:02}"),
            When::Hourly => write!(f, "hourly"),
            When::Every(n) => write!(f, "every {n} min"),
            When::Weekly(d, h, m) => write!(f, "weekly {} {h:02}:{m:02}", DAYS[*d as usize]),
        }
    }
}

fn parse_when(text: &str) -> Result<When, String> {
    let usage = "use `daily HH:MM`, `hourly`, `every N min` (N at least 5) or `weekly <mon..sun> HH:MM`";
    let clock = |hm: &str| -> Result<(i32, i32), String> {
        let (h, m) = hm.split_once(':').ok_or_else(|| format!("{hm:?} is not a time like 09:00"))?;
        match (h.parse::<i32>(), m.parse::<i32>()) {
            (Ok(h), Ok(m)) if (0..24).contains(&h) && (0..60).contains(&m) => Ok((h, m)),
            _ => Err(format!("{hm:?} is not a time like 09:00")),
        }
    };
    let lower = text.trim().to_lowercase();
    let words: Vec<&str> = lower.split_whitespace().collect();
    match words.as_slice() {
        ["hourly"] => Ok(When::Hourly),
        ["daily", hm] => clock(hm).map(|(h, m)| When::Daily(h, m)),
        ["every", n, "min" | "mins" | "minute" | "minutes"] => match n.parse::<u64>() {
            Ok(n) if (5..=10_080).contains(&n) => Ok(When::Every(n)),
            _ => Err(format!("`every {n} min` needs a whole number of minutes from 5 to 10080")),
        },
        ["weekly", day, hm] => {
            let index = DAYS.iter().position(|d| day.starts_with(d)).ok_or_else(|| format!("{day:?} is not a day; {usage}"))?;
            clock(hm).map(|(h, m)| When::Weekly(index as i32, h, m))
        }
        _ => Err(format!("{:?} is not a schedule; {usage}", text.trim())),
    }
}

fn local(secs: i64) -> libc::tm {
    let t = secs as libc::time_t;
    // SAFETY: a zeroed tm is a valid output buffer for localtime_r.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        tm
    }
}

/// Unix seconds of `days` days after `secs`'s local date at `h:m` (DST handled by mktime).
fn at_local(secs: i64, days: i32, h: i32, m: i32) -> i64 {
    let mut tm = local(secs);
    tm.tm_mday += days;
    tm.tm_hour = h;
    tm.tm_min = m;
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    // SAFETY: mktime normalises a filled-in tm.
    unsafe { libc::mktime(&mut tm) as i64 }
}

impl When {
    /// The first run strictly after `after` (Unix ms).
    fn next_after(self, after: u64) -> u64 {
        let secs = (after / 1000) as i64;
        let first_after = |candidates: &[i64]| candidates.iter().map(|s| (*s).max(0) as u64 * 1000).find(|ms| *ms > after);
        match self {
            When::Every(n) => after + n * 60_000,
            When::Hourly => {
                let tm = local(secs);
                at_local(secs, 0, tm.tm_hour + 1, 0).max(0) as u64 * 1000
            }
            When::Daily(h, m) => first_after(&[at_local(secs, 0, h, m), at_local(secs, 1, h, m)]).unwrap_or(after + 86_400_000),
            When::Weekly(day, h, m) => {
                let ahead = (day - local(secs).tm_wday).rem_euclid(7);
                first_after(&[at_local(secs, ahead, h, m), at_local(secs, ahead + 7, h, m)]).unwrap_or(after + 7 * 86_400_000)
            }
        }
    }
}

#[derive(Default)]
pub struct Store {
    list: ScheduleList,
    running: HashSet<String>,
    counter: u64,
}

impl Store {
    /// The schedules in the graph (the daily sweep seeded when there never was one), each one's
    /// next run set; one that was due while the app was closed runs a minute from now.
    pub async fn load() -> Result<Self, String> {
        let rows = graph::query_all(
            "MATCH (s:Schedule) RETURN s.key, s.name, s.kind, s.command, s.cwd, s.when, s.enabled, s.alert_on, s.next, \
             s.last_at, s.last_duration_ms, s.last_exit_code, s.last_tail, s.last_alerted, s.last_trace, s.state, \
             s.owner_app, s.owner_node, s.owner_name, s.owner_session, s.owner_by, s.sandboxed, s.writable, s.approved ORDER BY s.key",
            json!({}),
        )
        .await?;
        let fresh = rows.is_empty();
        let mut list = ScheduleList::default();
        for row in rows.iter().filter(|row| graph::text(&row[15]) != "gone") {
            let id = graph::text(&row[0]);
            let name = graph::text(&row[1]);
            let last_at = graph::number(&row[9]);
            list.schedules.push(Schedule {
                last: (last_at > 0).then(|| ScheduleRun {
                    id: id.clone(),
                    name: name.clone(),
                    at: last_at,
                    duration_ms: graph::number(&row[10]),
                    exit_code: row[11].as_i64().unwrap_or(0) as i32,
                    tail: graph::texts(&row[12]),
                    alerted: row[13].as_bool().unwrap_or(false),
                    trace: row[14].as_str().map(str::to_owned),
                }),
                id,
                name,
                kind: graph::text(&row[2]),
                command: graph::text(&row[3]),
                cwd: graph::text(&row[4]),
                when: graph::text(&row[5]),
                enabled: row[6].as_bool().unwrap_or(true),
                alert_on: graph::text(&row[7]),
                next: graph::number(&row[8]),
                owner: (!graph::text(&row[17]).is_empty()).then(|| Caller {
                    app: graph::text(&row[16]),
                    node: graph::text(&row[17]),
                    name: graph::text(&row[18]),
                    local: true,
                    session_id: graph::text(&row[19]),
                    by: graph::text(&row[20]),
                }),
                sandboxed: row[21].as_bool().unwrap_or(false),
                writable: graph::texts(&row[22]),
                // One made before schedules had owners was made by the person, here.
                approved: row[23].as_bool().unwrap_or(true),
            });
        }
        Ok(Self::start(list, fresh))
    }

    /// Seed and schedule a loaded list, and write it back.
    pub fn start(mut list: ScheduleList, fresh: bool) -> Self {
        if fresh {
            list.schedules.push(Schedule {
                id: SWEEP_ID.into(),
                name: "Security sweep".into(),
                kind: "sweep".into(),
                when: "daily 09:00".into(),
                enabled: true,
                ..Default::default()
            });
        }
        let now = now_ms();
        for schedule in &mut list.schedules {
            match parse_when(&schedule.when) {
                Ok(when) if schedule.next == 0 => schedule.next = when.next_after(now),
                Ok(_) if schedule.next <= now => schedule.next = now + 60_000,
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!("schedule {}: {error}; it stays off", schedule.id);
                    schedule.enabled = false;
                }
            }
        }
        let store = Store { list, running: HashSet::new(), counter: 0 };
        for schedule in &store.list.schedules {
            write(schedule, None);
        }
        store
    }

    pub fn list(&self) -> ScheduleList {
        self.list.clone()
    }

    /// Create (no `id`) or change a schedule; `next` is computed, `last` is kept.
    pub fn put(&mut self, mut input: Schedule) -> Result<Schedule, RpcError> {
        let invalid = |message: String| RpcError::invalid_params(message);
        input.name = input.name.trim().to_owned();
        if input.name.is_empty() {
            return Err(invalid("a schedule needs a name".into()));
        }
        input.kind = input.kind.trim().to_lowercase();
        match input.kind.as_str() {
            "command" => {
                input.command = input.command.trim().to_owned();
                if input.command.is_empty() {
                    return Err(invalid("a command schedule needs a command".into()));
                }
            }
            "sweep" => input.command.clear(),
            other => return Err(invalid(format!("unknown kind {other:?}; use command or sweep"))),
        }
        input.cwd = input.cwd.trim().to_owned();
        if !input.cwd.is_empty() && !expand(&input.cwd).is_dir() {
            return Err(invalid(format!("the folder {} does not exist", input.cwd)));
        }
        let when = parse_when(&input.when).map_err(invalid)?;
        input.when = when.to_string();
        input.alert_on = input.alert_on.trim().to_owned();
        input.next = when.next_after(now_ms());
        input.id = input.id.trim().to_owned();
        if input.id.is_empty() {
            self.counter += 1;
            input.id = format!("s{:x}{}", now_ms(), self.counter);
            input.last = None;
            self.list.schedules.push(input.clone());
        } else {
            let existing = self
                .list
                .schedules
                .iter_mut()
                .find(|s| s.id == input.id)
                .ok_or_else(|| RpcError::not_found(format!("no schedule {}; leave id empty to create one", input.id)))?;
            input.last = existing.last.take();
            // Who owns it never changes.
            input.owner = existing.owner.clone();
            *existing = input.clone();
        }
        write(&input, None);
        Ok(input)
    }

    pub fn delete(&mut self, id: &str) -> Result<(), RpcError> {
        let before = self.list.schedules.len();
        self.list.schedules.retain(|s| s.id != id);
        if self.list.schedules.len() == before {
            return Err(RpcError::not_found(format!("no schedule {id}")));
        }
        graph::retire(vec![r("Schedule", id)], "deleted");
        Ok(())
    }

    /// The enabled schedules due now that are not running.
    pub fn due(&self, now: u64) -> Vec<String> {
        self.list
            .schedules
            .iter()
            .filter(|s| s.enabled && s.next != 0 && s.next <= now && !self.running.contains(&s.id))
            .map(|s| s.id.clone())
            .collect()
    }

    /// Mark a schedule running and hand out a copy of it.
    pub fn begin(&mut self, id: &str) -> Result<Schedule, RpcError> {
        let schedule = self.list.schedules.iter().find(|s| s.id == id).cloned().ok_or_else(|| RpcError::not_found(format!("no schedule {id}")))?;
        if !self.running.insert(id.to_owned()) {
            return Err(RpcError::new("busy", format!("{} is already running", schedule.name)));
        }
        Ok(schedule)
    }

    /// Record a finished run and set the next one: the sweep it ran, or the command's Run.
    pub fn finish(&mut self, run: ScheduleRun, ran: Ran) {
        self.running.remove(&run.id);
        let now = now_ms();
        if let Some(schedule) = self.list.schedules.iter_mut().find(|s| s.id == run.id) {
            if let Ok(when) = parse_when(&schedule.when) {
                schedule.next = when.next_after(now);
            }
            schedule.last = Some(run);
            write(schedule, Some(ran));
        }
    }
}

/// What a run left in the graph.
pub enum Ran {
    /// The terminal's Run of the command.
    Command(String),
    /// Nothing to link: a sweep (on its stream), or a command that did not start.
    Nothing,
}

/// The trace ids of a schedule's command runs (every schedule's when `id` is empty).
pub async fn run_traces(id: &str) -> Vec<String> {
    let rows = graph::query_all(
        "MATCH (s:Schedule)-[:RUNS]->(c:CommandRun) WHERE $id = '' OR s.key = $id RETURN c.trace",
        json!({"id": id}),
    )
    .await
    .unwrap_or_default();
    rows.iter().map(|row| graph::text(&row[0])).filter_map(|t| t.strip_prefix("trace://").map(str::to_owned)).collect()
}

/// A schedule's node as it is now; with `ran`, also the run it just finished.
fn write(schedule: &Schedule, ran: Option<Ran>) {
    let Some(machine) = graph::machine() else { return };
    let mut batch = Batch::new();
    let unit = batch.unit();
    let me = r("Schedule", schedule.id.clone());
    let node = unit.node("Schedule", schedule.id.clone());
    node.p("name", schedule.name.clone())
        .p("kind", schedule.kind.clone())
        .p("command", schedule.command.clone())
        .p("cwd", schedule.cwd.clone())
        .p("when", schedule.when.clone())
        .p("enabled", schedule.enabled)
        .p("alert_on", schedule.alert_on.clone())
        .p("next", schedule.next)
        .p("sandboxed", schedule.sandboxed)
        .pl("writable", schedule.writable.clone())
        .p("approved", schedule.approved);
    if let Some(owner) = &schedule.owner {
        node.p("owner_app", owner.app.clone())
            .p("owner_node", owner.node.clone())
            .p("owner_name", owner.name.clone())
            .p("owner_session", owner.session_id.clone())
            .p("owner_by", owner.by.clone());
    }
    if let Some(last) = &schedule.last {
        node.p("last_at", last.at)
            .p("last_duration_ms", last.duration_ms)
            .p("last_exit_code", last.exit_code)
            .pl("last_tail", last.tail.clone())
            .p("last_alerted", last.alerted)
            .p("last_trace", last.trace.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
    }
    unit.edge(me.clone(), "ON", machine);
    match (ran, &schedule.last) {
        (Some(Ran::Command(run_id)), Some(last)) => {
            unit.edge(me, "RUNS", r("CommandRun", run_id)).p("at", last.at);
        }
        _ => {}
    }
    graph::put(batch);
}

fn expand(path: &str) -> PathBuf {
    match path {
        "~" => home(),
        _ => path.strip_prefix("~/").map(|rest| home().join(rest)).unwrap_or_else(|| PathBuf::from(path)),
    }
}
