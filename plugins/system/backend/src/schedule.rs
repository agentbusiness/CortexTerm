//! Scheduled jobs, run in-app while the plugin runs: a shell command or the security sweep, at
//! `daily HH:MM`, `hourly`, `every N min` or `weekly <day> HH:MM` (local time). They live in the
//! graph: `(:Schedule {key: id, name, kind, command, cwd, when, enabled, alert_on, next, last_…})
//! -[:ON]->(:Machine)`, `-[:RUNS {at}]->` each `(:Sweep)` it ran, or the `(:CommandRun)` of each
//! command it ran (`key: schedule:<id>:<at>`, `-[:IN]->` its folder). A deleted schedule is retired.
//! A run missed while the app was closed runs once a minute after start. The first start seeds
//! the daily security sweep.

use crate::graph::{self, Batch, Props, r};
use crate::util::{home, now_ms, shorten};
use cc_protocol::RpcError;
use cc_protocol::contracts::system::{Schedule, ScheduleList, ScheduleRun};
use serde_json::json;
use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

pub const SWEEP_ID: &str = "security-sweep";
/// A command gets ten minutes.
pub const TIMEOUT: Duration = Duration::from_secs(600);
const TAIL: usize = 40;
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
             s.last_at, s.last_duration_ms, s.last_exit_code, s.last_tail, s.last_alerted, s.last_trace, s.state ORDER BY s.key",
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

    /// Record a finished run and set the next one. `sweep_at`: the sweep it ran (a sweep job).
    pub fn finish(&mut self, run: ScheduleRun, sweep_at: Option<u64>) {
        self.running.remove(&run.id);
        let now = now_ms();
        if let Some(schedule) = self.list.schedules.iter_mut().find(|s| s.id == run.id) {
            if let Ok(when) = parse_when(&schedule.when) {
                schedule.next = when.next_after(now);
            }
            schedule.last = Some(run);
            write(schedule, Some(sweep_at));
        }
    }
}

/// A schedule's node as it is now; with `ran`, also the run it just finished: `Some(Some(at))`
/// for the sweep stored at `at`, `Some(None)` for a command.
fn write(schedule: &Schedule, ran: Option<Option<u64>>) {
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
        .p("next", schedule.next);
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
        (Some(Some(sweep_at)), Some(last)) => {
            unit.edge(me, "RUNS", r("Sweep", sweep_at.to_string())).p("at", last.at);
        }
        (Some(None), Some(last)) => {
            let key = format!("schedule:{}:{}", schedule.id, last.at);
            let cwd = if schedule.cwd.is_empty() { home() } else { expand(&schedule.cwd) };
            let folder = graph::folder(unit, &cwd);
            unit.node("CommandRun", key.clone())
                .p("command", schedule.command.clone())
                .p("started_ms", last.at)
                .p("finished_ms", last.at + last.duration_ms)
                .p("exit_code", last.exit_code)
                .p("duration_ms", last.duration_ms)
                .p("author", "schedule")
                .p("trace", last.trace.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
            unit.edge(r("CommandRun", key.clone()), "IN", folder);
            unit.edge(me, "RUNS", r("CommandRun", key)).p("at", last.at);
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

/// What a command run left behind.
pub struct Outcome {
    pub exit_code: i32,
    pub tail: Vec<String>,
    /// The output contained `alert_on`.
    pub matched: bool,
    pub timed_out: bool,
    /// Every output line with the time it came (the first [`LINES`]), for the run's trace.
    pub lines: Vec<(u64, String)>,
}

/// What a run printed so far: the last lines, whether `alert_on` showed, every line with its time.
#[derive(Default)]
struct Seen {
    tail: VecDeque<String>,
    matched: bool,
    lines: Vec<(u64, String)>,
}

/// Output lines kept for a run's trace.
const LINES: usize = 20_000;

/// Run a command schedule: the user's shell as a login shell (`-lc`), no terminal, in its
/// folder (home by default), stdout and stderr together, at most ten minutes (blocking).
pub fn run_command(schedule: &Schedule, started: impl FnOnce(u32)) -> Outcome {
    let failed = |line: String| Outcome { exit_code: -1, tail: vec![line], matched: false, timed_out: false, lines: Vec::new() };
    let shell = std::env::var("SHELL").ok().filter(|s| s.starts_with('/') && std::path::Path::new(s).is_file());
    let shell = shell.unwrap_or_else(|| "/bin/zsh".into());
    let cwd = if schedule.cwd.is_empty() { home() } else { expand(&schedule.cwd) };
    let (reader, writer) = match std::io::pipe() {
        Ok(pair) => pair,
        Err(error) => return failed(format!("cannot open a pipe: {error}")),
    };
    let child = writer.try_clone().map(|second| {
        Command::new(&shell)
            .arg("-lc")
            .arg(&schedule.command)
            .current_dir(&cwd)
            .env_remove("CORTEX_FRAME_SOCKET")
            .env_remove("CORTEX_PLUGIN_INSTANCE")
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(second)
            .process_group(0)
            .spawn()
    });
    // The Command (and its copies of the pipe's write end) is gone here, so the reader ends
    // when the job's processes close their output.
    let mut child = match child {
        Ok(Ok(child)) => child,
        Ok(Err(error)) | Err(error) => return failed(format!("cannot start {shell}: {error}")),
    };

    started(child.id());
    let needle = schedule.alert_on.to_lowercase();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let collect = seen.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
            let text = String::from_utf8_lossy(&line).trim_end().to_owned();
            line.clear();
            let mut seen = collect.lock().unwrap_or_else(|p| p.into_inner());
            seen.matched |= !needle.is_empty() && text.to_lowercase().contains(&needle);
            if seen.lines.len() < LINES {
                seen.lines.push((now_ms(), shorten(&text, 2000)));
            }
            seen.tail.push_back(shorten(&text, 400));
            if seen.tail.len() > TAIL {
                seen.tail.pop_front();
            }
        }
        let _ = done_tx.send(());
    });

    let deadline = Instant::now() + TIMEOUT;
    let pgid = child.id() as i32;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() >= deadline => {
                // SAFETY: the job runs in its own process group, created for it above.
                unsafe { libc::killpg(pgid, libc::SIGKILL) };
                break (child.wait().ok(), true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break (None, false),
        }
    };
    // Something it left running in the background may hold the output open: wait a little.
    let _ = done_rx.recv_timeout(Duration::from_secs(2));
    let (mut tail, matched, lines) = {
        let mut seen = seen.lock().unwrap_or_else(|p| p.into_inner());
        (seen.tail.iter().cloned().collect::<Vec<_>>(), seen.matched, std::mem::take(&mut seen.lines))
    };
    if timed_out {
        tail.push(format!("(stopped after {} minutes)", TIMEOUT.as_secs() / 60));
        if tail.len() > TAIL {
            tail.remove(0);
        }
    }
    let exit_code = match status {
        Some(status) => status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        None => -1,
    };
    Outcome { exit_code, tail, matched, timed_out, lines }
}
