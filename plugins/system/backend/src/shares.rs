//! What this plugin shares (`cc_protocol::contracts::service`): the trace service and the schedule
//! service, with a description and a params schema for every method, written for people and
//! models alike. Members read them; the mesh lends only these.

use cc_protocol::contracts::service::{Share, ShareList, SharedMethod};
use serde_json::{Value, json};

fn method(name: &str, description: &str, params: Value) -> SharedMethod {
    SharedMethod { method: name.into(), description: description.into(), params }
}

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

fn id(what: &str) -> Value {
    object(json!({"id": {"type": "string", "description": what}}), &["id"])
}

fn read_params(what: &str) -> Value {
    object(
        json!({
            "id": {"type": "string", "description": what},
            "size": {"type": "string", "enum": ["line", "summary", "series", "records"], "description": "line: one line; summary: a few KB of numbers, phases, what it touched and errors; series: points for a chart; records: the raw records of a span (with from, to, kinds, limit). Ask for the smallest that will do."},
            "from": {"type": "integer", "description": "Unix milliseconds; the whole trace when absent."},
            "to": {"type": "integer", "description": "Unix milliseconds."},
            "kinds": {"type": "array", "items": {"type": "string"}, "description": "For records: sample, start, end, open, close, connect, listen, output, exit."},
            "limit": {"type": "integer", "description": "For records: at most this many (500 when absent)."}
        }),
        &["id"],
    )
}

fn schedule_fields() -> Value {
    json!({
        "name": {"type": "string", "description": "A short name."},
        "kind": {"type": "string", "enum": ["command", "sweep"], "description": "command: a shell command; sweep: the security sweep."},
        "command": {"type": "string", "description": "The shell command, run non-interactively in the user's login shell."},
        "cwd": {"type": "string", "description": "The folder it runs in (the home folder when empty)."},
        "when": {"type": "string", "description": "`daily HH:MM`, `hourly`, `every N min` or `weekly <mon..sun> HH:MM`, local time."},
        "enabled": {"type": "boolean"},
        "alert_on": {"type": "string", "description": "Also alert when the output contains this text."}
    })
}

pub fn shares() -> ShareList {
    let trace = Share {
        service: "system.trace".into(),
        version: 1,
        title: "Traces".into(),
        description: "A week of what a process tree did: CPU, memory, GPU, disk, the processes that came and went, files, connections, ports and output.".into(),
        methods: vec![
            method(
                "system.trace.run",
                "Start recording a running process and its children. Answers the trace (its id is read as trace://<id>).",
                object(json!({"pid": {"type": "integer"}, "label": {"type": "string", "description": "What lists call it."}}), &["pid"]),
            ),
            method("system.trace.stop", "Stop recording a trace.", id("The trace id.")),
            method("system.trace.list", "The traces kept, newest first.", object(json!({"limit": {"type": "integer"}}), &[])),
            method("system.trace.read", "One trace in the size asked for: line, summary, series or records.", read_params("The trace id.")),
            method("system.trace.graph.get", "A trace's graph: its programs and the folders, hosts and ports they used.", id("The trace id.")),
            method("system.trace.delete", "Stop a trace if it records, and delete it.", id("The trace id.")),
        ],
    };
    let create = schedule_fields();
    let mut edit = schedule_fields();
    edit["id"] = json!({"type": "string", "description": "The schedule to change."});
    let schedule = Share {
        service: "system.schedule".into(),
        version: 1,
        title: "Scheduled jobs".into(),
        description: "Commands that run at set times on this machine while CortexTerm runs; every run is traced and its whole output kept a week.".into(),
        methods: vec![
            method("system.schedule.list", "The scheduled jobs with their last result.", object(json!({}), &[])),
            method("system.schedule.get", "One scheduled job.", id("The schedule id.")),
            method("system.schedule.create", "Add a scheduled job.", object(create, &["name", "kind", "when"])),
            method("system.schedule.edit", "Change a scheduled job: send it whole, with its id.", object(edit, &["id", "name", "kind", "when"])),
            method("system.schedule.delete", "Remove a scheduled job.", id("The schedule id.")),
            method("system.schedule.run", "Run a scheduled job now and wait for its result (at most 10 minutes).", id("The schedule id.")),
            method(
                "system.schedule.runs.list",
                "The runs kept (a week), newest first; each run is a trace with its whole output.",
                object(json!({"id": {"type": "string", "description": "One schedule's runs; all when absent."}, "limit": {"type": "integer"}}), &[]),
            ),
            method("system.schedule.runs.read", "One run in the size asked for: line, summary, series or records (records with kinds [\"output\"] is its output).", read_params("The run's trace id.")),
        ],
    };
    ShareList { shares: vec![trace, schedule] }
}
