//! The background sampler: machine metrics every tick (2 s), the process scan (with per-process
//! GPU time from the IORegistry) every 4 s, ports
//! every 5 s, battery every 30 s, and the watchers that read those samples. Power and GPU come
//! from macmon on its own thread (it blocks for each sample window).

use crate::alerts::Candidate;
use crate::procs::{Entry, Snapshot, app_of};
use crate::util::{now_ms, plural, shorten};
use crate::{host, ports};
use cc_protocol::contracts::system::{Alert, Battery, Metrics, Port, Proc};

use std::collections::{HashMap, VecDeque};

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sysinfo::{Disks, Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

const GB: f64 = 1_000_000_000.0;
const MB: f64 = 1_000_000.0;

/// GPU use and power from macmon (all `None` where macmon does not run).
#[derive(Debug, Clone, Copy, Default)]
pub struct Power {
    /// How much of the GPU's capacity is used (busy time scaled by clock), 0..100.
    pub gpu: Option<f32>,
    /// How much of the time the GPU is busy at any clock, 0..100.
    pub gpu_active: Option<f32>,
    pub cpu_power: Option<f32>,
    pub gpu_power: Option<f32>,
    pub ane_power: Option<f32>,
    /// Average CPU and GPU die temperature, °C.
    pub cpu_temp: Option<f32>,
    pub gpu_temp: Option<f32>,
    /// The fastest fan, rpm; `None` on a Mac without fans.
    pub fan_rpm: Option<u32>,
}

/// Start macmon on its own thread; it keeps `power` current (2 s windows).
pub fn spawn_power(power: Arc<Mutex<Power>>) {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let _ = std::thread::Builder::new().name("macmon".into()).spawn(move || {
            let mut sampler = match macmon::Sampler::new() {
                Ok(sampler) => sampler,
                Err(error) => {
                    tracing::warn!("macmon is unavailable: {error}");
                    return;
                }
            };
            loop {
                match sampler.get_metrics(2000) {
                    Ok(m) => {
                        if let Ok(mut p) = power.lock() {
                            *p = Power {
                                gpu: Some((m.gpu_scaled_ratio * 100.0).clamp(0.0, 100.0)),
                                gpu_active: Some((m.gpu_active_ratio * 100.0).clamp(0.0, 100.0)),
                                cpu_power: Some(m.cpu_power),
                                gpu_power: Some(m.gpu_power),
                                ane_power: Some(m.ane_power),
                                cpu_temp: m.temp.cpu_temp_avg,
                                gpu_temp: m.temp.gpu_temp_avg,
                                fan_rpm: m.fans.iter().map(|fan| fan.rpm).max(),
                            };
                        }
                    }
                    Err(error) => {
                        tracing::warn!("macmon sample failed: {error}");
                        std::thread::sleep(Duration::from_secs(10));
                    }
                }
            }
        });
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::thread::Builder::new().name("linux-sensors".into()).spawn(move || {
            let mut sensors = crate::linux::Sensors::new();
            loop {
                let sample = sensors.sample();
                if let Ok(mut current) = power.lock() { *current = sample; }
                std::thread::sleep(Duration::from_secs(2));
            }
        });
    }
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
    {
        let _ = power;
    }
}

/// Build tools that rightly use a whole core for minutes.
const BUSY_BY_DESIGN: &[&str] = &[
    "cc",
    "c++",
    "clang",
    "clang++",
    "gcc",
    "g++",
    "rustc",
    "cargo",
    "swift-frontend",
    "swiftc",
    "swift-build",
    "ld",
    "ld64",
    "lld",
    "ld.lld",
    "go",
    "javac",
    "kotlinc",
    "tsc",
    "esbuild",
    "xcodebuild",
    "make",
    "ninja",
    "cmake",
    "ffmpeg",
    "kernel_task",
    "llama-server",
    "ollama",
];

#[derive(Debug, Default)]
struct SeenPorts {
    /// `<process name>:<port>` -> last seen (Unix ms).
    seen: HashMap<String, u64>,
    /// Loaded from the graph (nothing is judged before).
    loaded: bool,
}

/// The listening ports seen in the last two weeks, from the graph (at start):
/// `(:Port {key: process:port, bind, public})-[:OPENED_BY]->(:Binary)`, last seen as `last_ms`.
static LOADED_PORTS: std::sync::Mutex<Option<HashMap<String, u64>>> = std::sync::Mutex::new(None);

pub async fn load_ports() -> Result<usize, String> {
    let since = now_ms().saturating_sub(14 * 24 * 3_600_000);
    let rows = crate::graph::query_all("MATCH (p:Port) WHERE p.last_ms >= $since RETURN p.key, p.last_ms ORDER BY p.key", serde_json::json!({"since": since})).await?;
    let seen: HashMap<String, u64> = rows.iter().map(|row| (crate::graph::text(&row[0]), crate::graph::number(&row[1]))).collect();
    let count = seen.len();
    // Older ones are not listening any more.
    let stale = crate::graph::query_all("MATCH (p:Port) WHERE p.last_ms < $since AND p.ended_ms IS NULL RETURN p.key ORDER BY p.key", serde_json::json!({"since": since})).await?;
    let stale: Vec<_> = stale.iter().map(|row| crate::graph::r("Port", crate::graph::text(&row[0]))).collect();
    if !stale.is_empty() {
        crate::graph::retire(stale, "not listening for two weeks");
    }
    *LOADED_PORTS.lock().unwrap_or_else(|p| p.into_inner()) = Some(seen);
    Ok(count)
}

/// Ports seen now, as nodes: who opened them (its program), the folder it runs in (a dev
/// server's project), and where they listen.
fn write_ports(ports: &[&Port], exe_of: &HashMap<u32, String>) {
    use crate::graph::{Props, r};
    let Some(machine) = crate::graph::machine() else { return };
    let mut batch = crate::graph::Batch::new();
    for port in ports {
        let key = format!("{}:{}", port.process, port.port);
        let unit = batch.unit();
        unit.node("Port", key.clone()).p("port", port.port).p("bind", port.address.clone()).p("public", port.public).p("process", port.process.clone());
        match exe_of.get(&port.pid).filter(|e| !e.is_empty()) {
            Some(exe) => {
                unit.node("Binary", exe.clone());
                unit.edge(r("Binary", exe.clone()), "ON", machine.clone());
                unit.edge(r("Port", key.clone()), "OPENED_BY", r("Binary", exe.clone()));
            }
            None => {
                unit.edge(r("Port", key.clone()), "ON", machine.clone());
            }
        }
        let cwd = crate::host::cwd_of(port.pid);
        if cwd.starts_with('/') && cwd != "/" {
            let folder = crate::graph::folder(unit, std::path::Path::new(&cwd));
            unit.edge(r("Port", key), "IN", folder);
        }
    }
    crate::graph::put(batch);
}

struct Watch {
    /// pid -> since when it has been above 90% of a core.
    hot_since: HashMap<u32, Instant>,
    /// pid -> one memory reading a minute.
    memory: HashMap<u32, VecDeque<(Instant, u64)>>,
    /// One free-space reading a minute (Unix ms, bytes).
    disk: VecDeque<(u64, u64)>,
    ports: SeenPorts,
    ports_saved: Instant,
    /// The first port scan after a fresh install only records what is there.
    ports_baseline: bool,
}

pub struct Sampler {
    sys: System,
    nets: Networks,
    disks: Disks,
    users: HashMap<u32, String>,
    machine: String,
    p_cores: u32,
    e_cores: u32,
    last_tick: Instant,
    last_procs: Option<Instant>,
    last_ports: Option<Instant>,
    last_slow: Option<Instant>,
    battery: Option<Battery>,
    #[cfg(target_os = "linux")]
    disk_previous: Option<(u64, u64)>,
    /// The previous scan's GPU time per pid (ns), to turn into a share of the interval.
    gpu_prev: Option<(Instant, HashMap<u32, u64>)>,
    pub ports: Vec<Port>,
    pub snapshot: Snapshot,
    watch: Watch,
}

impl Sampler {
    pub fn new() -> Self {
        let (machine, p_cores, e_cores) = host::machine();
        let users = Users::new_with_refreshed_list().list().iter().map(|u| (**u.id(), u.name().to_owned())).collect();
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        Sampler {
            sys,
            nets: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            users,
            machine,
            p_cores,
            e_cores,
            last_tick: Instant::now(),
            last_procs: None,
            last_ports: None,
            last_slow: None,
            battery: None,
            #[cfg(target_os = "linux")]
            disk_previous: None,
            gpu_prev: None,
            ports: Vec::new(),
            snapshot: Snapshot::default(),
            watch: Watch {
                hot_since: HashMap::new(),
                memory: HashMap::new(),
                disk: VecDeque::new(),
                ports: SeenPorts::default(),
                ports_saved: Instant::now(),
                ports_baseline: true,
            },
        }
    }

    /// One sample, and what the watchers found in it.
    pub fn tick(&mut self, power: Power) -> (Metrics, Vec<Candidate>) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_tick).as_secs_f64().max(0.5);
        self.last_tick = now;
        let due = |last: Option<Instant>, every: u64| last.is_none_or(|t| now.duration_since(t) >= Duration::from_millis(every));
        let mut found = Vec::new();

        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.nets.refresh(true);
        self.disks.refresh(true);

        let mut cores: Vec<f32> = self.sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();
        // The kernel numbers efficiency cores first; the contract wants performance cores first.
        let e = self.e_cores as usize;
        if e > 0 && (self.p_cores as usize + e) == cores.len() {
            cores.rotate_left(e);
        }
        let root = self.disks.list().iter().find(|d| d.mount_point() == std::path::Path::new("/")).or_else(|| self.disks.list().first());
        let capacity = root.map(|d| (d.total_space(), d.available_space()));
        #[cfg(target_os = "linux")]
        let capacity = crate::linux::root_capacity().or(capacity);
        let (disk_total, disk_free) = capacity.unwrap_or_default();
        // Volumes on one physical disk report that disk's traffic: take the busiest, not the sum.
        #[cfg(not(target_os = "linux"))]
        let disk_read = self.disks.list().iter().map(|d| d.usage().read_bytes).max().unwrap_or(0);
        #[cfg(not(target_os = "linux"))]
        let disk_write = self.disks.list().iter().map(|d| d.usage().written_bytes).max().unwrap_or(0);
        #[cfg(target_os = "linux")]
        let (disk_read, disk_write) = match crate::linux::disk_bytes() {
            Some(current) => {
                let previous = self.disk_previous.replace(current).unwrap_or(current);
                (current.0.saturating_sub(previous.0), current.1.saturating_sub(previous.1))
            }
            None => { self.disk_previous = None; (0, 0) }
        };
        let (mut rx, mut tx) = (0u64, 0u64);
        for (name, data) in self.nets.list() {
            if !name.starts_with("lo") {
                rx += data.received();
                tx += data.transmitted();
            }
        }
        if due(self.last_slow, 30_000) {
            self.last_slow = Some(now);
            self.battery = host::battery();
        }
        let ports_due = due(self.last_ports, 5_000);
        if ports_due {
            self.last_ports = Some(now);
            self.ports = ports::scan();
        }
        if due(self.last_procs, 4_000) {
            let proc_dt = self.last_procs.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(dt).max(0.5);
            self.last_procs = Some(now);
            self.scan_processes(proc_dt);
            found.extend(self.watch_processes(now));
        }
        if ports_due {
            found.extend(self.watch_ports());
        }
        let load = System::load_average();
        let metrics = Metrics {
            at: now_ms(),
            machine: self.machine.clone(),
            memory_total: self.sys.total_memory(),
            cpu: self.sys.global_cpu_usage(),
            cores,
            p_cores: self.p_cores,
            e_cores: self.e_cores,
            memory_used: self.sys.used_memory(),
            memory_compressed: host::compressed_memory(),
            swap_used: self.sys.used_swap(),
            pressure: host::pressure(),
            gpu: power.gpu,
            gpu_active: power.gpu_active,
            cpu_power: power.cpu_power,
            gpu_power: power.gpu_power,
            ane_power: power.ane_power,
            cpu_temp: power.cpu_temp,
            gpu_temp: power.gpu_temp,
            fan_rpm: power.fan_rpm,
            thermal: host::thermal(),
            disk_total,
            disk_free,
            disk_read: (disk_read as f64 / dt) as u64,
            disk_write: (disk_write as f64 / dt) as u64,
            net_rx: (rx as f64 / dt) as u64,
            net_tx: (tx as f64 / dt) as u64,
            battery: self.battery.clone(),
            load: [load.one as f32, load.five as f32, load.fifteen as f32],
        };
        found.extend(self.watch_disk(&metrics));
        (metrics, found)
    }

    fn scan_processes(&mut self, dt: f64) {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage()
                .with_exe(UpdateKind::OnlyIfNotSet)
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_user(UpdateKind::OnlyIfNotSet),
        );
        let mut ports_by_pid: HashMap<u32, Vec<u16>> = HashMap::new();
        for port in &self.ports {
            ports_by_pid.entry(port.pid).or_default().push(port.port);
        }
        for list in ports_by_pid.values_mut() {
            list.sort_unstable();
            list.dedup();
        }
        // GPU share since the previous scan; `None` until there are two readings, or when the
        // registry cannot be read.
        let gpu_now = host::gpu_times().map(|times| (Instant::now(), times));
        let gpu_share = |pid: u32| -> Option<f32> {
            let ((then, before), (now, after)) = (self.gpu_prev.as_ref()?, gpu_now.as_ref()?);
            let wall = now.duration_since(*then).as_nanos().max(1) as f64;
            let used = after.get(&pid).zip(before.get(&pid)).map(|(a, b)| a.saturating_sub(*b)).unwrap_or(0);
            Some((used as f64 / wall * 100.0).clamp(0.0, 100.0) as f32)
        };
        let mut entries = Vec::with_capacity(self.sys.processes().len());
        for (pid, process) in self.sys.processes() {
            // Threads show up as tasks on Linux; list processes only.
            if process.thread_kind().is_some() {
                continue;
            }
            let pid = pid.as_u32();
            let name = process.name().to_string_lossy().into_owned();
            let exe = process.exe().map(|p| p.display().to_string()).unwrap_or_default();
            let uid = process.user_id().map(|u| **u).unwrap_or(u32::MAX);
            let command = process.cmd().iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
            // SAFETY: getpgid has no preconditions; -1 means we may not ask.
            let pgid = unsafe { libc::getpgid(pid as i32) };
            entries.push(Entry {
                proc: Proc {
                    pid,
                    ppid: process.parent().map(Pid::as_u32).unwrap_or(0),
                    app: app_of(&exe, &name, pid, uid),
                    name,
                    command: shorten(&command, 400),
                    user: self.users.get(&uid).cloned().unwrap_or_default(),
                    cpu: process.cpu_usage(),
                    memory: host::footprint(pid).unwrap_or_else(|| process.memory()),
                    disk_write: (process.disk_usage().written_bytes as f64 / dt) as u64,
                    ports: ports_by_pid.remove(&pid).unwrap_or_default(),
                    gpu: gpu_share(pid),
                    started: process.start_time(),
                    pgid: pgid.max(0) as u32,
                },
                exe,
                uid,
            });
        }
        self.gpu_prev = gpu_now;
        self.snapshot = Snapshot { at: now_ms(), entries };
    }

    /// Runaway CPU (above 90% of a core for two minutes) and memory climb (more than 5 MB a minute
    /// for 15 minutes, mostly rising).
    fn watch_processes(&mut self, now: Instant) -> Vec<Candidate> {
        let mut found = Vec::new();
        let me = std::process::id();
        let alive: std::collections::HashSet<u32> = self.snapshot.entries.iter().map(|e| e.proc.pid).collect();
        self.watch.hot_since.retain(|pid, _| alive.contains(pid));
        self.watch.memory.retain(|pid, _| alive.contains(pid));
        for entry in &self.snapshot.entries {
            let p = &entry.proc;
            if p.pid == 0 || p.pid == me {
                continue;
            }
            if p.cpu > 90.0 && !BUSY_BY_DESIGN.contains(&p.name.as_str()) {
                let since = *self.watch.hot_since.entry(p.pid).or_insert(now);
                let minutes = now.duration_since(since).as_secs() / 60;
                if minutes >= 2 {
                    found.push(Candidate {
                        key: format!("cpu:{}:{}", p.pid, p.name),
                        alert: Alert {
                            kind: "cpu".into(),
                            severity: "warn".into(),
                            text: format!("{} (pid {}) has kept a CPU core above 90% busy for {} minutes.", p.name, p.pid, minutes),
                            pid: Some(p.pid),
                            path: (!entry.exe.is_empty()).then(|| entry.exe.clone()),
                            actions: vec!["show".into(), "kill".into()],
                            ..Default::default()
                        },
                    });
                }
            } else {
                self.watch.hot_since.remove(&p.pid);
            }

            let history = self.watch.memory.entry(p.pid).or_default();
            if history.back().is_none_or(|(at, _)| now.duration_since(*at) >= Duration::from_secs(60)) {
                history.push_back((now, p.memory));
                while history.len() > 16 {
                    history.pop_front();
                }
            }
            if history.len() == 16 {
                let (first_at, first) = history[0];
                let (last_at, last) = history[15];
                let minutes = last_at.duration_since(first_at).as_secs_f64() / 60.0;
                let rising = history.iter().zip(history.iter().skip(1)).filter(|(a, b)| b.1 >= a.1).count();
                let grown = last.saturating_sub(first) as f64;
                if minutes >= 14.0 && grown / minutes > 5.0 * MB && rising >= 12 {
                    found.push(Candidate {
                        key: format!("memory:{}:{}", p.pid, p.name),
                        alert: Alert {
                            kind: "memory".into(),
                            severity: "warn".into(),
                            text: format!(
                                "{} (pid {}) has grown by {:.0} MB in the last {:.0} minutes and keeps climbing, so it may be leaking memory.",
                                p.name,
                                p.pid,
                                grown / MB,
                                minutes
                            ),
                            pid: Some(p.pid),
                            path: (!entry.exe.is_empty()).then(|| entry.exe.clone()),
                            actions: vec!["show".into(), "kill".into()],
                            ..Default::default()
                        },
                    });
                }
            }
        }
        found
    }

    /// Disk full: a straight line through the last hour of free space; warn under 48 h, high under
    /// 24 h; and 90% used.
    fn watch_disk(&mut self, m: &Metrics) -> Vec<Candidate> {
        let mut found = Vec::new();
        if m.disk_total == 0 {
            return found;
        }
        let now = m.at;
        if self.watch.disk.back().is_none_or(|(at, _)| now.saturating_sub(*at) >= 60_000) {
            self.watch.disk.push_back((now, m.disk_free));
            while self.watch.disk.front().is_some_and(|(at, _)| now.saturating_sub(*at) > 3_600_000) {
                self.watch.disk.pop_front();
            }
        }
        let used = 1.0 - m.disk_free as f64 / m.disk_total as f64;
        if used >= 0.9 {
            found.push(Candidate {
                key: "disk:full90".into(),
                alert: Alert {
                    kind: "disk".into(),
                    severity: if used >= 0.95 { "high" } else { "warn" }.into(),
                    text: format!("The startup disk is {:.0}% full, with {:.1} GB left.", used * 100.0, m.disk_free as f64 / GB),
                    path: Some("/".into()),
                    actions: vec!["show".into()],
                    ..Default::default()
                },
            });
        }
        // Least squares over at least 20 minutes of readings.
        let points = &self.watch.disk;
        if points.len() >= 20 {
            let n = points.len() as f64;
            let t0 = points[0].0 as f64;
            let xs: Vec<f64> = points.iter().map(|(t, _)| (*t as f64 - t0) / 3_600_000.0).collect();
            let ys: Vec<f64> = points.iter().map(|(_, free)| *free as f64).collect();
            let (mx, my) = (xs.iter().sum::<f64>() / n, ys.iter().sum::<f64>() / n);
            let sxx: f64 = xs.iter().map(|x| (x - mx).powi(2)).sum();
            let sxy: f64 = xs.iter().zip(&ys).map(|(x, y)| (x - mx) * (y - my)).sum();
            let per_hour = if sxx > 0.0 { sxy / sxx } else { 0.0 };
            if per_hour < 0.0 {
                let hours = m.disk_free as f64 / -per_hour;
                if hours < 48.0 {
                    found.push(Candidate {
                        key: "disk:eta".into(),
                        alert: Alert {
                            kind: "disk".into(),
                            severity: if hours < 24.0 { "high" } else { "warn" }.into(),
                            text: format!(
                                "At the rate it filled over the last hour ({:.1} GB an hour), the startup disk will be full in about {} ({:.1} GB left).",
                                -per_hour / GB,
                                plural(hours.round().max(1.0) as usize, "hour", "hours"),
                                m.disk_free as f64 / GB
                            ),
                            path: Some("/".into()),
                            actions: vec!["show".into()],
                            ..Default::default()
                        },
                    });
                }
            }
        }
        found
    }

    /// A new port open to the network: a program and port pair not seen in 7 days, bound to every
    /// interface.
    fn watch_ports(&mut self) -> Vec<Candidate> {
        let now = now_ms();
        let week = 7 * 24 * 3_600_000;
        if !self.watch.ports.loaded {
            // What was seen before is in the graph: nothing is judged until it is loaded.
            let Some(seen) = LOADED_PORTS.lock().unwrap_or_else(|p| p.into_inner()).take() else { return Vec::new() };
            self.watch.ports_baseline = seen.is_empty();
            self.watch.ports = SeenPorts { seen, loaded: true };
        }
        let exe_of: HashMap<u32, String> = self.snapshot.entries.iter().map(|e| (e.proc.pid, e.exe.clone())).collect();
        let mut found = Vec::new();
        let mut added = false;
        let mut fresh_ports = Vec::new();
        for port in &self.ports {
            let key = format!("{}:{}", port.process, port.port);
            let fresh = self.watch.ports.seen.get(&key).is_none_or(|at| now.saturating_sub(*at) > week);
            added |= fresh;
            if fresh {
                fresh_ports.push(port);
            }
            self.watch.ports.seen.insert(key.clone(), now);
            // Apple's own services (Handoff, AirPlay, sharing) open ports as part of their job;
            // they are recorded with the rest, not alerted.
            let apple = || exe_of.get(&port.pid).is_some_and(|exe| !exe.is_empty() && crate::codesign::check(std::path::Path::new(exe)).apple);
            if fresh && port.public && !self.watch.ports_baseline && !apple() {
                found.push(Candidate {
                    key: format!("port:{key}"),
                    alert: Alert {
                        kind: "port".into(),
                        severity: "warn".into(),
                        text: format!(
                            "{} (pid {}) started listening on port {} on every network interface, so other machines on your network can reach it.",
                            port.process, port.pid, port.port
                        ),
                        pid: Some(port.pid),
                        port: Some(port.port),
                        path: exe_of.get(&port.pid).filter(|e| !e.is_empty()).cloned(),
                        actions: vec!["show".into(), "kill".into()],
                        ..Default::default()
                    },
                });
            }
        }
        self.watch.ports_baseline = false;
        if self.watch.ports_saved.elapsed() >= Duration::from_secs(600) {
            // Every port open now, so its last_ms says it is still seen; one not seen for two
            // weeks is marked gone.
            let gone: Vec<_> = self.watch.ports.seen.iter().filter(|(_, at)| now.saturating_sub(**at) > 2 * week).map(|(key, _)| crate::graph::r("Port", key.clone())).collect();
            if !gone.is_empty() {
                crate::graph::retire(gone, "not listening for two weeks");
            }
            self.watch.ports.seen.retain(|_, at| now.saturating_sub(*at) <= 2 * week);
            write_ports(&self.ports.iter().collect::<Vec<_>>(), &exe_of);
            self.watch.ports_saved = Instant::now();
        } else if added {
            write_ports(&fresh_ports, &exe_of);
        }
        found
    }
}
