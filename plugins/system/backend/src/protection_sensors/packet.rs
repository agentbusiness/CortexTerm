//! TCP SYN metadata watch. Captures only the current machine's visible interfaces without
//! promiscuous mode. Port probes are attempts, never evidence of successful access.

use super::Collection;
use cc_protocol::contracts::system::{ProtectionSensor, SecurityObservation};
use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const WINDOW: u64 = 60_000;
const QUIET: u64 = 300_000;
const LIMIT: usize = 4096;

struct Packet {
    at: u64,
    source: IpAddr,
    dest: IpAddr,
    port: u16,
}
struct Bucket {
    since: u64,
    ports: BTreeSet<u16>,
    destinations: BTreeSet<IpAddr>,
    reported: u64,
}
enum Message {
    Line(Vec<u8>),
    Error(String),
}

struct Capture {
    child: Child,
    receiver: mpsc::Receiver<Message>,
    readers: Vec<JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
    last_error: String,
    kernel_dropped: u64,
    started: Instant,
    stats_at: Instant,
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

pub(super) struct PacketWatch {
    capture: Option<Capture>,
    next_retry: Instant,
    locals: BTreeSet<IpAddr>,
    incoming: HashMap<(IpAddr, IpAddr), Bucket>,
    outgoing: HashMap<IpAddr, Bucket>,
    last_at: u64,
    dropped: u64,
    error: String,
    reported: HashMap<String, u64>,
}

impl PacketWatch {
    pub fn new() -> Self {
        Self {
            capture: None,
            next_retry: Instant::now(),
            locals: BTreeSet::new(),
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
            last_at: 0,
            dropped: 0,
            error: String::new(),
            reported: HashMap::new(),
        }
    }

    fn stop(&mut self) {
        if let Some(capture) = self.capture.take() {
            self.dropped = self
                .dropped
                .saturating_add(capture.dropped.load(Ordering::Relaxed))
                .saturating_add(capture.kernel_dropped);
            drop(capture);
        }
    }

    pub fn collect(&mut self, enabled: bool) -> Collection {
        let mut result = Collection {
            observations: Vec::new(),
            sensors: Vec::new(),
        };
        let now = crate::util::now_ms();
        let mut status = ProtectionSensor {
            id: "packet-watch".into(),
            label: "Scan detection".into(),
            last_at: self.last_at,
            dropped: self.dropped,
            ..Default::default()
        };
        if !enabled {
            self.stop();
            self.incoming.clear();
            self.outgoing.clear();
            self.reported.clear();
            status.dropped = self.dropped;
            status.state = "disabled".into();
            status.detail = "Packet monitoring is off.".into();
            result.sensors.push(status);
            return result;
        }
        let locals = local_addresses();
        if locals != self.locals {
            self.stop();
            self.incoming.clear();
            self.outgoing.clear();
            self.reported.clear();
            self.locals = locals;
            self.next_retry = Instant::now();
        }
        if self.locals.is_empty() {
            self.stop();
            status.state = "unavailable".into();
            status.detail =
                "No active non-loopback IPv4 or IPv6 interface address is available.".into();
            result.sensors.push(status);
            return result;
        }
        if self.capture.is_none() && Instant::now() >= self.next_retry {
            self.next_retry = Instant::now() + Duration::from_secs(30);
            match start_capture() {
                Ok(capture) => {
                    self.capture = Some(capture);
                    self.error.clear();
                }
                Err(error) => self.error = error,
            }
        }
        let mut packets = Vec::new();
        let mut ended = false;
        if let Some(capture) = self.capture.as_mut() {
            match capture.child.try_wait() {
                Ok(Some(exit)) => {
                    ended = true;
                    // Drain what tcpdump said before exiting so the reason is the real one.
                    while let Ok(message) = capture.receiver.recv_timeout(Duration::from_millis(50)) {
                        if let Message::Error(line) = message {
                            capture.last_error = line;
                        }
                    }
                    self.error = if denied(&capture.last_error) {
                        "Packet capture permission is missing: macOS lets only root read the BPF capture devices (/dev/bpf*). CT never elevates itself. Grant your user read access to BPF (for example with Wireshark's ChmodBPF) and scan detection starts within 30 seconds.".into()
                    } else {
                        format!("Packet collector exited ({exit}). {}", capture.last_error)
                    };
                }
                Err(error) => {
                    ended = true;
                    self.error = format!("Cannot inspect packet collector: {error}");
                }
                _ => (),
            }
            for _ in 0..8192 {
                match capture.receiver.try_recv() {
                    Ok(Message::Line(line)) => {
                        if let Some(packet) = parse(&line) {
                            packets.push(packet);
                        } else {
                            self.dropped = self.dropped.saturating_add(1);
                        }
                    }
                    Ok(Message::Error(line)) => {
                        if let Some(count) = line
                            .split_whitespace()
                            .next()
                            .and_then(|s| s.parse::<u64>().ok())
                            .filter(|_| line.contains("dropped by kernel"))
                        {
                            capture.kernel_dropped = count;
                        }
                        capture.last_error = clean(&line, 240);
                    }
                    Err(_) => break,
                }
            }
            if !ended && capture.stats_at.elapsed() >= Duration::from_secs(30) {
                #[cfg(target_os = "macos")]
                let signal = libc::SIGINFO;
                #[cfg(not(target_os = "macos"))]
                let signal = libc::SIGUSR1;
                // tcpdump handles this signal by printing cumulative capture/drop statistics.
                // Only its still-owned child PID is addressed, immediately after try_wait.
                let _ = unsafe { libc::kill(capture.child.id() as i32, signal) };
                capture.stats_at = Instant::now();
            }
            status.dropped = self
                .dropped
                .saturating_add(capture.dropped.load(Ordering::Relaxed))
                .saturating_add(capture.kernel_dropped);
            status.state = if capture.started.elapsed() < Duration::from_secs(3) {
                "starting"
            } else if status.dropped > 0 {
                "degraded"
            } else {
                "active"
            }
            .into();
            status.last_at = now;
            status.detail = format!(
                "TCP connection-attempt metadata on this Mac's visible interfaces. Last matching packet: {}. No packet payload is stored. IPv6 extension-header traffic, UDP probes, encrypted tunnels and probes discarded upstream may be invisible; scans elsewhere on the LAN need a network sensor.",
                if self.last_at == 0 {
                    "none yet".into()
                } else {
                    format!("{} seconds ago", now.saturating_sub(self.last_at) / 1000)
                }
            );
            if !capture.last_error.is_empty() && !capture.last_error.contains("listening on") {
                status
                    .detail
                    .push_str(&format!(" Collector: {}", capture.last_error));
            }
        } else {
            status.state = "unavailable".into();
            status.detail = if self.error.is_empty() {
                "Packet capture is unavailable; CT never elevates itself. macOS needs a readable BPF device, and Linux needs capture permission.".into()
            } else {
                self.error.clone()
            };
        }
        if ended {
            self.stop();
            status.state = "unavailable".into();
            status.detail = self.error.clone();
            self.next_retry = Instant::now() + Duration::from_secs(30);
        }
        self.incoming
            .retain(|_, b| now.saturating_sub(b.since) <= WINDOW);
        self.outgoing
            .retain(|_, b| now.saturating_sub(b.since) <= WINDOW);
        self.reported
            .retain(|_, at| now.saturating_sub(*at) <= QUIET);
        for packet in packets {
            if packet.at > now.saturating_add(60_000) || now.saturating_sub(packet.at) > WINDOW {
                self.dropped = self.dropped.saturating_add(1);
                continue;
            }
            self.last_at = packet.at;
            let from_local = self.locals.contains(&packet.source);
            let to_local = self.locals.contains(&packet.dest);
            if to_local && !from_local {
                let key = (packet.source, packet.dest);
                if self.incoming.len() >= LIMIT && !self.incoming.contains_key(&key) {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
                let bucket = self.incoming.entry(key).or_insert_with(|| Bucket {
                    since: packet.at,
                    ports: BTreeSet::new(),
                    destinations: BTreeSet::new(),
                    reported: 0,
                });
                if bucket.ports.len() < 128 {
                    bucket.ports.insert(packet.port);
                }
                let report_key = format!("scan:{}:{}", packet.source, packet.dest);
                if bucket.ports.len() >= 20
                    && !self.reported.contains_key(&report_key)
                    && self.reported.len() < LIMIT
                {
                    bucket.reported = packet.at;
                    self.reported.insert(report_key.clone(), packet.at);
                    result.observations.push(SecurityObservation {
                        at: packet.at, source: "packet-watch".into(), kind: "port_scan".into(), severity: "medium".into(),
                        summary: format!("{} sent TCP connection attempts to {} distinct ports on this Mac ({}) within 60 seconds. This is probing, not proof of a successful login or compromise.", packet.source, bucket.ports.len(), packet.dest),
                        rule: "network.port_scan".into(), subject: report_key, remote: Some(packet.source.to_string()), count: bucket.ports.len() as u64, ..Default::default()
                    });
                }
            } else if from_local
                && !to_local
                && !packet.dest.is_multicast()
                && !packet.dest.is_loopback()
            {
                if self.outgoing.len() >= LIMIT && !self.outgoing.contains_key(&packet.source) {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
                let bucket = self
                    .outgoing
                    .entry(packet.source)
                    .or_insert_with(|| Bucket {
                        since: packet.at,
                        ports: BTreeSet::new(),
                        destinations: BTreeSet::new(),
                        reported: 0,
                    });
                if bucket.destinations.len() < 128 {
                    bucket.destinations.insert(packet.dest);
                }
                if bucket.ports.len() < 128 {
                    bucket.ports.insert(packet.port);
                }
                // A wide fan-out on one or few ports deserves investigation, while normal browser
                // fan-out over HTTPS alone is far too common to flag as scanning.
                let ordinary_web = bucket.ports.iter().all(|p| [80, 443].contains(p));
                let report_key = format!("sweep:{}", packet.source);
                if bucket.destinations.len() >= 32
                    && bucket.ports.len() <= 4
                    && !ordinary_web
                    && !self.reported.contains_key(&report_key)
                    && self.reported.len() < LIMIT
                {
                    bucket.reported = packet.at;
                    self.reported.insert(report_key.clone(), packet.at);
                    result.observations.push(SecurityObservation {
                        at: packet.at, source: "packet-watch".into(), kind: "network_sweep".into(), severity: "medium".into(), summary: format!("This Mac ({}) sent TCP connection attempts to {} different addresses on a small set of ports within 60 seconds. This resembles a network sweep; legitimate discovery tools can do this too. Packet headers do not identify the responsible process.", packet.source, bucket.destinations.len()),
                        rule: "network.address_sweep".into(), subject: report_key, count: bucket.destinations.len() as u64, ..Default::default()
                    });
                }
            }
        }
        if self.capture.is_none() {
            status.last_at = self.last_at;
        }
        status.dropped = status.dropped.max(self.dropped);
        result.sensors.push(status);
        result
    }
}

fn start_capture() -> Result<Capture, String> {
    let executable = ["/usr/sbin/tcpdump", "/usr/bin/tcpdump"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or("tcpdump is unavailable; scan detection has no packet source.")?;
    // The IPv6 clause deliberately covers ordinary TCP headers only; the health text exposes
    // that limitation instead of pretending extension-header chains are parsed.
    let filter = "(ip and tcp[13] & 18 = 2) or (ip6 and ip6[6] = 6 and ip6[53] & 18 = 2)";
    // macOS pktap needs root to create its interface even when BPF is readable, so capture on
    // the interface that carries the default route.
    let interface = if cfg!(target_os = "macos") {
        default_interface().ok_or("No default-route interface; scan detection has no packet source.")?
    } else {
        "any".into()
    };
    let mut child = Command::new(executable)
        .args([
            "-l", "-n", "-tt", "-p", "-s", "256", "-i", &interface, filter,
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Cannot start packet metadata collector: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Packet collector has no output pipe.")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Packet collector has no diagnostic pipe.")?;
    let dropped = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::sync_channel(8192);
    let out_sender = sender.clone();
    let out_loss = dropped.clone();
    let out = std::thread::spawn(move || drain(stdout, out_sender, out_loss, false));
    let err_loss = dropped.clone();
    let err = std::thread::spawn(move || drain(stderr, sender, err_loss, true));
    Ok(Capture {
        child,
        receiver,
        readers: vec![out, err],
        dropped,
        last_error: String::new(),
        kernel_dropped: 0,
        started: Instant::now(),
        stats_at: Instant::now(),
    })
}

fn denied(error: &str) -> bool {
    ["Permission denied", "Operation not permitted", "don't have permission"]
        .iter()
        .any(|text| error.contains(text))
}

fn default_interface() -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
}

fn drain<R: Read>(reader: R, sender: mpsc::SyncSender<Message>, loss: Arc<AtomicU64>, error: bool) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let mut oversized = false;
        loop {
            let bytes = match reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(_) => {
                    loss.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            if bytes.is_empty() {
                return;
            }
            let count = bytes
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |i| i + 1);
            let done = bytes.get(count - 1) == Some(&b'\n');
            if !oversized && line.len() + count <= 4096 {
                line.extend_from_slice(&bytes[..count]);
            } else {
                line.clear();
                oversized = true;
            }
            reader.consume(count);
            if done {
                break;
            }
        }
        if oversized {
            loss.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let message = if error {
            Message::Error(clean(&String::from_utf8_lossy(&line), 240))
        } else {
            Message::Line(std::mem::take(&mut line))
        };
        match sender.try_send(message) {
            Ok(()) => (),
            Err(mpsc::TrySendError::Full(_)) => {
                loss.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return,
        }
    }
}

fn clean(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn parse(line: &[u8]) -> Option<Packet> {
    let line = std::str::from_utf8(line).ok()?;
    let flags = line.split_once("Flags [")?.1.split_once(']')?.0;
    // ECN-capable SYNs may print [SEW]/[SWE], not just [S]. A dot denotes ACK.
    if !flags.contains('S') || flags.contains('.') {
        return None;
    }
    let mut words = line.split_whitespace();
    let timestamp = words.next()?.parse::<f64>().ok()?;
    if !timestamp.is_finite() || timestamp < 0.0 {
        return None;
    }
    // macOS any/PKTAP may prefix the IP header with interface and direction metadata.
    let words: Vec<&str> = words.take(24).collect();
    let ip = words
        .iter()
        .position(|word| matches!(*word, "IP" | "IP6"))?;
    let (source, _) = endpoint(words.get(ip + 1)?)?;
    if words.get(ip + 2) != Some(&">") {
        return None;
    }
    let (dest, port) = endpoint(words.get(ip + 3)?.trim_end_matches(':'))?;
    Some(Packet {
        at: (timestamp * 1000.0) as u64,
        source,
        dest,
        port,
    })
}
fn endpoint(text: &str) -> Option<(IpAddr, u16)> {
    let (address, port) = text.rsplit_once('.')?;
    let address = address.split('%').next()?;
    Some((address.parse().ok()?, port.parse().ok()?))
}

pub(crate) fn local_addresses() -> BTreeSet<IpAddr> {
    let mut addresses = BTreeSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // getifaddrs allocates the list; all pointers are read only while it is live, and family
    // checks precede casts. No interface names or packet payloads are retained.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut next = head;
        while !next.is_null() {
            let item = &*next;
            if !item.ifa_addr.is_null()
                && item.ifa_flags & libc::IFF_UP as u32 != 0
                && item.ifa_flags & libc::IFF_LOOPBACK as u32 == 0
            {
                match (*item.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let address = &*(item.ifa_addr as *const libc::sockaddr_in);
                        addresses.insert(IpAddr::V4(std::net::Ipv4Addr::from(
                            address.sin_addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    libc::AF_INET6 => {
                        let address = &*(item.ifa_addr as *const libc::sockaddr_in6);
                        addresses.insert(IpAddr::V6(std::net::Ipv6Addr::from(
                            address.sin6_addr.s6_addr,
                        )));
                    }
                    _ => (),
                }
            }
            next = item.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses
}
