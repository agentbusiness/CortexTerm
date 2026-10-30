//! Linux collectors. procfs/sysfs need no agent, GPU or privileged helper. Missing permissions or
//! hardware leave optional readings absent rather than reporting a fabricated zero.

use crate::sampler::Power;
use cc_protocol::contracts::system::OpenFile;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn text(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn number(path: impl AsRef<Path>) -> Option<u64> {
    text(path)?.parse().ok()
}

fn dirs(path: impl AsRef<Path>) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect()
}

/// Physical block-device counters, excluding partitions and stacked devices (LVM/RAID would
/// otherwise count the underlying traffic again). Linux reports sectors in units of 512 bytes.
pub fn disk_bytes() -> Option<(u64, u64)> {
    let mut total = (0u64, 0u64);
    let mut read_any = false;
    for dev in dirs("/sys/block") {
        let name = dev.file_name()?.to_string_lossy();
        if ["loop", "ram", "zram"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            || !dirs(dev.join("slaves")).is_empty()
        {
            continue;
        }
        let Some(stat) = text(dev.join("stat")) else {
            continue;
        };
        let fields: Vec<_> = stat.split_whitespace().collect();
        let value = |i: usize| fields.get(i).and_then(|v| v.parse::<u64>().ok());
        if let (Some(read), Some(written)) = (value(2), value(6)) {
            total.0 = total.0.saturating_add(read.saturating_mul(512));
            total.1 = total.1.saturating_add(written.saturating_mul(512));
            read_any = true;
        }
    }
    read_any.then_some(total)
}

pub fn compressed_memory() -> u64 {
    let zram: u64 = dirs("/sys/block")
        .into_iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("zram"))
        })
        .filter_map(|p| text(p.join("mm_stat")))
        .filter_map(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
        })
        .sum();
    zram.saturating_add(number("/sys/kernel/debug/zswap/pool_total_size").unwrap_or(0))
}

pub struct Sensors {
    energy: HashMap<PathBuf, (Instant, u64)>,
}

impl Sensors {
    pub fn new() -> Self {
        Self {
            energy: HashMap::new(),
        }
    }

    pub fn sample(&mut self) -> Power {
        let mut power = Power::default();
        for chip in dirs("/sys/class/hwmon") {
            let name = text(chip.join("name")).unwrap_or_default().to_lowercase();
            let gpu = ["amdgpu", "nouveau", "nvidia", "i915", "xe"]
                .iter()
                .any(|s| name.contains(s));
            let cpu = [
                "coretemp",
                "k10temp",
                "zenpower",
                "cpu_thermal",
                "cpu-thermal",
            ]
            .iter()
            .any(|s| name.contains(s));
            for file in dirs(&chip) {
                let Some(filename) = file.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                if filename.starts_with("temp") && filename.ends_with("_input") {
                    let Some(raw) = number(&file).filter(|v| *v <= 200_000) else {
                        continue;
                    };
                    let label = text(chip.join(filename.replace("_input", "_label")))
                        .unwrap_or_default()
                        .to_lowercase();
                    let slot = if gpu {
                        &mut power.gpu_temp
                    } else if cpu || label.contains("cpu") || label.contains("package") {
                        &mut power.cpu_temp
                    } else {
                        continue;
                    };
                    let value = raw as f32 / 1000.0;
                    *slot = Some(slot.unwrap_or(value).max(value));
                } else if filename.starts_with("fan") && filename.ends_with("_input") {
                    if let Some(rpm) = number(&file).and_then(|v| u32::try_from(v).ok()) {
                        power.fan_rpm = Some(power.fan_rpm.unwrap_or(0).max(rpm));
                    }
                } else if gpu && filename == "power1_average" {
                    power.gpu_power = number(&file).map(|v| v as f32 / 1_000_000.0);
                }
            }
        }
        if power.cpu_temp.is_none() {
            for zone in dirs("/sys/class/thermal") {
                let kind = text(zone.join("type")).unwrap_or_default().to_lowercase();
                if kind.contains("cpu") || kind.contains("x86_pkg") {
                    if let Some(raw) = number(zone.join("temp")).filter(|v| *v <= 200_000) {
                        power.cpu_temp =
                            Some(power.cpu_temp.unwrap_or(0.0).max(raw as f32 / 1000.0));
                    }
                }
            }
        }
        let busy: Vec<f32> = dirs("/sys/class/drm")
            .into_iter()
            .filter_map(|p| number(p.join("device/gpu_busy_percent")))
            .filter(|v| *v <= 100)
            .map(|v| v as f32)
            .collect();
        power.gpu = busy.into_iter().reduce(f32::max);
        power.gpu_active = power.gpu;
        // Top-level RAPL packages only: subdomains such as cores/DRAM overlap the package.
        let now = Instant::now();
        for domain in dirs("/sys/class/powercap") {
            if !text(domain.join("name")).is_some_and(|n| n.starts_with("package-")) {
                continue;
            }
            let Some(energy) = number(domain.join("energy_uj")) else {
                continue;
            };
            if let Some((before, previous)) = self.energy.insert(domain.clone(), (now, energy)) {
                let delta = if energy >= previous {
                    Some(energy - previous)
                } else {
                    number(domain.join("max_energy_range_uj"))
                        .map(|max| max.saturating_sub(previous).saturating_add(energy))
                };
                if let Some(delta) = delta {
                    let watts = delta as f32
                        / 1_000_000.0
                        / now.duration_since(before).as_secs_f32().max(0.001);
                    power.cpu_power = Some(power.cpu_power.unwrap_or(0.0) + watts);
                }
            }
        }
        power
    }
}

#[derive(Clone)]
pub struct Socket {
    pub inode: u64,
    pub proto: &'static str,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: String,
}

fn endpoint(encoded: &str, ipv6: bool) -> Option<SocketAddr> {
    let (address, port) = encoded.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(
                &u32::from_str_radix(&address[i * 8..i * 8 + 8], 16)
                    .ok()?
                    .to_ne_bytes(),
            );
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(address, 16).ok()?.to_ne_bytes(),
        ))
    };
    Some(SocketAddr::new(ip, port))
}

pub fn sockets() -> std::io::Result<HashMap<u64, Socket>> {
    let mut sockets = HashMap::new();
    let mut read_any = false;
    for (file, proto, ipv6) in [
        ("tcp", "tcp", false),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", true),
    ] {
        let Ok(content) = std::fs::read_to_string(format!("/proc/net/{file}")) else {
            continue;
        };
        read_any = true;
        for line in content.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (Some(local), Some(remote), Ok(inode)) = (
                endpoint(fields[1], ipv6),
                endpoint(fields[2], ipv6),
                fields[9].parse::<u64>(),
            ) else {
                continue;
            };
            if inode == 0 {
                continue;
            }
            let state = if proto == "udp" {
                if fields[3] == "01" {
                    "ESTABLISHED"
                } else {
                    "UNCONN"
                }
            } else {
                match fields[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "04" => "FIN_WAIT1",
                    "05" => "FIN_WAIT2",
                    "06" => "TIME_WAIT",
                    "07" => "CLOSE",
                    "08" => "CLOSE_WAIT",
                    "09" => "LAST_ACK",
                    "0A" => "LISTEN",
                    "0B" => "CLOSING",
                    _ => "UNKNOWN",
                }
            }
            .to_owned();
            sockets.insert(
                inode,
                Socket {
                    inode,
                    proto,
                    local,
                    remote,
                    state,
                },
            );
        }
    }
    if read_any {
        Ok(sockets)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cannot read Linux network sockets in /proc/net",
        ))
    }
}

pub fn pids() -> Vec<u32> {
    dirs("/proc")
        .iter()
        .filter_map(|p| p.file_name()?.to_str()?.parse().ok())
        .collect()
}

pub fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Read descriptors directly; minimal servers do not need lsof installed for monitors/traces.
pub fn open_files(pids: &[u32]) -> HashMap<u32, Vec<OpenFile>> {
    let sockets = sockets().unwrap_or_default();
    let unix: HashMap<u64, String> = std::fs::read_to_string("/proc/net/unix")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let inode = fields.get(6)?.parse().ok()?;
            Some((inode, fields.get(7).copied().unwrap_or("").to_owned()))
        })
        .collect();
    let mut result = HashMap::new();
    for pid in pids {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let Ok(fds) = std::fs::read_dir(base.join("fd")) else {
            continue;
        };
        let mut files = Vec::new();
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let name = target.to_string_lossy().into_owned();
            let descriptor = fd.file_name().to_string_lossy().into_owned();
            let info = text(base.join("fdinfo").join(&descriptor)).unwrap_or_default();
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok());
            let mode = match flags.map(|v| v & 3) {
                Some(0) => "r",
                Some(1) => "w",
                Some(2) => "rw",
                _ => "",
            }
            .to_owned();
            let mut file = OpenFile {
                fd: descriptor,
                name: name.clone(),
                mode,
                ..Default::default()
            };
            if let Some(socket) = socket_inode(&name).and_then(|inode| sockets.get(&inode)) {
                file.kind = socket.proto.into();
                file.name = format!("{}->{}", socket.local, socket.remote);
                file.state = socket.state.clone();
            } else if let Some(path) = socket_inode(&name).and_then(|inode| unix.get(&inode)) {
                file.kind = "unix".into();
                if !path.is_empty() {
                    file.name = path.clone();
                }
            } else if name.starts_with("socket:[") {
                file.kind = "other".into();
            } else if name.starts_with("pipe:[") {
                file.kind = "pipe".into();
            } else if name.starts_with("/dev/") {
                file.kind = "device".into();
            } else if fd.path().is_dir() {
                file.kind = "dir".into();
            } else if name.starts_with('/') {
                file.kind = "file".into();
            } else {
                file.kind = "other".into();
            }
            files.push(file);
        }
        result.insert(*pid, files);
    }
    result
}

pub fn socket_owners() -> HashMap<u64, Vec<(u32, String)>> {
    let mut owners: HashMap<u64, Vec<(u32, String)>> = HashMap::new();
    for pid in pids() {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let name = text(base.join("comm")).unwrap_or_default();
        for fd in dirs(base.join("fd")) {
            let Ok(target) = std::fs::read_link(fd) else {
                continue;
            };
            if let Some(inode) = socket_inode(&target.to_string_lossy()) {
                let list = owners.entry(inode).or_default();
                if !list.iter().any(|(other, _)| *other == pid) {
                    list.push((pid, name.clone()));
                }
            }
        }
    }
    owners
}

pub fn root_capacity() -> Option<(u64, u64)> {
    // SAFETY: statvfs fills a valid output struct for the static, NUL-terminated root path.
    unsafe {
        let mut stats: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c"/".as_ptr(), &mut stats) != 0 {
            return None;
        }
        let block = stats.f_frsize as u64;
        Some((
            (stats.f_blocks as u64).saturating_mul(block),
            (stats.f_bavail as u64).saturating_mul(block),
        ))
    }
}
