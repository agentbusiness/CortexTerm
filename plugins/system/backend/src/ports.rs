//! Listening TCP ports per process: macOS asks each process's socket descriptors through libproc
//! (microseconds per process, no `lsof`); Linux maps `/proc/net/tcp*` inodes to `/proc/<pid>/fd`.
//! Only processes this user may inspect are seen.

use cc_protocol::contracts::system::Port;
use std::collections::HashSet;

fn is_public(address: &str) -> bool {
    address == "0.0.0.0" || address == "::" || address == "*"
}

fn finish(mut ports: Vec<Port>) -> Vec<Port> {
    let mut seen = HashSet::new();
    ports.retain(|p| seen.insert((p.pid, p.port, p.address.clone())));
    for port in &mut ports {
        port.public = is_public(&port.address);
    }
    ports.sort_by(|a, b| a.port.cmp(&b.port).then(a.pid.cmp(&b.pid)));
    ports
}

#[cfg(target_os = "macos")]
pub fn scan() -> Vec<Port> {
    use libproc::libproc::bsd_info::BSDInfo;
    use libproc::libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
    use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind, TcpSIState};
    use libproc::libproc::proc_pid::{listpidinfo, pidinfo};
    use libproc::processes::{ProcFilter, pids_by_type};
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut ports = Vec::new();
    for pid in pids_by_type(ProcFilter::All).unwrap_or_default() {
        let pid = pid as i32;
        let Ok(info) = pidinfo::<BSDInfo>(pid, 0) else { continue };
        let Ok(fds) = listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize) else { continue };
        let mut name: Option<String> = None;
        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) else { continue };
            if !matches!(SocketInfoKind::from(socket.psi.soi_kind), SocketInfoKind::Tcp) {
                continue;
            }
            // SAFETY: soi_kind says the union holds TCP socket info.
            let tcp = unsafe { socket.psi.soi_proto.pri_tcp };
            if !matches!(TcpSIState::from(tcp.tcpsi_state), TcpSIState::Listen) {
                continue;
            }
            let ini = tcp.tcpsi_ini;
            let port = u16::from_be(ini.insi_lport as u16);
            // INI_IPV4 = 1, INI_IPV6 = 2.
            // SAFETY: the vflag says which member of the address union is set.
            let address = if ini.insi_vflag & 0x1 != 0 {
                Ipv4Addr::from(u32::from_be(unsafe { ini.insi_laddr.ina_46.i46a_addr4.s_addr })).to_string()
            } else {
                Ipv6Addr::from(unsafe { ini.insi_laddr.ina_6.s6_addr }).to_string()
            };
            let process = name.get_or_insert_with(|| libproc::libproc::proc_pid::name(pid).unwrap_or_default()).clone();
            ports.push(Port { port, address, pid: pid as u32, process, public: false });
        }
    }
    finish(ports)
}

#[cfg(not(target_os = "macos"))]
pub fn scan() -> Vec<Port> {
    use std::collections::HashMap;
    // inode -> (address, port) of listening sockets (state 0A).
    let mut listening: HashMap<u64, (String, u16)> = HashMap::new();
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" {
                continue;
            }
            let Some((addr, port)) = fields[1].split_once(':') else { continue };
            let Ok(port) = u16::from_str_radix(port, 16) else { continue };
            let address = if v6 {
                // Four 32-bit words, each in host byte order.
                let mut bytes = [0u8; 16];
                for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                    let word = addr.get(i * 8..i * 8 + 8).and_then(|w| u32::from_str_radix(w, 16).ok()).unwrap_or(0);
                    chunk.copy_from_slice(&word.to_ne_bytes());
                }
                std::net::Ipv6Addr::from(bytes).to_string()
            } else {
                u32::from_str_radix(addr, 16).map(|raw| std::net::Ipv4Addr::from(u32::from_be(raw)).to_string()).unwrap_or_default()
            };
            if let Ok(inode) = fields[9].parse() {
                listening.insert(inode, (address, port));
            }
        }
    }
    let mut ports = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else { continue };
        let process = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default().trim().to_owned();
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let target = target.to_string_lossy();
            let Some(inode) = target.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')).and_then(|s| s.parse::<u64>().ok()) else {
                continue;
            };
            if let Some((address, port)) = listening.get(&inode) {
                ports.push(Port { port: *port, address: address.clone(), pid, process: process.clone(), public: false });
            }
        }
    }
    finish(ports)
}
