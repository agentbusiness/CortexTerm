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

#[cfg(target_os = "linux")]
pub fn scan() -> Vec<Port> {
    let mut owners = crate::linux::socket_owners();
    let mut ports = Vec::new();
    for socket in crate::linux::sockets().unwrap_or_default().into_values().filter(|s| s.proto == "tcp" && s.state == "LISTEN") {
        // Keep a visible listener even when procfs permissions hide its owner's descriptors.
        let processes = owners.remove(&socket.inode).unwrap_or_else(|| vec![(0, "owner unavailable".into())]);
        for (pid, process) in processes {
            ports.push(Port { port: socket.local.port(), address: socket.local.ip().to_string(), pid, process, public: false });
        }
    }
    finish(ports)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn scan() -> Vec<Port> { Vec::new() }
