//! The sweep's network checks: this Mac's network and what the internet sees of it. All as this
//! user, nothing changed, each step time-limited.
//!
//! - the network now: the router's hardware address, the DHCP server, DNS servers and IPv6
//!   routers, remembered per network (its Wi-Fi name when macOS shows it, else the subnet); a
//!   change on a known network is reported (the watcher compares every minute);
//! - Wi-Fi security, a captive portal, a public IPv6 address;
//! - devices on the network (ARP, Bonjour, UPnP/SSDP), named by vendor, remembered per network;
//! - port forwards the router opened by UPnP;
//! - the public IP as Shodan InternetDB and GreyNoise see it;
//! - which DNS resolver queries really reach, and whether DNS or IPv6 bypass a VPN;
//! - the network digest the watcher keeps.
//!
//! What is remembered lives in the graph: `(:Machine)-[:JOINED]->(:Lan {key, ssid, interface,
//! router, dns, router6, public6, router_mac*, dhcp_server*, security*})`, the devices seen on it
//! as `(:Device {key: mac:… | name:…, ip, mac, name, vendor})-[:ON]->(:Lan)` (the edge's
//! `first_ms` / `last_ms` say when), and GreyNoise's daily answer as
//! `(:MacSetting {key: greynoise, value*, checked_ms})-[:OF]->(:Machine)`. It is loaded once at
//! start and kept in RAM.

use crate::feeds;
use crate::graph::{self, Batch, Props, r};
use crate::netwatch;
use crate::sweep::Part;
use crate::util::{now_ms, plural};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
#[cfg(target_os = "macos")]
use crate::util::run;
#[cfg(target_os = "macos")]
use std::io::Read;
#[cfg(target_os = "macos")]
use std::net::UdpSocket;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::time::Instant;

const DAY: u64 = 24 * 3_600_000;
#[cfg(target_os = "macos")]
const SHORT: Duration = Duration::from_secs(5);

/// This Mac's network as it is now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Net {
    /// The Wi-Fi name when macOS shows it, else `en0 192.168.1.0/24`.
    key: String,
    ssid: String,
    interface: String,
    router: String,
    router_mac: String,
    dhcp_server: String,
    dns: Vec<String>,
    router6: Vec<String>,
    /// `WPA2_PSK`, `NONE`, ...; empty when wired or unknown.
    security: String,
    public6: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Device {
    ip: String,
    mac: String,
    name: String,
    vendor: String,
    first: u64,
    last: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Known {
    net: Net,
    first: u64,
    /// Device key (`mac:..` or `name:..`) -> device.
    devices: BTreeMap<String, Device>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Lan {
    networks: BTreeMap<String, Known>,
    /// GreyNoise is asked once a day: when, and what it said.
    greynoise_at: u64,
    greynoise: Option<String>,
}

static LAN: Mutex<Option<Lan>> = Mutex::new(None);

fn lock_lan() -> std::sync::MutexGuard<'static, Option<Lan>> {
    LAN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The networks, devices and GreyNoise's answer, from the graph (at start).
pub async fn load() -> Result<usize, String> {
    let mut lan = Lan::default();
    let rows = graph::query_all(
        "MATCH (:Machine)-[j:JOINED]->(l:Lan) RETURN l.key, l.ssid, l.interface, l.router, l.router_mac, l.dhcp_server, l.dns, l.router6, l.security, l.public6, j.first_ms ORDER BY l.key",
        json!({}),
    )
    .await?;
    for row in rows {
        let net = Net {
            key: graph::text(&row[0]),
            ssid: graph::text(&row[1]),
            interface: graph::text(&row[2]),
            router: graph::text(&row[3]),
            router_mac: graph::text(&row[4]),
            dhcp_server: graph::text(&row[5]),
            dns: graph::texts(&row[6]),
            router6: graph::texts(&row[7]),
            security: graph::text(&row[8]),
            public6: graph::texts(&row[9]),
        };
        lan.networks.insert(net.key.clone(), Known { net, first: graph::number(&row[10]), devices: BTreeMap::new() });
    }
    let since = now_ms().saturating_sub(90 * DAY);
    let rows = graph::query_all(
        "MATCH (d:Device)-[o:ON]->(l:Lan) WHERE o.last_ms >= $since RETURN l.key, d.key, d.ip, d.mac, d.name, d.vendor, o.first_ms, o.last_ms ORDER BY l.key, d.key",
        json!({"since": since}),
    )
    .await?;
    for row in rows {
        let Some(known) = lan.networks.get_mut(&graph::text(&row[0])) else { continue };
        known.devices.insert(
            graph::text(&row[1]),
            Device { ip: graph::text(&row[2]), mac: graph::text(&row[3]), name: graph::text(&row[4]), vendor: graph::text(&row[5]), first: graph::number(&row[6]), last: graph::number(&row[7]) },
        );
    }
    let rows = graph::query("MATCH (s:MacSetting {key: 'greynoise'}) RETURN s.value, s.checked_ms", json!({})).await?;
    if let Some(row) = rows.first() {
        lan.greynoise_at = graph::number(&row[1]);
        lan.greynoise = Some(graph::text(&row[0])).filter(|v| !v.is_empty() && v != "quiet");
    }
    let count = lan.networks.len();
    *lock_lan() = Some(lan);
    Ok(count)
}

/// A network's node as remembered now, joined by this Mac.
fn write_net(net: &Net) {
    let Some(machine) = graph::machine() else { return };
    let mut batch = Batch::new();
    batch.units.push(net_unit(net, &machine));
    graph::put(batch);
}

fn net_unit(net: &Net, machine: &cc_protocol::contracts::memory::GraphRef) -> graph::Unit {
    let mut unit = graph::Unit::default();
    unit.node("Lan", net.key.clone())
        .p("ssid", net.ssid.clone())
        .p("interface", net.interface.clone())
        .p("router", net.router.clone())
        .pl("dns", net.dns.clone())
        .pl("router6", net.router6.clone())
        .pl("public6", net.public6.clone())
        .t("router_mac", net.router_mac.clone())
        .t("dhcp_server", net.dhcp_server.clone())
        .t("security", net.security.clone());
    unit.edge(machine.clone(), "JOINED", r("Lan", net.key.clone()));
    unit
}

/// The devices seen on a network now, for the sweep's batch.
fn devices_batch(net: &Net, devices: &[(&String, &Device)]) -> Batch {
    let mut batch = Batch::new();
    let Some(machine) = graph::machine() else { return batch };
    batch.units.push(net_unit(net, &machine));
    for (key, device) in devices {
        let unit = batch.unit();
        unit.node("Device", (*key).clone()).p("ip", device.ip.clone()).p("mac", device.mac.clone()).ps("name", &device.name).ps("vendor", &device.vendor);
        unit.edge(r("Device", (*key).clone()), "ON", r("Lan", net.key.clone()));
    }
    batch
}

/// GreyNoise's last answer, for the sweep's batch.
fn greynoise_batch(at: u64, class: Option<&str>) -> Batch {
    let mut batch = Batch::new();
    let Some(machine) = graph::machine() else { return batch };
    let unit = batch.unit();
    unit.node("MacSetting", "greynoise").t("value", class.unwrap_or("quiet")).p("checked_ms", at);
    unit.edge(r("MacSetting", "greynoise"), "OF", machine);
    batch
}

/// One change on a known network.
pub struct Change {
    pub severity: String,
    pub text: String,
    /// Worth an interruption (the gateway or the Wi-Fi's security changed).
    pub alert: bool,
}

#[cfg(target_os = "macos")]
fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.trim().strip_prefix(name)).map(|rest| rest.trim_start_matches([' ', ':', '=']).trim())
}

/// `{a, b}` -> [a, b].
#[cfg(target_os = "macos")]
fn list(text: &str) -> Vec<String> {
    text.trim_matches(['{', '}']).split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
}

#[cfg(target_os = "macos")]
fn mac(text: &str) -> Option<String> {
    let parts: Vec<u8> = text.split(':').filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
    (parts.len() == 6).then(|| parts.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

#[cfg(target_os = "macos")]
fn out(program: &str, args: &[&str]) -> String {
    run(program, args, SHORT).map(|o| o.stdout).unwrap_or_default()
}

/// Read the network now; `None` without a default route on a real interface.
#[cfg(target_os = "macos")]
fn current() -> Option<Net> {
    let routes = out("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
    let (router, interface) = routes.lines().find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        (cols.len() >= 4 && cols[0] == "default" && !["utun", "ipsec", "ppp", "lo"].iter().any(|p| cols[3].starts_with(p)))
            .then(|| (cols[1].to_owned(), cols[3].to_owned()))
    })?;
    let mut net = Net { router: router.clone(), interface: interface.clone(), ..Default::default() };
    let arp = out("/usr/sbin/arp", &["-n", &router]);
    net.router_mac = arp.split(" at ").nth(1).and_then(|rest| rest.split_whitespace().next()).and_then(mac).unwrap_or_default();
    let packet = out("/usr/sbin/ipconfig", &["getpacket", &interface]);
    net.dhcp_server = field(&packet, "server_identifier (ip)").unwrap_or("").to_owned();
    net.dns = field(&packet, "domain_name_server (ip_mult)").map(list).unwrap_or_default();
    let summary = out("/usr/sbin/ipconfig", &["getsummary", &interface]);
    net.ssid = field(&summary, "SSID").filter(|s| !s.contains("redacted")).unwrap_or("").to_owned();
    net.security = field(&summary, "Security").unwrap_or("").to_owned();
    let ndp = out("/usr/sbin/ndp", &["-rn"]);
    net.router6 = ndp
        .lines()
        .filter(|line| line.contains(&format!("if={interface}")))
        .filter_map(|line| line.split_whitespace().next().map(|a| a.split('%').next().unwrap_or(a).to_owned()))
        .collect();
    let ifconfig = out("/sbin/ifconfig", &[&interface]);
    net.public6 = ifconfig
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet6 ").and_then(|rest| rest.split_whitespace().next()))
        .filter(|a| a.parse::<IpAddr>().is_ok_and(netwatch::public))
        .map(str::to_owned)
        .collect();
    let subnet = match (field(&packet, "yiaddr").and_then(|a| a.parse::<Ipv4Addr>().ok()), field(&packet, "subnet_mask (ip)").and_then(|m| m.parse::<Ipv4Addr>().ok())) {
        (Some(ip), Some(mask)) => {
            let bits = u32::from(mask).count_ones();
            format!("{}/{bits}", Ipv4Addr::from(u32::from(ip) & u32::from(mask)))
        }
        _ => format!("via {router}"),
    };
    net.key = if net.ssid.is_empty() { format!("{interface} {subnet}") } else { format!("Wi-Fi {}", net.ssid) };
    Some(net)
}

#[cfg(target_os = "linux")]
fn current() -> Option<Net> {
    // procfs works on minimal servers without the macOS network tools or iproute2.
    let routes = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let route = routes.lines().skip(1).filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[1] != "00000000" { return None; }
        let flags = u32::from_str_radix(fields[3], 16).ok()?;
        if flags & 1 == 0 { return None; }
        let router = Ipv4Addr::from(u32::from_str_radix(fields[2], 16).ok()?.to_ne_bytes()).to_string();
        Some((fields[6].parse::<u64>().unwrap_or(u64::MAX), fields[0].to_owned(), router))
    }).min_by_key(|route| route.0);
    let (interface, router) = if let Some((_, interface, router)) = route { (interface, router) } else {
        let routes = std::fs::read_to_string("/proc/net/ipv6_route").ok()?;
        let route = routes.lines().filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[4].len() != 32 || fields[0] != "00000000000000000000000000000000" || fields[1] != "00" || fields[9] == "lo" { return None; }
            Some((u32::from_str_radix(fields[5], 16).unwrap_or(u32::MAX), fields[9].to_owned(), fields[4].to_owned()))
        }).min_by_key(|route| route.0)?;
        let address = (0..8).map(|i| &route.2[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(":");
        (route.1, address.parse::<std::net::Ipv6Addr>().ok()?.to_string())
    };
    let dns = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default().lines().filter_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "nameserver").then(|| fields.next().unwrap_or("").to_owned())
    }).filter(|s| !s.is_empty()).collect();
    let router_mac = std::fs::read_to_string("/proc/net/arp").unwrap_or_default().lines().skip(1).find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.len() >= 6 && fields[0] == router && fields[5] == interface).then(|| fields[3].to_owned())
    }).unwrap_or_default();
    let public6 = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default().lines().filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[5] != interface || fields[0].len() != 32 { return None; }
        let address = (0..8).map(|i| &fields[0][i * 4..i * 4 + 4]).collect::<Vec<_>>().join(":");
        let ip = address.parse::<IpAddr>().ok()?;
        netwatch::public(ip).then(|| ip.to_string())
    }).collect();
    Some(Net { key: format!("{interface} via {router}"), interface, router, router_mac, dns, public6, ..Default::default() })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current() -> Option<Net> { None }

fn open_wifi(security: &str) -> bool {
    let s = security.to_ascii_uppercase();
    s.contains("NONE") || s.contains("OPEN") || s.contains("WEP")
}

fn name_of(net: &Net) -> String {
    if net.ssid.is_empty() { format!("this network ({})", net.key) } else { format!("the Wi-Fi network {}", net.ssid) }
}

/// Compare the network now with what was remembered for it, and remember it. Blocking.
pub fn network_changes() -> Vec<Change> {
    let Some(net) = current() else { return Vec::new() };
    let mut slot = lock_lan();
    // Nothing is compared before what is remembered is loaded.
    let Some(lan) = slot.as_mut() else { return Vec::new() };
    let mut changes = Vec::new();
    let mut change = |severity: &str, alert: bool, text: String| changes.push(Change { severity: severity.into(), text, alert });
    match lan.networks.get_mut(&net.key) {
        None => {
            change("info", false, format!("This Mac joined a network it had not used before: {}.", name_of(&net)));
            lan.networks.insert(net.key.clone(), Known { net: net.clone(), first: now_ms(), devices: BTreeMap::new() });
            write_net(&net);
        }
        Some(known) => {
            let old = &known.net;
            let name = name_of(&net);
            let gateway_moved = !old.router_mac.is_empty() && !net.router_mac.is_empty() && old.router_mac != net.router_mac;
            let dhcp_moved = !old.dhcp_server.is_empty() && !net.dhcp_server.is_empty() && old.dhcp_server != net.dhcp_server;
            let opened = !old.security.is_empty() && !open_wifi(&old.security) && open_wifi(&net.security);
            let security_moved = !old.security.is_empty() && !net.security.is_empty() && old.security != net.security;
            if opened || (gateway_moved && dhcp_moved && security_moved) {
                change(
                    "high",
                    true,
                    format!(
                        "On {name} the Wi-Fi security changed from {} to {}{}. This may be a fake copy of the network (an evil twin); disconnect unless you changed it.",
                        old.security,
                        net.security,
                        if gateway_moved { " and the router is a different device" } else { "" }
                    ),
                );
            } else if gateway_moved {
                change(
                    "high",
                    true,
                    format!(
                        "The router on {name} ({}) now answers from a different hardware address ({} instead of {}). Unless the router was replaced, another device may be intercepting this network's traffic (ARP spoofing).",
                        net.router, net.router_mac, old.router_mac
                    ),
                );
            }
            if dhcp_moved {
                change("medium", false, format!("On {name} addresses now come from a different DHCP server ({} instead of {}); a rogue DHCP server can redirect traffic.", net.dhcp_server, old.dhcp_server));
            }
            if !old.dns.is_empty() && !net.dns.is_empty() && old.dns != net.dns {
                change("medium", false, format!("On {name} the DNS servers handed out changed to {} (they were {}).", net.dns.join(", "), old.dns.join(", ")));
            }
            let (old6, new6): (BTreeSet<&String>, BTreeSet<&String>) = (old.router6.iter().collect(), net.router6.iter().collect());
            if !old6.is_empty() && !new6.is_empty() && old6 != new6 {
                let added: Vec<&str> = new6.difference(&old6).map(|s| s.as_str()).collect();
                if !added.is_empty() {
                    change("medium", false, format!("On {name} a new IPv6 router announced itself ({}); a rogue one can take over IPv6 traffic.", added.join(", ")));
                }
            }
            // Keep what was known when the new reading lacks it (an expired ARP entry).
            let mut merged = net.clone();
            if merged.router_mac.is_empty() {
                merged.router_mac = old.router_mac.clone();
            }
            if merged.security.is_empty() {
                merged.security = old.security.clone();
            }
            // Written each minute: the JOINED edge's last_ms says when this Mac was last on it.
            write_net(&merged);
            known.net = merged;
        }
    }
    changes
}

/// Run a program for a fixed window (it does not end by itself) and return what it printed.
#[cfg(target_os = "macos")]
fn run_for(program: &str, args: &[&str], window: Duration) -> Option<String> {
    let mut child = Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    std::thread::sleep(window);
    let _ = child.kill();
    let _ = child.wait();
    reader.join().ok()
}

/// One SSDP answer.
struct Ssdp {
    ip: String,
    location: String,
    server: String,
    #[cfg(target_os = "macos")]
    st: String,
}

/// UPnP discovery: M-SEARCH for every device and for internet gateways, 3 s of answers.
#[cfg(target_os = "macos")]
fn ssdp() -> Result<Vec<Ssdp>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(Duration::from_millis(300))).map_err(|e| e.to_string())?;
    for st in ["ssdp:all", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"] {
        let msg = format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n");
        socket.send_to(msg.as_bytes(), "239.255.255.250:1900").map_err(|e| e.to_string())?;
    }
    let started = Instant::now();
    let mut found: Vec<Ssdp> = Vec::new();
    let mut buf = [0u8; 2048];
    while started.elapsed() < Duration::from_secs(3) {
        let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
        let text = String::from_utf8_lossy(&buf[..n]);
        let header = |name: &str| {
            text.lines()
                .find_map(|line| line.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()))
                .unwrap_or_default()
        };
        let answer = Ssdp { ip: from.ip().to_string(), location: header("location"), server: header("server"), st: header("st") };
        if !found.iter().any(|f| f.ip == answer.ip && f.location == answer.location && f.st == answer.st) {
            found.push(answer);
        }
    }
    Ok(found)
}

/// `<tag>value</tag>`, the first one.
fn tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].trim().to_owned())
}

/// What the blocking part found, for the async part.
struct Local {
    part: Part,
    net: Option<Net>,
    answers: Vec<Ssdp>,
    /// ip -> mac from ARP.
    arp: Vec<(String, String)>,
    vpn: bool,
    resolver: Option<IpAddr>,
    /// IPv6 traffic leaves through this interface.
    v6_interface: String,
}

#[cfg(target_os = "linux")]
fn local_checks() -> Local { linux_local_checks() }

#[cfg(not(target_os = "linux"))]
fn local_checks() -> Local {
    let mut part = Part::default();
    // Changes since the last look (the watcher may have seen them first: they are in the digest).
    for change in network_changes() {
        netwatch::note("Network", "lan", &change.severity, change.text);
    }
    let net = current();
    let Some(net) = net else {
        part.skipped.push("network checks: this Mac has no network connection".into());
        return Local { part, net: None, answers: Vec::new(), arp: Vec::new(), vpn: false, resolver: None, v6_interface: String::new() };
    };
    part.checked.push("router, DHCP, DNS and IPv6 router changes".into());
    // The network as remembered goes with the sweep, so its findings can point at it.
    if let (Some(machine), Some(known)) = (graph::machine(), lock_lan().as_ref().and_then(|lan| lan.networks.get(&net.key)).map(|k| k.net.clone())) {
        part.graph.units.push(net_unit(&known, &machine));
    }
    if !net.public6.is_empty() {
        part.add(
            "info",
            "lan",
            format!("This Mac has a public IPv6 address ({}), so it can be reached from the internet unless the router's firewall blocks it; NAT does not protect IPv6.", net.public6[0]),
            None,
            "network",
        );
        part.about("Lan", net.key.clone());
    }

    // Wi-Fi.
    if net.security.is_empty() {
        part.skipped.push("Wi-Fi security: not on Wi-Fi, or macOS did not say".into());
    } else {
        part.checked.push("Wi-Fi security".into());
        let s = net.security.to_ascii_uppercase();
        if s.contains("WEP") {
            part.add("medium", "lan", format!("{} uses WEP, which is broken: anyone nearby can read its traffic.", capital(&name_of(&net))), None, "Wi-Fi");
            part.about("Lan", net.key.clone());
        } else if open_wifi(&s) {
            part.add("medium", "lan", format!("{} is open (no password): anyone nearby can see unencrypted traffic. Use a VPN or iCloud Private Relay here.", capital(&name_of(&net))), None, "Wi-Fi");
            part.about("Lan", net.key.clone());
        } else if s.starts_with("WPA_") || s == "WPA" {
            part.add("low", "lan", format!("{} uses the original WPA, which is weak; WPA2 or WPA3 is safer.", capital(&name_of(&net))), None, "Wi-Fi");
            part.about("Lan", net.key.clone());
        }
    }
    if net.ssid.is_empty() && !net.security.is_empty() {
        part.skipped.push("Wi-Fi name: macOS hides it without Location Services permission, so networks are told apart by subnet".into());
    }

    // Devices: ARP, Bonjour and SSDP (the last two at once, 3 s each).
    let bonjour = std::thread::spawn(|| run_for("/usr/bin/dns-sd", &["-B", "_services._dns-sd._udp", "local."], Duration::from_secs(3)));
    let answers = match ssdp() {
        Ok(answers) => {
            part.checked.push("UPnP devices (SSDP)".into());
            answers
        }
        Err(error) => {
            part.skipped.push(format!("UPnP devices and port forwards: cannot reach the local network ({error}); CortexTerm may need the Local Network permission in System Settings > Privacy & Security"));
            Vec::new()
        }
    };
    let services = bonjour.join().ok().flatten().map(|text| text.lines().filter(|l| l.contains(" Add ")).count());
    match services {
        Some(n) if n > 0 => part.checked.push(format!("Bonjour ({})", plural(n, "service type", "service types"))),
        _ => part.skipped.push("Bonjour: no answers in 3 s (no devices announce services, or Local Network access is blocked)".into()),
    }
    let arp_text = out("/usr/sbin/arp", &["-an", "-i", &net.interface]);
    let arp: Vec<(String, String)> = arp_text
        .lines()
        .filter(|line| !line.contains("permanent") && !line.contains("incomplete"))
        .filter_map(|line| {
            let ip = line.split('(').nth(1)?.split(')').next()?.to_owned();
            let mac = mac(line.split(" at ").nth(1)?.split_whitespace().next()?)?;
            let addr: Ipv4Addr = ip.parse().ok()?;
            (!addr.is_multicast() && !addr.is_broadcast() && !ip.ends_with(".255")).then_some((ip, mac))
        })
        .collect();
    part.checked.push("devices on the network (ARP)".into());

    // Packet capture tier: only with a readable /dev/bpf0.
    if std::fs::File::open("/dev/bpf0").is_ok() {
        dns_capture(&mut part, &net.interface);
    } else {
        part.skipped.push("DNS watch (packet capture): /dev/bpf0 is not readable by this user; installing Wireshark (with its ChmodBPF helper) enables it".into());
    }

    // VPN and the resolver the internet sees.
    let nwi = out("/usr/sbin/scutil", &["--nwi"]);
    let ipv4_section = nwi.split("IPv6 network interface information").next().unwrap_or("");
    let vpn = ipv4_section.lines().any(|l| l.trim_start().starts_with("utun") || l.trim_start().starts_with("ipsec") || l.trim_start().starts_with("ppp"));
    let resolver = run("/usr/bin/dig", &["+short", "+time=3", "+tries=1", "whoami.akamai.net"], SHORT)
        .ok()
        .and_then(|o| o.stdout.lines().find_map(|l| l.trim().parse::<IpAddr>().ok()));
    let v6 = out("/sbin/route", &["-n", "get", "-inet6", "default"]);
    let v6_interface = field(&v6, "interface").unwrap_or("").to_owned();
    Local { part, net: Some(net), answers, arp, vpn, resolver, v6_interface }
}

#[cfg(target_os = "linux")]
fn linux_local_checks() -> Local {
    let mut part = Part::default();
    for change in network_changes() { netwatch::note("Network", "lan", &change.severity, change.text); }
    let net = current();
    if net.is_some() { part.checked.push("Linux default route, router neighbour, resolver and public IPv6 addresses".into()); }
    else { part.skipped.push("Linux network: no readable default route".into()); }
    part.skipped.push("Wi-Fi security, DHCP-server identity and per-connection transfer volumes are unavailable from the Linux procfs collector".into());
    let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default().lines().skip(1).filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.len() >= 4 && fields[3] != "00:00:00:00:00:00").then(|| (fields[0].to_owned(), fields[3].to_owned()))
    }).collect();
    let vpn = net.as_ref().is_some_and(|net| ["tun", "tap", "wg", "ppp"].iter().any(|prefix| net.interface.starts_with(prefix)));
    let v6_interface = net.as_ref().map(|net| net.interface.clone()).unwrap_or_default();
    Local { part, net, answers: Vec::new(), arp, vpn, resolver: None, v6_interface }
}

#[cfg(target_os = "macos")]
fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default()
}

/// 5 s of DNS queries; names that look machine-generated (long, random-looking labels).
#[cfg(target_os = "macos")]
fn dns_capture(part: &mut Part, interface: &str) {
    let Some(text) = run_for("/usr/sbin/tcpdump", &["-l", "-n", "-i", interface, "udp", "port", "53"], Duration::from_secs(5)) else {
        part.skipped.push("DNS watch: tcpdump did not start".into());
        return;
    };
    part.checked.push("DNS queries (5 s capture)".into());
    let mut odd = BTreeSet::new();
    for line in text.lines() {
        let Some(name) = line.split(" A? ").nth(1).or_else(|| line.split(" AAAA? ").nth(1)).and_then(|r| r.split_whitespace().next()) else { continue };
        let name = name.trim_end_matches('.');
        let label = name.split('.').next().unwrap_or("");
        if generated(label) {
            odd.insert(name.to_owned());
        }
    }
    if !odd.is_empty() {
        let names: Vec<String> = odd.into_iter().take(5).collect();
        part.add("low", "network", format!("This Mac looked up names that look machine-generated, as some malware does: {}.", names.join(", ")), None, "DNS watch");
    }
}

/// Long, high-entropy labels with long consonant runs.
#[cfg(target_os = "macos")]
fn generated(label: &str) -> bool {
    if label.len() < 12 {
        return false;
    }
    let mut counts = [0usize; 256];
    for b in label.bytes() {
        counts[b as usize] += 1;
    }
    let n = label.len() as f64;
    let entropy: f64 = counts.iter().filter(|c| **c > 0).map(|c| -(*c as f64 / n) * (*c as f64 / n).log2()).sum();
    let mut run_len = 0;
    let mut longest = 0;
    for c in label.chars() {
        if c.is_ascii_alphabetic() && !"aeiou".contains(c.to_ascii_lowercase()) {
            run_len += 1;
            longest = longest.max(run_len);
        } else {
            run_len = 0;
        }
    }
    entropy > 3.6 && longest >= 5
}

/// The whole group, capped at 90 s.
pub async fn checks() -> Part {
    match tokio::time::timeout(Duration::from_secs(90), all()).await {
        Ok(part) => part,
        Err(_) => Part { skipped: vec!["network checks: did not finish within 90 s".into()], ..Default::default() },
    }
}

async fn all() -> Part {
    // Fresh lists when due; the cache is used when offline.
    let _ = tokio::time::timeout(Duration::from_secs(40), feeds::refresh()).await;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).user_agent("CortexTerm").build().ok();
    let (local, public) = tokio::join!(tokio::task::spawn_blocking(local_checks), public_ip(client.as_ref()));
    let Ok(local) = local else { return Part::default() };
    let tables = tokio::task::spawn_blocking(feeds::tables).await.ok();
    let mut part = Part::default();
    let Local { part: local_part, net, answers, arp, vpn, resolver, v6_interface } = local;
    part.merge(local_part);
    if let Some(client) = &client
        && let Some(net) = &net
    {
        devices_and_upnp(&mut part, client, net, &answers, &arp).await;
        captive(&mut part, client).await;
    }
    match (&public, &client) {
        (Ok(ip), Some(client)) => exposure(&mut part, client, *ip).await,
        (Err(error), _) => part.skipped.push(format!("internet exposure: {error}")),
        _ => {}
    }
    if let Some(tables) = &tables {
        leaks(&mut part, tables, public.as_ref().ok().copied(), resolver, vpn, &v6_interface, net.as_ref());
        if !tables.missing.is_empty() {
            part.skipped.push(format!("threat and owner lists not downloaded yet: {}", tables.missing.join(", ")));
        }
    }
    // The watcher's digest.
    let mut notes = netwatch::digest();
    notes.sort_by(|a, b| b.at.cmp(&a.at));
    notes.truncate(60);
    notes.sort_by(|a, b| a.app.cmp(&b.app).then(b.at.cmp(&a.at)));
    part.checked.push("network digest (the watcher's notes this week)".into());
    for note in notes {
        part.add(&note.severity, &note.kind, note.text, None, "network watcher");
    }
    part
}

async fn public_ip(client: Option<&reqwest::Client>) -> Result<IpAddr, String> {
    let client = client.ok_or("no HTTP client")?;
    let text = client.get("https://api.ipify.org").send().await.map_err(|e| format!("api.ipify.org: {e}"))?.text().await.map_err(|e| e.to_string())?;
    text.trim().parse().map_err(|_| "api.ipify.org gave no address".to_owned())
}

async fn devices_and_upnp(part: &mut Part, client: &reqwest::Client, net: &Net, answers: &[Ssdp], arp: &[(String, String)]) {
    // Each answering device's description: its name, and the gateway's port-mapping service.
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut gateways: Vec<(String, String, String)> = Vec::new(); // (ip, control URL, service type)
    let locations: BTreeSet<(&str, &str)> = answers.iter().filter(|a| !a.location.is_empty()).map(|a| (a.ip.as_str(), a.location.as_str())).collect();
    for (ip, location) in locations.into_iter().take(20) {
        let Ok(Ok(xml)) = tokio::time::timeout(Duration::from_secs(4), async { client.get(location).send().await?.text().await }).await else { continue };
        if let Some(name) = tag(&xml, "friendlyName") {
            names.entry(ip.to_owned()).or_insert(name);
        }
        for service in ["urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANPPPConnection:1"] {
            let Some(at) = xml.find(&format!("<serviceType>{service}</serviceType>")) else { continue };
            let Some(control) = tag(&xml[at..], "controlURL") else { continue };
            let base = tag(&xml, "URLBase").unwrap_or_else(|| {
                let after = location.split("//").nth(1).unwrap_or("");
                format!("http://{}", after.split('/').next().unwrap_or(""))
            });
            let url = if control.starts_with("http") { control } else { format!("{}/{}", base.trim_end_matches('/'), control.trim_start_matches('/')) };
            gateways.push((ip.to_owned(), url, service.to_owned()));
            break;
        }
    }
    for answer in answers {
        if !answer.server.is_empty() {
            names.entry(answer.ip.clone()).or_insert_with(|| crate::util::shorten(&answer.server, 60));
        }
    }

    // Remember the devices on this network.
    let vendors = tokio::task::spawn_blocking(feeds::vendors).await.unwrap_or_default();
    let by_ip: BTreeMap<String, String> = {
        let mut slot = lock_lan();
        let Some(lan) = slot.as_mut() else {
            part.skipped.push("devices on this network: memory is not reachable, so there is nothing to compare with".into());
            return;
        };
        let now = now_ms();
        let known = lan.networks.entry(net.key.clone()).or_insert_with(|| Known { net: net.clone(), first: now, devices: BTreeMap::new() });
        let baseline = known.devices.is_empty();
        let mut fresh = Vec::new();
        for (ip, mac_text) in arp {
            let bytes: Vec<u8> = mac_text.split(':').filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
            let private = bytes.first().is_some_and(|b| b & 0x02 != 0);
            let vendor = if private {
                "private address".to_owned()
            } else {
                bytes.get(..3).and_then(|p| vendors.get(&[p[0], p[1], p[2]])).cloned().unwrap_or_default()
            };
            let name = names.get(ip).cloned().unwrap_or_default();
            // A phone's private address is fixed per network, so the address is the key; a name, when
            // one is known for a private address, survives its rotation.
            let key = if private && !name.is_empty() { format!("name:{name}") } else { format!("mac:{mac_text}") };
            let device = known.devices.entry(key).or_insert_with(|| {
                fresh.push(ip.clone());
                Device { ip: ip.clone(), mac: mac_text.clone(), name: name.clone(), vendor: vendor.clone(), first: now, last: now }
            });
            device.ip = ip.clone();
            device.last = now;
            if !name.is_empty() {
                device.name = name;
            }
            if device.vendor.is_empty() {
                device.vendor = vendor;
            }
        }
        known.devices.retain(|_, d| now.saturating_sub(d.last) < 90 * DAY);
        let describe = |d: &Device| {
            let what: Vec<&str> = [d.name.as_str(), d.vendor.as_str()].into_iter().filter(|s| !s.is_empty()).collect();
            if what.is_empty() { format!("{} ({})", d.ip, d.mac) } else { format!("{} ({})", d.ip, what.join(", ")) }
        };
        if baseline {
            let list: Vec<String> = known.devices.values().take(12).map(describe).collect();
            part.add("info", "lan", format!("{} on {}: {}.", plural(known.devices.len(), "device seen", "devices seen"), name_of(net), list.join("; ")), None, "devices");
        } else {
            for device in known.devices.values().filter(|d| fresh.contains(&d.ip) && d.first == now) {
                part.add("low", "lan", format!("A new device joined {}: {}.", name_of(net), describe(device)), None, "devices");
                if let Some((key, _)) = known.devices.iter().find(|(_, d)| d.ip == device.ip && d.first == now) {
                    part.about("Device", key.clone());
                }
            }
        }
        let by_ip: BTreeMap<String, String> = known.devices.values().map(|d| (d.ip.clone(), describe(d))).collect();
        let seen: Vec<(&String, &Device)> = known.devices.iter().filter(|(_, d)| d.last == now).collect();
        part.graph.extend(devices_batch(&known.net, &seen));
    by_ip
    };

    // Port forwards the router opened by UPnP.
    if gateways.is_empty() {
        part.checked.push("UPnP port forwards (no router answered: UPnP looks off)".into());
        return;
    }
    part.checked.push("UPnP port forwards".into());
    for (ip, url, service) in gateways.into_iter().take(1) {
        part.add("low", "lan", format!("The router at {ip} has UPnP turned on, so any device on the network can open ports to the internet without asking."), None, "UPnP");
        for index in 0..64 {
            let body = format!(
                "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetGenericPortMappingEntry xmlns:u=\"{service}\"><NewPortMappingIndex>{index}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
            );
            let request = client
                .post(&url)
                .header("Content-Type", "text/xml; charset=\"utf-8\"")
                .header("SOAPAction", format!("\"{service}#GetGenericPortMappingEntry\""))
                .body(body);
            let Ok(Ok(response)) = tokio::time::timeout(Duration::from_secs(4), request.send()).await else { break };
            if !response.status().is_success() {
                break;
            }
            let Ok(xml) = response.text().await else { break };
            let external = tag(&xml, "NewExternalPort").unwrap_or_default();
            let client_ip = tag(&xml, "NewInternalClient").unwrap_or_default();
            let internal = tag(&xml, "NewInternalPort").unwrap_or_default();
            let protocol = tag(&xml, "NewProtocol").unwrap_or_default();
            let description = tag(&xml, "NewPortMappingDescription").unwrap_or_default();
            let device = by_ip.get(&client_ip).cloned().unwrap_or_else(|| client_ip.clone());
            let label = if description.is_empty() { String::new() } else { format!(" for \"{description}\"") };
            part.add(
                "medium",
                "lan",
                format!("The router forwards {protocol} port {external} from the internet to {device} port {internal}{label}, opened by UPnP."),
                None,
                "UPnP",
            );
        }
    }
}

async fn captive(part: &mut Part, client: &reqwest::Client) {
    match client.get("http://captive.apple.com/hotspot-detect.html").send().await {
        Ok(response) => {
            let body = response.text().await.unwrap_or_default();
            part.checked.push("captive portal".into());
            if !body.contains("Success") {
                part.add("info", "lan", "This network sends web traffic to a sign-in page (a captive portal), as hotel and café networks do; use a VPN or iCloud Private Relay on networks you do not trust.".into(), None, "network");
            }
        }
        Err(error) => part.skipped.push(format!("captive portal: {error}")),
    }
}

/// What the internet sees of the public IP: Shodan InternetDB (no key) and, once a day, GreyNoise.
async fn exposure(part: &mut Part, client: &reqwest::Client, ip: IpAddr) {
    let shown = mask(ip);
    match client.get(format!("https://internetdb.shodan.io/{ip}")).send().await {
        Ok(response) if response.status().as_u16() == 404 => part.checked.push("internet exposure (Shodan InternetDB: nothing seen)".into()),
        Ok(response) if response.status().is_success() => {
            let info: Value = response.bytes().await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
            part.checked.push("internet exposure (Shodan InternetDB)".into());
            let ports: Vec<String> = info["ports"].as_array().into_iter().flatten().filter_map(Value::as_u64).map(|p| p.to_string()).collect();
            let vulns: Vec<String> = info["vulns"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)).collect();
            if !ports.is_empty() {
                let cves = if vulns.is_empty() {
                    String::new()
                } else {
                    format!(", with {} ({})", plural(vulns.len(), "known vulnerability", "known vulnerabilities"), vulns.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
                };
                part.add(
                    "high",
                    "network",
                    format!("From the internet, this network's address ({shown}) answers on {}: {}{cves}. Check the router's port forwards.", plural(ports.len(), "port", "ports"), ports.join(", ")),
                    None,
                    "Shodan InternetDB",
                );
            }
        }
        Ok(response) => part.skipped.push(format!("internet exposure: Shodan InternetDB answered {}", response.status())),
        Err(error) => part.skipped.push(format!("internet exposure: {error}")),
    }

    let (mut greynoise_at, mut greynoise) = match lock_lan().as_ref() {
        Some(lan) => (lan.greynoise_at, lan.greynoise.clone()),
        None => (now_ms(), None),
    };
    if now_ms().saturating_sub(greynoise_at) >= DAY {
        match client.get(format!("https://api.greynoise.io/v3/community/{ip}")).send().await {
            Ok(response) if response.status().as_u16() == 404 => {
                greynoise_at = now_ms();
                greynoise = None;
            }
            Ok(response) if response.status().is_success() => {
                let info: Value = response.bytes().await.ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
                greynoise_at = now_ms();
                greynoise = (info["noise"].as_bool() == Some(true) && info["classification"].as_str() != Some("benign"))
                    .then(|| info["classification"].as_str().unwrap_or("unknown").to_owned());
            }
            Ok(response) => part.skipped.push(format!("GreyNoise: answered {} (it allows a few lookups a day)", response.status())),
            Err(error) => part.skipped.push(format!("GreyNoise: {error}")),
        }
        if let Some(lan) = lock_lan().as_mut() {
            lan.greynoise_at = greynoise_at;
            lan.greynoise = greynoise.clone();
        }
    }
    if greynoise_at > 0 {
        part.checked.push("GreyNoise (is this network scanning others)".into());
        if lock_lan().is_some() {
            part.graph.extend(greynoise_batch(greynoise_at, greynoise.as_deref()));
        }
    }
    if let Some(class) = &greynoise {
        part.about("MacSetting", "greynoise");
        part.add(
            "high",
            "network",
            format!("GreyNoise has seen this network's address ({shown}) scanning the internet (rated {class}); a device here may be infected."),
            None,
            "GreyNoise",
        );
    }
}

/// `81.45.x.x` in finding text (the sweep's report is kept and shown).
fn mask(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.x.x", o[0], o[1])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}::…", s[0], s[1])
        }
    }
}

/// Which resolver DNS queries really reach, and whether DNS or IPv6 go around a VPN.
fn leaks(part: &mut Part, tables: &feeds::Tables, public: Option<IpAddr>, resolver: Option<IpAddr>, vpn: bool, v6_interface: &str, net: Option<&Net>) {
    let Some(resolver) = resolver else {
        part.skipped.push("DNS leak test: dig could not ask whoami.akamai.net".into());
        return;
    };
    part.checked.push("DNS resolver as the internet sees it".into());
    let seen = tables.owner(resolver);
    if !vpn {
        part.add("info", "network", format!("DNS lookups reach the internet through {}.", seen.label()), None, "DNS leak test");
        return;
    }
    part.checked.push("VPN leaks (DNS and IPv6)".into());
    let exit = public.map(|ip| tables.owner(ip));
    let public_dns = [15169, 13335, 19281, 36692, 42, 3356];
    if let Some(exit) = exit
        && exit.asn != 0
        && seen.asn != exit.asn
        && !public_dns.contains(&seen.asn)
    {
        part.add(
            "medium",
            "network",
            format!("A VPN is on, but DNS lookups reach {} while web traffic leaves through {}; DNS may be going around the VPN.", seen.label(), exit.label()),
            None,
            "DNS leak test",
        );
    }
    if let Some(net) = net
        && !net.public6.is_empty()
        && v6_interface == net.interface
    {
        part.add("medium", "network", format!("A VPN is on, but IPv6 traffic leaves directly through {} and not through the VPN.", net.interface), None, "VPN leak test");
    }
}
