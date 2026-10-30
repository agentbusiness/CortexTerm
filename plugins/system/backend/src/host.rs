//! What the operating system tells us beyond `sysinfo`: memory pressure, compressed memory, core
//! tiers, thermal state, battery, code signatures, quarantine, launchd jobs and per-process facts.
//! macOS gets real numbers; Linux gets what is cheap to read, the rest stays empty.

use crate::util::run;
use cc_protocol::contracts::system::Battery;
use std::collections::{HashMap, HashSet};
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::path::PathBuf;
use std::time::Duration;

#[cfg(target_os = "macos")]
fn sysctl_raw(name: &str) -> Option<Vec<u8>> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: first call asks for the size, the second fills a buffer of that size.
    unsafe {
        if libc::sysctlbyname(name.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(name.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

#[cfg(target_os = "macos")]
pub fn sysctl_u32(name: &str) -> Option<u32> {
    let buf = sysctl_raw(name)?;
    Some(match buf.len() {
        4 => u32::from_ne_bytes(buf[..4].try_into().ok()?),
        8 => u64::from_ne_bytes(buf[..8].try_into().ok()?) as u32,
        _ => return None,
    })
}

#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> Option<String> {
    let buf = sysctl_raw(name)?;
    let text = String::from_utf8_lossy(&buf).trim_end_matches('\0').trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// The machine's name ("Apple M2 Pro") and its performance / efficiency core counts.
pub fn machine() -> (String, u32, u32) {
    #[cfg(target_os = "macos")]
    {
        let name = sysctl_string("machdep.cpu.brand_string").or_else(|| sysctl_string("hw.model")).unwrap_or_default();
        let levels = sysctl_u32("hw.nperflevels").unwrap_or(0);
        if levels >= 2 {
            let p = sysctl_u32("hw.perflevel0.logicalcpu").unwrap_or(0);
            let e = sysctl_u32("hw.perflevel1.logicalcpu").unwrap_or(0);
            return (name, p, e);
        }
        (name, 0, 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let sys = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::nothing().with_cpu(sysinfo::CpuRefreshKind::nothing()));
        (sys.cpus().first().map(|cpu| cpu.brand().trim().to_owned()).unwrap_or_default(), 0, 0)
    }
}

/// normal | warn | critical
pub fn pressure() -> String {
    #[cfg(target_os = "macos")]
    {
        match sysctl_u32("kern.memorystatus_vm_pressure_level") {
            Some(4) => "critical",
            Some(2) => "warn",
            _ => "normal",
        }
        .to_owned()
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux PSI: `some avg10=..` / `full avg10=..`.
        let text = std::fs::read_to_string("/proc/pressure/memory").unwrap_or_default();
        let avg10 = |prefix: &str| {
            text.lines()
                .find(|line| line.starts_with(prefix))
                .and_then(|line| line.split_whitespace().find_map(|f| f.strip_prefix("avg10=")))
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0)
        };
        if avg10("full") >= 10.0 {
            "critical"
        } else if avg10("some") >= 10.0 {
            "warn"
        } else {
            "normal"
        }
        .to_owned()
    }
}

/// Bytes held by the memory compressor (what Activity Monitor shows as "Compressed").
pub fn compressed_memory() -> u64 {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: host_statistics64 fills a vm_statistics64 of HOST_VM_INFO64_COUNT words.
        #[allow(deprecated)]
        unsafe {
            let mut stats: libc::vm_statistics64 = std::mem::zeroed();
            let mut count = libc::HOST_VM_INFO64_COUNT;
            let rc = libc::host_statistics64(
                libc::mach_host_self(),
                libc::HOST_VM_INFO64,
                (&mut stats as *mut libc::vm_statistics64).cast(),
                &mut count,
            );
            if rc != 0 {
                return 0;
            }
            let page = libc::sysconf(libc::_SC_PAGESIZE).max(0) as u64;
            stats.compressor_page_count as u64 * page
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

/// nominal | fair | serious | critical ("" when unknown).
pub fn thermal() -> String {
    #[cfg(target_os = "macos")]
    {
        use objc2_foundation::{NSProcessInfo, NSProcessInfoThermalState};
        let state = NSProcessInfo::processInfo().thermalState();
        if state == NSProcessInfoThermalState::Nominal {
            "nominal"
        } else if state == NSProcessInfoThermalState::Fair {
            "fair"
        } else if state == NSProcessInfoThermalState::Serious {
            "serious"
        } else if state == NSProcessInfoThermalState::Critical {
            "critical"
        } else {
            ""
        }
        .to_owned()
    }
    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

/// The internal battery, if there is one (`pmset -g batt`, watts from the smart battery's
/// voltage and current).
pub fn battery() -> Option<Battery> {
    #[cfg(target_os = "macos")]
    {
        let out = run("/usr/bin/pmset", &["-g", "batt"], Duration::from_secs(5)).ok()?;
        let line = out.stdout.lines().find(|line| line.contains("InternalBattery"))?;
        let (before, after) = line.split_once('%')?;
        let percent: f32 = before.rsplit(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
        let state = after.trim_start_matches(';').split(';').next().unwrap_or("").trim();
        let charging = state == "charging";
        Some(Battery { percent, charging, watts: battery_watts() })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let dir = std::fs::read_dir("/sys/class/power_supply")
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| std::fs::read_to_string(p.join("type")).map(|t| t.trim() == "Battery").unwrap_or(false))?;
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).ok().map(|s| s.trim().to_owned());
        let percent: f32 = read("capacity")?.parse().ok()?;
        let charging = read("status").as_deref() == Some("Charging");
        let watts = read("power_now").and_then(|v| v.parse::<f32>().ok()).map(|uw| uw / 1_000_000.0);
        Some(Battery { percent, charging, watts })
    }
}

#[cfg(target_os = "macos")]
fn battery_watts() -> Option<f32> {
    let out = run("/usr/sbin/ioreg", &["-rn", "AppleSmartBattery"], Duration::from_secs(5)).ok()?;
    let field = |key: &str| {
        let needle = format!("\"{key}\" = ");
        out.stdout.lines().find_map(|line| line.trim().strip_prefix(&needle).and_then(|v| v.trim().parse::<u64>().ok()))
    };
    let volts = field("Voltage")? as f64 / 1000.0;
    // Current is a signed value printed as unsigned.
    let amps = field("InstantAmperage").or_else(|| field("Amperage"))? as i64 as f64 / 1000.0;
    let watts = (volts * amps).abs() as f32;
    (watts > 0.0).then_some(watts)
}

/// signed | adhoc | unsigned | unknown, and the team identifier. Cached by path and mtime; the
/// full signature (notarization, entitlements) is [`crate::codesign`].
pub fn signature(path: &Path) -> (String, String) {
    let sig = crate::codesign::check(path);
    (sig.status, sig.team_id)
}

/// Carries a `com.apple.quarantine` flag the user has not yet approved (Gatekeeper sets bit 0x40
/// once the user opened it), itself or the app bundle it lives in.
pub fn quarantined(path: &Path) -> bool {
    let flagged = |p: &Path| match xattr::get(p, "com.apple.quarantine") {
        Ok(Some(value)) => {
            let text = String::from_utf8_lossy(&value);
            let flags = u32::from_str_radix(text.split(';').next().unwrap_or(""), 16).unwrap_or(0);
            flags & 0x40 == 0
        }
        _ => false,
    };
    if flagged(path) {
        return true;
    }
    let text = path.display().to_string();
    match text.find(".app/") {
        Some(end) => flagged(Path::new(&text[..end + 4])),
        None => false,
    }
}

/// Pids of launchd jobs in the user's domain that launchd restarts (apps launched from the Dock
/// are `application.*` jobs and do not restart).
pub fn launchd_job_pids() -> HashSet<u32> {
    if !cfg!(target_os = "macos") {
        return HashSet::new();
    }
    let Ok(out) = run("/bin/launchctl", &["list"], Duration::from_secs(5)) else {
        return HashSet::new();
    };
    out.stdout
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let pid = fields.next()?.trim().parse::<u32>().ok()?;
            let label = fields.nth(1)?.trim();
            (!label.starts_with("application.")).then_some(pid)
        })
        .collect()
}

fn cwd_of(pid: u32) -> String {
    let mut sys = sysinfo::System::new();
    let pid = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        false,
        sysinfo::ProcessRefreshKind::nothing().with_cwd(sysinfo::UpdateKind::Always),
    );
    sys.process(pid).and_then(|p| p.cwd()).map(|p| p.display().to_string()).unwrap_or_default()
}

/// Working directory, open file descriptors and thread count of a process.
pub fn process_facts(pid: u32) -> (String, u32, u32) {
    #[cfg(target_os = "macos")]
    {
        use libproc::libproc::bsd_info::BSDInfo;
        use libproc::libproc::file_info::ListFDs;
        use libproc::libproc::proc_pid::{listpidinfo, pidinfo};
        use libproc::libproc::task_info::TaskAllInfo;
        let pid = pid as i32;
        let cwd = cwd_of(pid as u32);
        let files = pidinfo::<BSDInfo>(pid, 0)
            .ok()
            .and_then(|info| listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize).ok())
            .map(|fds| fds.len() as u32)
            .unwrap_or(0);
        let threads = pidinfo::<TaskAllInfo>(pid, 0).map(|info| info.ptinfo.pti_threadnum as u32).unwrap_or(0);
        (cwd, files, threads)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let cwd = cwd_of(pid);
        let files = std::fs::read_dir(base.join("fd")).map(|d| d.count() as u32).unwrap_or(0);
        let threads = std::fs::read_to_string(base.join("status"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Threads:").and_then(|v| v.trim().parse().ok())))
            .unwrap_or(0);
        (cwd, files, threads)
    }
}

/// The memory footprint Activity Monitor shows (macOS), when this user may read it.
pub fn footprint(pid: u32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        use libproc::libproc::pid_rusage::{RUsageInfoV2, pidrusage};
        pidrusage::<RUsageInfoV2>(pid as i32).ok().map(|info| info.ri_phys_footprint).filter(|bytes| *bytes > 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Accumulated GPU time in ns per pid, from the `AGXDeviceUserClient` children of every
/// `IOAccelerator` service (`IOUserClientCreator` = "pid N, name", `AppUsage` = one dict per
/// command queue with `accumulatedGPUTime`). `None` when the registry cannot be read.
#[cfg(target_os = "macos")]
pub fn gpu_times() -> Option<HashMap<u32, u64>> {
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, CFTypeRef, TCFType, kCFAllocatorDefault};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use std::ffi::{c_char, c_void};

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOServiceMatching(name: *const c_char) -> *const c_void;
        fn IOServiceGetMatchingServices(main_port: u32, matching: *const c_void, existing: *mut u32) -> i32;
        fn IORegistryEntryGetChildIterator(entry: u32, plane: *const c_char, iterator: *mut u32) -> i32;
        fn IORegistryEntryCreateCFProperty(entry: u32, key: CFStringRef, allocator: *const c_void, options: u32) -> CFTypeRef;
        fn IOIteratorNext(iterator: u32) -> u32;
        fn IOObjectRelease(object: u32) -> i32;
    }

    /// An owned IOKit object, released on drop.
    struct Object(u32);
    impl Drop for Object {
        fn drop(&mut self) {
            // SAFETY: we own one reference to this object.
            unsafe { IOObjectRelease(self.0) };
        }
    }
    fn next(iterator: &Object) -> Option<Object> {
        // SAFETY: a valid iterator; a non-zero result is an object we own.
        let object = unsafe { IOIteratorNext(iterator.0) };
        (object != 0).then_some(Object(object))
    }
    fn property(entry: &Object, key: &CFString) -> Option<CFType> {
        // SAFETY: a valid entry and key; the result follows the create rule.
        let value = unsafe { IORegistryEntryCreateCFProperty(entry.0, key.as_concrete_TypeRef(), kCFAllocatorDefault.cast(), 0) };
        // SAFETY: a non-null CF object we now own.
        (!value.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(value) })
    }

    let creator_key = CFString::from_static_string("IOUserClientCreator");
    let usage_key = CFString::from_static_string("AppUsage");
    let time_key = CFString::from_static_string("accumulatedGPUTime");
    let mut services = 0;
    // SAFETY: IOServiceGetMatchingServices takes ownership of the matching dictionary.
    if unsafe { IOServiceGetMatchingServices(0, IOServiceMatching(c"IOAccelerator".as_ptr()), &mut services) } != 0 {
        return None;
    }
    let services = Object(services);
    let mut times = HashMap::new();
    while let Some(gpu) = next(&services) {
        let mut children = 0;
        // SAFETY: a valid entry and plane name.
        if unsafe { IORegistryEntryGetChildIterator(gpu.0, c"IOService".as_ptr(), &mut children) } != 0 {
            continue;
        }
        let children = Object(children);
        while let Some(client) = next(&children) {
            let Some(creator) = property(&client, &creator_key).and_then(|v| v.downcast_into::<CFString>()) else { continue };
            let creator = creator.to_string();
            let Some(pid) = creator.strip_prefix("pid ").and_then(|rest| rest.split(',').next()).and_then(|p| p.trim().parse::<u32>().ok())
            else {
                continue;
            };
            let Some(usage) = property(&client, &usage_key).and_then(|v| v.downcast_into::<CFArray>()) else { continue };
            let mut ns = 0u64;
            for entry in usage.iter() {
                let entry: *const c_void = *entry;
                if entry.is_null() {
                    continue;
                }
                // SAFETY: an element of a live array, retained for the wrapper's lifetime.
                let Some(dict) = unsafe { CFType::wrap_under_get_rule(entry) }.downcast_into::<CFDictionary>() else { continue };
                let Some(value) = dict.find(time_key.as_CFTypeRef()).map(|v| *v).filter(|v| !v.is_null()) else { continue };
                // SAFETY: a value of a live dictionary, retained for the wrapper's lifetime.
                if let Some(n) = unsafe { CFType::wrap_under_get_rule(value) }.downcast_into::<CFNumber>().and_then(|n| n.to_i64()) {
                    ns = ns.saturating_add(n.max(0) as u64);
                }
            }
            let total: &mut u64 = times.entry(pid).or_default();
            *total = total.saturating_add(ns);
        }
    }
    Some(times)
}

#[cfg(not(target_os = "macos"))]
pub fn gpu_times() -> Option<HashMap<u32, u64>> {
    None
}

/// Lifetime counters of one process: CPU time (ms), disk read and written, peak footprint, and
/// its BSD status (stopped, zombie). Zeros when this user may not read them.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lifetime {
    pub cpu_time_ms: u64,
    pub disk_read: u64,
    pub disk_written: u64,
    pub peak_memory: u64,
    pub stopped: bool,
    pub zombie: bool,
}

#[allow(deprecated)] // libc points to mach2 for the timebase; one call does not earn a crate.
pub fn lifetime(pid: u32) -> Lifetime {
    #[cfg(target_os = "macos")]
    {
        use libproc::libproc::bsd_info::BSDInfo;
        use libproc::libproc::pid_rusage::{RUsageInfoV4, pidrusage};
        use libproc::libproc::proc_pid::pidinfo;
        let mut out = Lifetime::default();
        if let Ok(info) = pidrusage::<RUsageInfoV4>(pid as i32) {
            // rusage times are Mach ticks; the timebase turns them into ns (1:1 on Intel).
            let mut base = libc::mach_timebase_info { numer: 1, denom: 1 };
            // SAFETY: fills the struct we pass.
            unsafe {
                libc::mach_timebase_info(&mut base);
            }
            let ns = (info.ri_user_time + info.ri_system_time) as u128 * base.numer as u128 / base.denom.max(1) as u128;
            out.cpu_time_ms = (ns / 1_000_000) as u64;
            out.disk_read = info.ri_diskio_bytesread;
            out.disk_written = info.ri_diskio_byteswritten;
            out.peak_memory = info.ri_lifetime_max_phys_footprint;
        }
        if let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) {
            out.stopped = info.pbi_status == 4;
            out.zombie = info.pbi_status == 5;
        }
        out
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut out = Lifetime::default();
        let base = PathBuf::from(format!("/proc/{pid}"));
        if let Ok(stat) = std::fs::read_to_string(base.join("stat"))
            && let Some(rest) = stat.rsplit_once(") ").map(|(_, rest)| rest)
        {
            let fields: Vec<&str> = rest.split_whitespace().collect();
            out.stopped = fields.first().is_some_and(|s| *s == "T");
            out.zombie = fields.first().is_some_and(|s| *s == "Z");
            // SAFETY: sysconf has no preconditions.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
            let ticks: u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0) + fields.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            out.cpu_time_ms = ticks * 1000 / hz;
        }
        if let Ok(io) = std::fs::read_to_string(base.join("io")) {
            let field = |name: &str| io.lines().find_map(|l| l.strip_prefix(name).and_then(|v| v.trim().parse().ok())).unwrap_or(0);
            out.disk_read = field("read_bytes:");
            out.disk_written = field("write_bytes:");
        }
        if let Ok(status) = std::fs::read_to_string(base.join("status")) {
            out.peak_memory = status.lines().find_map(|l| l.strip_prefix("VmHWM:").and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())).unwrap_or(0) * 1024;
        }
        out
    }
}

/// Every thread of one process, busiest first (macOS: libproc; Linux: /proc/<pid>/task).
pub fn threads(pid: u32) -> Vec<cc_protocol::contracts::system::ThreadSample> {
    use cc_protocol::contracts::system::ThreadSample;
    #[cfg(target_os = "macos")]
    let mut list = {
        use libproc::libproc::proc_pid::{ListThreads, listpidinfo, pidinfo};
        use libproc::libproc::task_info::TaskAllInfo;
        use libproc::libproc::thread_info::ThreadInfo;
        let count = pidinfo::<TaskAllInfo>(pid as i32, 0).map(|info| info.ptinfo.pti_threadnum as usize).unwrap_or(0);
        let handles = if count == 0 { Vec::new() } else { listpidinfo::<ListThreads>(pid as i32, count + 8).unwrap_or_default() };
        handles
            .into_iter()
            .filter_map(|handle| {
                let info = pidinfo::<ThreadInfo>(pid as i32, handle).ok()?;
                let name: Vec<u8> = info.pth_name.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
                Some(ThreadSample {
                    id: handle,
                    name: String::from_utf8_lossy(&name).into_owned(),
                    state: match info.pth_run_state {
                        1 => "running",
                        2 => "stopped",
                        3 => "waiting",
                        4 => "uninterruptible",
                        5 => "halted",
                        _ => "",
                    }
                    .into(),
                    // TH_USAGE_SCALE is 1000 for one full core.
                    cpu: info.pth_cpu_usage as f32 / 10.0,
                    user_ms: info.pth_user_time / 1_000_000,
                    system_ms: info.pth_system_time / 1_000_000,
                    priority: info.pth_curpri,
                })
            })
            .collect::<Vec<_>>()
    };
    #[cfg(not(target_os = "macos"))]
    let mut list = {
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|dir| {
                dir.flatten()
                    .filter_map(|task| {
                        let id: u64 = task.file_name().to_str()?.parse().ok()?;
                        let stat = std::fs::read_to_string(task.path().join("stat")).ok()?;
                        let (head, rest) = stat.rsplit_once(") ")?;
                        let name = head.split_once(" (").map(|(_, name)| name).unwrap_or("").to_owned();
                        let fields: Vec<&str> = rest.split_whitespace().collect();
                        let at = |i: usize| fields.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                        Some(ThreadSample {
                            id,
                            name,
                            state: match fields.first().copied().unwrap_or("") {
                                "R" => "running",
                                "T" | "t" => "stopped",
                                "D" => "uninterruptible",
                                "Z" | "X" => "halted",
                                _ => "waiting",
                            }
                            .into(),
                            cpu: 0.0,
                            user_ms: at(11) * 1000 / hz,
                            system_ms: at(12) * 1000 / hz,
                            priority: fields.get(15).and_then(|v| v.parse().ok()).unwrap_or(0),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    list.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal).then((b.user_ms + b.system_ms).cmp(&(a.user_ms + a.system_ms))));
    list
}

/// Open files, sockets and pipes of the given pids, from `lsof -F` (numeric hosts and ports).
/// Keyed by pid; a pid that could not be read is missing.
pub fn open_files(pids: &[u32]) -> HashMap<u32, Vec<cc_protocol::contracts::system::OpenFile>> {
    use cc_protocol::contracts::system::OpenFile;
    let mut out: HashMap<u32, Vec<OpenFile>> = HashMap::new();
    if pids.is_empty() {
        return out;
    }
    let list = pids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
    let Ok(output) = run("lsof", &["-nP", "-w", "-a", "-p", &list, "-F", "pfatPnT"], Duration::from_secs(8)) else { return out };
    let mut pid = 0u32;
    let mut file: Option<OpenFile> = None;
    let mut kind = String::new();
    let flush = |out: &mut HashMap<u32, Vec<OpenFile>>, pid: u32, file: &mut Option<OpenFile>| {
        if let Some(file) = file.take() {
            out.entry(pid).or_default().push(file);
        }
    };
    for line in output.stdout.lines() {
        let (tag, value) = line.split_at(line.len().min(1));
        match tag {
            "p" => {
                flush(&mut out, pid, &mut file);
                pid = value.parse().unwrap_or(0);
                out.entry(pid).or_default();
            }
            "f" => {
                flush(&mut out, pid, &mut file);
                file = Some(OpenFile { fd: value.into(), ..Default::default() });
                kind.clear();
            }
            "a" => {
                if let Some(file) = file.as_mut() {
                    file.mode = value.trim().into();
                }
            }
            "t" => {
                kind = value.to_owned();
                if let Some(file) = file.as_mut() {
                    file.kind = match value {
                        "REG" => "file",
                        "DIR" => "dir",
                        "unix" => "unix",
                        "PIPE" | "FIFO" => "pipe",
                        "CHR" | "BLK" => "device",
                        "IPv4" | "IPv6" => "tcp",
                        _ => "other",
                    }
                    .into();
                }
            }
            "n" => {
                if let Some(file) = file.as_mut() {
                    file.name = value.to_owned();
                }
            }
            "P" => {
                if let Some(file) = file.as_mut()
                    && (kind == "IPv4" || kind == "IPv6")
                {
                    file.kind = value.to_lowercase();
                }
            }
            "T" => {
                if let Some(file) = file.as_mut()
                    && let Some(state) = value.strip_prefix("ST=")
                {
                    file.state = state.to_owned();
                }
            }
            _ => {}
        }
    }
    flush(&mut out, pid, &mut file);
    out
}
