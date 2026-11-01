//! Who uses what right now: every process of this user with its working folder and open files,
//! read once per scan and again just before a clean, plus the build locks a running tool holds.
//! The model never decides this; these facts do.

use crate::recipes::Recipe;
use std::path::{Path, PathBuf};

pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cwd: PathBuf,
}

#[derive(Default)]
pub struct Snapshot {
    pub processes: Vec<Process>,
    /// (open file, index into `processes`).
    pub open: Vec<(PathBuf, usize)>,
}

impl Snapshot {
    pub fn take() -> Self {
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing().with_cwd(sysinfo::UpdateKind::Always).with_user(sysinfo::UpdateKind::Always),
        );
        let uid = unsafe { libc::getuid() };
        let mut snapshot = Snapshot::default();
        for (pid, process) in system.processes() {
            if process.user_id().is_some_and(|user| **user != uid) {
                continue;
            }
            let index = snapshot.processes.len();
            snapshot.processes.push(Process {
                pid: pid.as_u32(),
                name: process.name().to_string_lossy().into_owned(),
                cwd: process.cwd().map(Path::to_path_buf).unwrap_or_default(),
            });
            // The Virtualization framework's VM process keeps read-only handles on whatever a
            // guest touched through a shared folder; only what it writes (its disk) is use.
            let shares = snapshot.processes[index].name == "com.apple.Virtualization.VirtualMachine";
            for (path, writes) in open_files(pid.as_u32()) {
                if writes || !shares {
                    snapshot.open.push((path, index));
                }
            }
        }
        snapshot
    }

    /// Why `path` is in use now (empty when it is not): a held build lock, a program with files
    /// open or working inside, a recipe's program working in the project, or a recipe's app open.
    pub fn users(&self, path: &Path, project: Option<&Path>, recipe: Option<&Recipe>) -> Vec<String> {
        let mut why = Vec::new();
        let mut add = |text: String| {
            if !why.contains(&text) && why.len() < 4 {
                why.push(text);
            }
        };
        if let Some(recipe) = recipe {
            for lock in &recipe.locks {
                if locked(&path.join(lock)) {
                    add(format!("a build holds {lock}"));
                }
            }
        }
        let open_ok = recipe.is_some_and(|r| r.open_ok);
        for (file, index) in self.open.iter().filter(|_| !open_ok) {
            if file.starts_with(path) {
                let process = &self.processes[*index];
                add(format!("{} (pid {}) has files open", process.name, process.pid));
            }
        }
        for process in &self.processes {
            if !process.cwd.as_os_str().is_empty() && process.cwd.starts_with(path) {
                add(format!("{} (pid {}) works inside", process.name, process.pid));
            }
        }
        if let Some(recipe) = recipe {
            for process in &self.processes {
                let name = process.name.to_lowercase();
                let program = recipe.programs.iter().any(|p| name == p.to_lowercase());
                if program && project.is_some_and(|project| !process.cwd.as_os_str().is_empty() && process.cwd.starts_with(project)) {
                    add(format!("{} (pid {}) runs in the project", process.name, process.pid));
                }
                if recipe.apps.iter().any(|app| name == app.to_lowercase()) {
                    add(format!("{} is open", process.name));
                }
            }
        }
        why
    }
}

/// A lock file some process holds an exclusive or shared `flock` on (cargo's `.cargo-lock` while
/// it builds). Taken and given back at once when free.
fn locked(file: &Path) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(handle) = std::fs::File::open(file) else { return false };
    let fd = handle.as_raw_fd();
    // SAFETY: a valid descriptor owned by `handle` for the duration of the calls.
    let taken = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if taken {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
    !taken
}

/// The regular files `pid` has open, each with whether it may write to it.
#[cfg(target_os = "macos")]
fn open_files(pid: u32) -> Vec<(PathBuf, bool)> {
    use std::ffi::CStr;
    // <sys/proc_info.h>: PROC_PIDLISTFDS lists `struct proc_fdinfo {int32 fd; uint32 type}`;
    // PROC_PIDFDVNODEPATHINFO fills `struct vnode_fdinfowithpath`: proc_fileinfo (24 bytes, its
    // `fi_openflags` first), vnode_info (152 bytes: vinfo_stat (136), then `vi_type`), then the
    // path (MAXPATHLEN).
    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    const PROX_FDTYPE_VNODE: u32 = 1;
    const FWRITE: u32 = 2;
    const TYPE_AT: usize = 24 + 136;
    const VREG: i32 = 1;
    const PATH_AT: usize = 24 + 152;
    const INFO_SIZE: usize = PATH_AT + 1024;
    unsafe extern "C" {
        fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut libc::c_void, size: i32) -> i32;
        fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut libc::c_void, size: i32) -> i32;
    }
    let pid = pid as i32;
    // SAFETY: a null buffer asks for the size; the buffers below are as large as passed.
    let bytes = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Vec::new();
    }
    let mut fds = vec![[0u32; 2]; bytes as usize / 8 + 16];
    let bytes = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), (fds.len() * 8) as i32) };
    if bytes <= 0 {
        return Vec::new();
    }
    fds.truncate(bytes as usize / 8);
    let mut paths = Vec::new();
    let mut info = vec![0u8; INFO_SIZE];
    for [fd, kind] in fds {
        if kind != PROX_FDTYPE_VNODE {
            continue;
        }
        let read = unsafe { proc_pidfdinfo(pid, fd as i32, PROC_PIDFDVNODEPATHINFO, info.as_mut_ptr().cast(), INFO_SIZE as i32) };
        if read as usize != INFO_SIZE {
            continue;
        }
        let word = |at: usize| [info[at], info[at + 1], info[at + 2], info[at + 3]];
        if i32::from_ne_bytes(word(TYPE_AT)) != VREG {
            continue;
        }
        let writes = u32::from_ne_bytes(word(0)) & FWRITE != 0;
        if let Ok(path) = CStr::from_bytes_until_nul(&info[PATH_AT..]) {
            let path = path.to_string_lossy();
            if path.starts_with('/') {
                paths.push((PathBuf::from(path.as_ref()), writes));
            }
        }
    }
    paths
}

#[cfg(not(target_os = "macos"))]
fn open_files(pid: u32) -> Vec<(PathBuf, bool)> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|entries| {
            entries.flatten().filter_map(|entry| std::fs::read_link(entry.path()).ok()).filter(|p| p.is_absolute()).map(|p| (p, true)).collect()
        })
        .unwrap_or_default()
}
