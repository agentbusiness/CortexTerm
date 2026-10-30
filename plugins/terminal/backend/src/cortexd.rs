//! `cortexd` executable: the PTY daemon (see `cc_terminal::daemon`).
//!
//! `cortexd [--home <dir>] [--foreground]`. The terminal plugin starts it when it finds no daemon;
//! it forks into its own session (so the frame's process-group cleanup and the app quitting do not
//! reach it), takes `<home>/run/cortexd.lock` (a second daemon exits at once), writes its log to
//! `<home>/logs/cortexd.log` and serves `<home>/run/cortexd.sock`.

use std::os::fd::AsRawFd;
use std::path::PathBuf;

fn main() {
    let mut home = cc_terminal::wire::home();
    let mut foreground = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--home" => home = args.next().map(PathBuf::from).unwrap_or(home),
            "--foreground" => foreground = true,
            other => {
                eprintln!("cortexd: unknown argument `{other}`");
                std::process::exit(2);
            }
        }
    }
    for dir in [home.join("run"), home.join("logs")] {
        let _ = std::fs::create_dir_all(dir);
    }
    if !foreground {
        // SAFETY: still single-threaded here; the parent returns at once, so whoever started us
        // does not wait for the daemon, and the child leaves the caller's session and group.
        unsafe {
            match libc::fork() {
                -1 => {
                    eprintln!("cortexd: fork failed");
                    std::process::exit(1);
                }
                0 => {
                    libc::setsid();
                }
                _ => libc::_exit(0),
            }
        }
        if let Ok(log) = std::fs::OpenOptions::new().create(true).append(true).open(cc_terminal::wire::log_path(&home)) {
            // SAFETY: dup2 onto the standard descriptors of this process.
            unsafe {
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
                if null >= 0 {
                    libc::dup2(null, 0);
                    libc::close(null);
                }
                libc::dup2(log.as_raw_fd(), 1);
                libc::dup2(log.as_raw_fd(), 2);
            }
        }
        let _ = std::env::set_current_dir("/");
    }
    // SAFETY: ignoring SIGHUP (no controlling terminal) and SIGPIPE (a client that went away).
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let lock = match std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(cc_terminal::wire::lock_path(&home)) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("cortexd: lock file: {error}");
            std::process::exit(1);
        }
    };
    // SAFETY: flock on a descriptor we own; held until the process exits.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        // Another daemon serves this home.
        std::process::exit(0);
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("CORTEX_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cortexd: cannot start the async runtime: {error}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(cc_terminal::daemon::run(home));
    drop(lock);
    std::process::exit(code);
}
