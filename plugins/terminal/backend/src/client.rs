//! The plugin's connection to `cortexd` (see `wire` for the protocol).
//!
//! [`Daemon::connect`] connects to `$CORTEX_HOME/run/cortexd.sock`, starting the daemon (the
//! `cortexd` executable beside this one) when nothing answers. Requests are queued in the order
//! they are made, so input reaches a shell in the order it was typed.
//!
//! Versions: an owner that meets a daemon of another [`wire::DAEMON_VERSION`] with no living
//! shell asks it to quit and starts its own; with living shells it keeps using the old daemon
//! (the protocol only grows) until a later connect finds it without shells. Shells are never
//! killed for an upgrade.

use crate::wire::{self, Hello, Message, Op, Request};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};

use crate::lock;

/// Called with every pushed message, in order; `None` once the connection has ended.
pub type OnMessage = Arc<dyn Fn(Option<Message>) + Send + Sync>;

type Waiting = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Daemon {
    tx: mpsc::UnboundedSender<String>,
    waiting: Waiting,
    next: AtomicU64,
    pub version: u32,
    pub pid: u32,
}

/// The daemon executable: `cortexd` beside this one (the package ships both in `backend/`).
fn executable() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this executable: {e}"))?;
    let path = exe.parent().map(|dir| dir.join("cortexd")).ok_or("the executable has no folder")?;
    if path.is_file() { Ok(path) } else { Err(format!("cortexd is missing beside {}", exe.display())) }
}

/// Start the daemon. It forks into its own session at once, so it is neither our child for long
/// nor in our process group (the frame kills a plugin's group when it stops it).
async fn start(home: &Path) -> Result<(), String> {
    let exe = executable()?;
    let home = home.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new(&exe);
        command.arg("--home").arg(&home).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        for var in ["CORTEX_FRAME_SOCKET", "CORTEX_PLUGIN_INSTANCE", "CORTEX_PLUGIN_DATA", "CORTEX_PLUGIN_LIVE", "CORTEX_LIVE"] {
            command.env_remove(var);
        }
        command.status().map_err(|e| format!("cannot start {}: {e}", exe.display())).map(|_| ())
    })
    .await
    .map_err(|e| format!("start task failed: {e}"))?
}

async fn dial(home: &Path) -> Result<UnixStream, String> {
    let socket = wire::socket_path(home);
    if let Ok(stream) = UnixStream::connect(&socket).await {
        return Ok(stream);
    }
    start(home).await?;
    let mut last = String::new();
    for _ in 0..100 {
        match UnixStream::connect(&socket).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("cortexd did not come up at {}: {last}", socket.display()))
}

impl Daemon {
    /// Connect (starting the daemon when none answers) and say hello. A guest (the probe) sees
    /// only the terminals it opens; they end with its connection.
    pub async fn connect(home: &Path, guest: bool, on_message: OnMessage) -> Result<(Arc<Daemon>, Hello), String> {
        for _ in 0..2 {
            let (daemon, hello) = Self::hello(home, guest, on_message.clone()).await?;
            if guest || hello.version == wire::DAEMON_VERSION {
                return Ok((daemon, hello));
            }
            if hello.terms.iter().any(|t| t.alive) {
                tracing::info!(daemon = hello.version, ours = wire::DAEMON_VERSION, "cortexd of another version keeps its shells; using it");
                return Ok((daemon, hello));
            }
            tracing::info!(daemon = hello.version, ours = wire::DAEMON_VERSION, "replacing an idle cortexd of another version");
            if daemon.call::<Value>(Op::Quit).await.is_err() {
                return Ok((daemon, hello));
            }
            drop(daemon);
            let socket = wire::socket_path(home);
            for _ in 0..40 {
                if !socket.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        Self::hello(home, guest, on_message).await
    }

    async fn hello(home: &Path, guest: bool, on_message: OnMessage) -> Result<(Arc<Daemon>, Hello), String> {
        let stream = dial(home).await?;
        let (read, mut write) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(mut line) = rx.recv().await {
                line.push('\n');
                if write.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let waiting: Waiting = Arc::new(Mutex::new(HashMap::new()));
        let pending = waiting.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                match serde_json::from_str::<Message>(&line) {
                    Ok(Message::Reply { id, ok, error }) => {
                        if let Some(waiter) = lock(&pending).remove(&id) {
                            let _ = waiter.send(match error {
                                Some(error) => Err(error),
                                None => Ok(ok),
                            });
                        }
                    }
                    Ok(message) => on_message(Some(message)),
                    Err(error) => tracing::warn!("cortexd sent a bad message: {error}"),
                }
            }
            for (_, waiter) in lock(&pending).drain() {
                let _ = waiter.send(Err("cortexd closed the connection".into()));
            }
            on_message(None);
        });
        let mut daemon = Daemon { tx, waiting, next: AtomicU64::new(1), version: 0, pid: 0 };
        let hello: Hello = daemon.call(Op::Hello { guest }).await?;
        daemon.version = hello.version;
        daemon.pid = hello.pid;
        let daemon = Arc::new(daemon);
        Ok((daemon, hello))
    }

    /// Queue a request now (its place in line is taken here); await the answer later.
    pub fn request(&self, op: Op) -> oneshot::Receiver<Result<Value, String>> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (waiter, answer) = oneshot::channel();
        lock(&self.waiting).insert(id, waiter);
        match serde_json::to_string(&Request { id, op }) {
            Ok(line) => {
                if self.tx.send(line).is_err()
                    && let Some(waiter) = lock(&self.waiting).remove(&id)
                {
                    let _ = waiter.send(Err("not connected to cortexd".into()));
                }
            }
            Err(error) => {
                if let Some(waiter) = lock(&self.waiting).remove(&id) {
                    let _ = waiter.send(Err(error.to_string()));
                }
            }
        }
        answer
    }

    pub async fn answer<T: DeserializeOwned>(answer: oneshot::Receiver<Result<Value, String>>) -> Result<T, String> {
        let value = answer.await.map_err(|_| "cortexd closed the connection".to_owned())??;
        serde_json::from_value(value).map_err(|e| format!("cortexd answered something unexpected: {e}"))
    }

    pub async fn call<T: DeserializeOwned>(&self, op: Op) -> Result<T, String> {
        Self::answer(self.request(op)).await
    }
}
