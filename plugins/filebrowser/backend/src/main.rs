//! File Browser owns filesystem access; the window only hosts its UI slot.
use base64::Engine;
use cc_protocol::contracts::filebrowser::{self as wire, Chunk, Entry, ListParams, Listing, ReadParams, Saved, Transfer, UploadStart, UploadWrite, methods};
use cc_protocol::contracts::lifecycle::{Hello, ProbeCheck, ProbeReport};
use cc_protocol::{BoxFuture, Call, Ctx, Plugin, RpcError, parse_params, run_plugin, to_value};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn io_error(path: &Path, error: std::io::Error) -> RpcError {
    let code = match error.kind() {
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::AlreadyExists => "conflict",
        _ => "filesystem_error",
    };
    RpcError::new(code, format!("{}: {error}", path.display()))
}

fn cstr(name: &std::ffi::OsStr) -> Result<CString, RpcError> {
    CString::new(name.as_bytes()).map_err(|_| RpcError::invalid_params("file name contains NUL"))
}

/// Owned descriptor, opened without following a link at the final component.
fn open_at(dir: &File, name: &CStr, flags: i32) -> std::io::Result<File> {
    // SAFETY: the directory and name live throughout openat; a successful descriptor is owned.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NOFOLLOW, 0o600) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

struct Root {
    path: PathBuf,
    dir: File,
}
impl Root {
    fn new() -> Result<Self, RpcError> {
        let home = std::env::var_os("HOME").ok_or_else(|| RpcError::new("unavailable", "the serving user has no home folder"))?;
        let path = std::fs::canonicalize(home).map_err(|e| RpcError::new("unavailable", e.to_string()))?;
        let dir = File::open(&path).map_err(|e| io_error(&path, e))?;
        if !dir.metadata().map_err(|e| io_error(&path, e))?.is_dir() {
            return Err(RpcError::new("unavailable", "the home folder is not a directory"));
        }
        Ok(Self { path, dir })
    }

    fn resolve(&self, given: &str) -> Result<PathBuf, RpcError> {
        let path = if given.is_empty() || given == "~" {
            self.path.clone()
        } else if let Some(rest) = given.strip_prefix("~/") {
            self.path.join(rest)
        } else if Path::new(given).is_absolute() {
            PathBuf::from(given)
        } else {
            return Err(RpcError::invalid_params("use an absolute path or ~"));
        };
        let path = std::fs::canonicalize(&path).map_err(|e| io_error(&path, e))?;
        if !path.starts_with(&self.path) {
            return Err(RpcError::new("permission_denied", "this file browser stays inside the user's home folder"));
        }
        Ok(path)
    }

    /// Resolve links first, then walk the canonical relative path by descriptor. A link changed
    /// during the walk cannot redirect a read or an upload outside the opened home directory.
    fn open(&self, path: &Path, directory: bool) -> Result<File, RpcError> {
        let relative = path.strip_prefix(&self.path).map_err(|_| RpcError::invalid_params("path is outside home"))?;
        let components: Vec<_> = relative.components().collect();
        let mut current = open_at(&self.dir, c".", libc::O_RDONLY | libc::O_DIRECTORY).map_err(|e| io_error(path, e))?;
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(RpcError::invalid_params("invalid path component"));
            };
            let flags = libc::O_RDONLY | libc::O_NONBLOCK | if index + 1 < components.len() || directory { libc::O_DIRECTORY } else { 0 };
            current = open_at(&current, &cstr(name)?, flags).map_err(|e| io_error(path, e))?;
        }
        Ok(current)
    }

    fn list(&self, params: ListParams) -> Result<Listing, RpcError> {
        let path = self.resolve(&params.path)?;
        let dir = self.open(&path, true)?;
        // fdopendir takes ownership of its descriptor. Keep the directory used for child opens.
        let duplicate = open_at(&dir, c".", libc::O_RDONLY | libc::O_DIRECTORY).map_err(|e| io_error(&path, e))?;
        use std::os::fd::IntoRawFd;
        let fd = duplicate.into_raw_fd();
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(io_error(&path, error));
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Directory(stream);
        let mut entries = Vec::new();
        loop {
            // errno distinguishes end-of-directory from a failed read.
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error().unwrap_or(0) != 0 {
                    return Err(io_error(&path, error));
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." || (!params.show_hidden && bytes.starts_with(b".")) {
                continue;
            }
            // JSON paths cannot represent a non-UTF-8 filename faithfully. Display it disabled.
            let valid_name = std::str::from_utf8(bytes).is_ok();
            let name = String::from_utf8_lossy(bytes).into_owned();
            let child = path.join(std::ffi::OsStr::from_bytes(bytes));
            let symlink = std::fs::symlink_metadata(&child).is_ok_and(|m| m.file_type().is_symlink());
            let meta = child
                .to_str()
                .and_then(|p| self.resolve(p).ok())
                .and_then(|p| self.open(&p, false).ok())
                .and_then(|f| f.metadata().ok());
            let kind = match &meta {
                Some(m) if m.is_dir() => "directory",
                Some(m) if m.is_file() => "file",
                _ if symlink => "symlink",
                _ => "other",
            };
            entries.push(Entry {
                name,
                path: child.to_string_lossy().into_owned(),
                kind: kind.into(),
                symlink,
                bytes: meta.as_ref().map_or(0, |m| m.len()),
                modified: meta.as_ref().map_or(0, modified),
                accessible: valid_name && meta.as_ref().is_some_and(|m| m.is_dir() || m.is_file()),
            });
        }
        entries.sort_by(|a, b| {
            (a.kind != "directory")
                .cmp(&(b.kind != "directory"))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(Listing {
            home: self.path.to_string_lossy().into_owned(),
            parent: (path != self.path).then(|| path.parent().unwrap_or(&self.path).to_string_lossy().into_owned()),
            path: path.to_string_lossy().into_owned(),
            entries,
        })
    }

    fn read(&self, params: ReadParams) -> Result<Chunk, RpcError> {
        let path = self.resolve(&params.path)?;
        let mut file = self.open(&path, false)?;
        let meta = file.metadata().map_err(|e| io_error(&path, e))?;
        if !meta.is_file() {
            return Err(RpcError::invalid_params("only regular files can be downloaded"));
        }
        let stamp = stamp(&meta);
        if params.offset > meta.len() || (params.offset != 0 && params.stamp.is_none()) || params.stamp.as_ref().is_some_and(|expected| expected != &stamp) {
            return Err(RpcError::new("conflict", "the file changed during download; download it again"));
        }
        file.seek(SeekFrom::Start(params.offset)).map_err(|e| io_error(&path, e))?;
        let mut bytes = vec![0; (meta.len() - params.offset).min(wire::CHUNK_BYTES as u64) as usize];
        file.read_exact(&mut bytes).map_err(|e| io_error(&path, e))?;
        if stamp != self::stamp(&file.metadata().map_err(|e| io_error(&path, e))?) {
            return Err(RpcError::new("conflict", "the file changed during download; download it again"));
        }
        Ok(Chunk {
            offset: params.offset,
            bytes: meta.len(),
            stamp,
            eof: params.offset + bytes.len() as u64 == meta.len(),
            data: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }
}

fn modified(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64)
}
fn stamp(m: &std::fs::Metadata) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    )
}

struct Upload {
    dir: File,
    file: File,
    temporary: CString,
    name: CString,
    path: PathBuf,
    expected: u64,
    written: u64,
    touched: Instant,
}
impl Drop for Upload {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.dir.as_raw_fd(), self.temporary.as_ptr(), 0);
        }
    }
}

struct Browser {
    root: Root,
    uploads: Mutex<HashMap<String, Upload>>,
}
impl Browser {
    fn expire(&self) {
        self.uploads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, upload| upload.touched.elapsed() < Duration::from_secs(300));
    }
    fn dispatch(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.expire();
        match method {
            methods::LIST => to_value(&self.root.list(parse_params(params)?)?),
            methods::READ => to_value(&self.root.read(parse_params(params)?)?),
            methods::UPLOAD_START => {
                let p: UploadStart = parse_params(params)?;
                if p.name.is_empty() || p.name == "." || p.name == ".." || p.name.contains('/') || p.name.contains('\0') {
                    return Err(RpcError::invalid_params("upload needs a single file name"));
                }
                let directory = self.root.resolve(&p.directory)?;
                let dir = self.root.open(&directory, true)?;
                let name = cstr(std::ffi::OsStr::new(&p.name))?;
                let path = directory.join(&p.name);
                let mut meta: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut meta, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
                    return Err(RpcError::new(
                        "conflict",
                        format!("{} already exists; rename the local file before uploading", path.display()),
                    ));
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(io_error(&path, error));
                }
                let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
                if uploads.len() >= 8 {
                    return Err(RpcError::new("busy", "too many uploads; finish or cancel one first"));
                }
                let id = uuid::Uuid::new_v4().to_string();
                let temporary = CString::new(format!(".cortex-upload-{id}")).unwrap();
                let file = open_at(&dir, &temporary, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).map_err(|e| io_error(&path, e))?;
                uploads.insert(
                    id.clone(),
                    Upload {
                        dir,
                        file,
                        temporary,
                        name,
                        path,
                        expected: p.bytes,
                        written: 0,
                        touched: Instant::now(),
                    },
                );
                to_value(&Transfer { id })
            }
            methods::UPLOAD_WRITE => {
                let p: UploadWrite = parse_params(params)?;
                if p.data.len() > wire::CHUNK_BYTES.div_ceil(3) * 4 {
                    return Err(RpcError::invalid_params("upload chunk is too large"));
                }
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&p.data)
                    .map_err(|_| RpcError::invalid_params("invalid base64 chunk"))?;
                let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
                let upload = uploads
                    .get_mut(&p.id)
                    .ok_or_else(|| RpcError::new("not_found", "upload expired or was cancelled; upload it again"))?;
                if bytes.is_empty() || bytes.len() > wire::CHUNK_BYTES || p.offset != upload.written || bytes.len() as u64 > upload.expected - upload.written {
                    return Err(RpcError::invalid_params("upload chunk has the wrong offset or size"));
                }
                upload.file.write_all(&bytes).map_err(|e| io_error(&upload.path, e))?;
                upload.written += bytes.len() as u64;
                upload.touched = Instant::now();
                Ok(json!({ "bytes": upload.written }))
            }
            methods::UPLOAD_FINISH => {
                let p: Transfer = parse_params(params)?;
                let mut uploads = self.uploads.lock().unwrap_or_else(|e| e.into_inner());
                let upload = uploads
                    .remove(&p.id)
                    .ok_or_else(|| RpcError::new("not_found", "upload expired or was cancelled; upload it again"))?;
                if upload.written != upload.expected {
                    return Err(RpcError::new("conflict", "upload is incomplete"));
                }
                upload.file.sync_all().map_err(|e| io_error(&upload.path, e))?;
                // linkat publishes the complete file without ever replacing an existing name.
                if unsafe {
                    libc::linkat(
                        upload.dir.as_raw_fd(),
                        upload.temporary.as_ptr(),
                        upload.dir.as_raw_fd(),
                        upload.name.as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(io_error(&upload.path, std::io::Error::last_os_error()));
                }
                to_value(&Saved {
                    path: upload.path.to_string_lossy().into_owned(),
                    bytes: upload.written,
                })
            }
            methods::UPLOAD_CANCEL => {
                let p: Transfer = parse_params(params)?;
                self.uploads.lock().unwrap_or_else(|e| e.into_inner()).remove(&p.id);
                Ok(Value::Null)
            }
            _ => Err(RpcError::unknown_method(method)),
        }
    }
}

struct FileBrowser(Arc<Browser>);
impl Plugin for FileBrowser {
    fn handle(&self, _ctx: Ctx, call: Call) -> BoxFuture<'static, Result<Value, RpcError>> {
        let browser = self.0.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || browser.dispatch(&call.method, call.params))
                .await
                .map_err(|e| RpcError::internal(e.to_string()))?
        })
    }
    fn probe(&self, _ctx: Ctx) -> BoxFuture<'static, Result<ProbeReport, RpcError>> {
        let ok = self.0.root.dir.metadata().is_ok_and(|m| m.is_dir());
        Box::pin(async move {
            Ok(ProbeReport::from_checks(vec![ProbeCheck {
                name: "home folder".into(),
                ok,
                detail: "home-rooted filesystem access".into(),
                ms: 0,
            }]))
        })
    }
    fn shutdown(&self, _ctx: Ctx) -> BoxFuture<'static, ()> {
        self.0.uploads.lock().unwrap_or_else(|e| e.into_inner()).clear();
        Box::pin(async {})
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let root = match Root::new() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("cc-filebrowser: {error}");
            std::process::exit(1);
        }
    };
    let browser = Arc::new(Browser {
        root,
        uploads: Mutex::new(HashMap::new()),
    });
    let cleanup = browser.clone();
    let timer = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            cleanup.expire();
        }
    });
    let mut hello = Hello::new("cc-filebrowser", env!("CARGO_PKG_VERSION"), "filebrowser", "filebrowser@1");
    hello.provides = methods::ALL.iter().map(|m| (*m).to_owned()).collect();
    let plugin = Arc::new(FileBrowser(browser.clone()));
    let result = run_plugin(hello, plugin).await;
    timer.abort();
    browser.uploads.lock().unwrap_or_else(|e| e.into_inner()).clear();
    if let Err(error) = result {
        eprintln!("cc-filebrowser: {error}");
        std::process::exit(1);
    }
}
