//! `terminal.file.read` / `terminal.file.write`: text files for the native editor. Saving is
//! atomic (a temporary file in the same folder, synced, the mode kept, renamed over the target;
//! a symbolic link is followed to its target) and never uses elevated rights.

use crate::assess::expand;
use cc_protocol::contracts::terminal::{FileReadParams, FileText, FileWriteParams, FileWritten};
use cc_protocol::{RpcError, codes};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The editor's limit; a bigger file opens read-only in a viewer.
const MAX_BYTES: u64 = 30 * 1024 * 1024;

fn modified_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// access(2) with the real user's rights.
fn can_write(path: &Path) -> bool {
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: access only reads the NUL-terminated path.
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

fn needs_admin(path: &Path) -> RpcError {
    RpcError::new("permission_denied", format!("{} is not writable by you; saving it needs admin", path.display()))
        .with_data(serde_json::json!({ "needs_admin": true }))
}

fn resolve(path: &str, cwd: Option<&str>) -> Result<PathBuf, RpcError> {
    if path.trim().is_empty() {
        return Err(RpcError::invalid_params("path is empty"));
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let base = cwd.filter(|c| !c.is_empty()).map(|c| expand(c, Path::new(&home))).unwrap_or_else(|| PathBuf::from(&home));
    let path = expand(path, &base);
    if !path.is_absolute() {
        return Err(RpcError::invalid_params(format!("`{}` is not an absolute path", path.display())));
    }
    Ok(path)
}

pub fn read(params: FileReadParams) -> Result<FileText, RpcError> {
    let path = resolve(&params.path, params.cwd.as_deref())?;
    let shown = path.to_string_lossy().into_owned();
    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let writable = path.parent().is_some_and(|dir| dir.is_dir() && can_write(dir));
            return Ok(FileText { path: shown, text: String::new(), exists: false, writable, modified: 0, bytes: 0, too_large: false });
        }
        Err(error) => return Err(RpcError::new(codes::CONFLICT, format!("{shown}: {error}"))),
    };
    if meta.is_dir() {
        return Err(RpcError::invalid_params(format!("{shown} is a folder")));
    }
    let mut text = FileText {
        path: shown.clone(),
        text: String::new(),
        exists: true,
        writable: can_write(&path),
        modified: modified_ms(&meta),
        bytes: meta.len(),
        too_large: meta.len() > MAX_BYTES,
    };
    if !text.too_large {
        let bytes = std::fs::read(&path).map_err(|e| RpcError::new(codes::CONFLICT, format!("{shown}: {e}")))?;
        match String::from_utf8(bytes) {
            Ok(content) => text.text = content,
            Err(_) => text.too_large = true,
        }
    }
    Ok(text)
}

pub fn write(params: FileWriteParams) -> Result<FileWritten, RpcError> {
    let given = resolve(&params.path, None)?;
    // A symbolic link is saved through: its target is the file replaced.
    let target = match std::fs::canonicalize(&given) {
        Ok(target) => target,
        Err(_) => given.clone(),
    };
    let dir = target.parent().ok_or_else(|| RpcError::invalid_params("no parent folder"))?.to_path_buf();
    if !dir.is_dir() {
        return Err(RpcError::new(codes::NOT_FOUND, format!("folder {} does not exist", dir.display())));
    }
    let existing = std::fs::metadata(&target).ok();
    if let Some(meta) = &existing {
        if meta.is_dir() {
            return Err(RpcError::invalid_params(format!("{} is a folder", target.display())));
        }
        if let Some(expected) = params.expected_modified
            && modified_ms(meta) != expected
        {
            return Err(RpcError::new(codes::CONFLICT, format!("{} changed on disk since it was opened", target.display())));
        }
        if !can_write(&target) {
            return Err(needs_admin(&target));
        }
    } else if !can_write(&dir) {
        return Err(needs_admin(&target));
    }
    let bytes = params.text.as_bytes();
    if can_write(&dir) {
        let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let temp = dir.join(format!(".{name}.cortexterm-{}.tmp", uuid::Uuid::new_v4().simple()));
        let saved = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
            file.write_all(bytes)?;
            let mode = existing.as_ref().map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o644);
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            std::fs::rename(&temp, &target)?;
            if let Ok(folder) = std::fs::File::open(&dir) {
                let _ = folder.sync_all();
            }
            Ok(())
        })();
        if let Err(error) = saved {
            let _ = std::fs::remove_file(&temp);
            return Err(RpcError::new(codes::CONFLICT, format!("cannot save {}: {error}", target.display())));
        }
    } else {
        // The file is writable but its folder is not: write it in place.
        let saved = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(&target)?;
            file.write_all(bytes)?;
            file.sync_all()
        })();
        saved.map_err(|e| RpcError::new(codes::CONFLICT, format!("cannot save {}: {e}", target.display())))?;
    }
    let meta = std::fs::metadata(&target).map_err(|e| RpcError::internal(e.to_string()))?;
    Ok(FileWritten { path: given.to_string_lossy().into_owned(), modified: modified_ms(&meta), bytes: meta.len() })
}
