//! Large files kept more than once: grouped by volume and size, hard links counted once, then a
//! BLAKE3 hash of the first and last 16 KB, then of the whole file. On APFS a copy's private size
//! (the blocks no clone or snapshot shares) is what removing it gives back, so copies that are
//! already clones of each other are not offered. Cleaning turns the copies into clones of the one
//! that stays: every path keeps its file, the space is shared. Elsewhere the copies go to the Trash.

use crate::walk::Big;
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const EDGE: u64 = 16 * 1024;

pub struct Set {
    pub hash: String,
    pub keep: PathBuf,
    pub copies: Vec<PathBuf>,
    pub len: u64,
    /// What turning the copies into clones (or removing them) gives back.
    pub reclaim: u64,
    pub newest_ms: u64,
}

fn edges(path: &Path, len: u64) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; EDGE as usize];
    let head = file.read(&mut buffer).ok()?;
    hasher.update(&buffer[..head]);
    if len > 2 * EDGE {
        file.seek(SeekFrom::End(-(EDGE as i64))).ok()?;
        file.read_exact(&mut buffer).ok()?;
        hasher.update(&buffer);
    }
    Some(hasher.finalize().to_hex().to_string())
}

pub fn full(path: &Path) -> Option<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(path).ok()?).ok()?;
    Some(hasher.finalize().to_hex().to_string())
}

/// Bytes only this file holds (APFS); its allocated size elsewhere.
pub fn private_size(path: &Path) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        #[repr(C)]
        struct AttrList {
            bitmapcount: u16,
            reserved: u16,
            commonattr: u32,
            volattr: u32,
            dirattr: u32,
            fileattr: u32,
            forkattr: u32,
        }
        const ATTR_BIT_MAP_COUNT: u16 = 5;
        const ATTR_CMNEXT_PRIVATESIZE: u32 = 0x8;
        const FSOPT_NOFOLLOW: u32 = 0x1;
        const FSOPT_ATTR_CMN_EXTENDED: u32 = 0x20;
        unsafe extern "C" {
            fn getattrlist(path: *const libc::c_char, list: *mut AttrList, buffer: *mut libc::c_void, size: libc::size_t, options: u32) -> libc::c_int;
        }
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let mut list = AttrList { bitmapcount: ATTR_BIT_MAP_COUNT, reserved: 0, commonattr: 0, volattr: 0, dirattr: 0, fileattr: 0, forkattr: ATTR_CMNEXT_PRIVATESIZE };
        let mut buffer = [0u8; 32];
        // SAFETY: the list and buffer outlive the call; the size passed is the buffer's.
        let ok = unsafe { getattrlist(name.as_ptr(), &mut list, buffer.as_mut_ptr().cast(), buffer.len(), FSOPT_NOFOLLOW | FSOPT_ATTR_CMN_EXTENDED) } == 0;
        // The reply: a u32 length, then the off_t.
        if ok && u32::from_ne_bytes(buffer[0..4].try_into().ok()?) >= 12 {
            return Some(i64::from_ne_bytes(buffer[4..12].try_into().ok()?).max(0) as u64);
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.blocks() * 512)
    }
}

/// Files with the same key, in groups of two or more.
fn group<K: std::hash::Hash + Eq + Send>(files: Vec<Big>, key: impl Fn(&Big) -> Option<K> + Sync) -> Vec<(K, Vec<Big>)> {
    let keyed: Vec<(K, Big)> = files.into_par_iter().filter_map(|file| key(&file).map(|k| (k, file))).collect();
    let mut groups: HashMap<K, Vec<Big>> = HashMap::new();
    for (k, file) in keyed {
        groups.entry(k).or_default().push(file);
    }
    groups.into_iter().filter(|(_, g)| g.len() > 1).collect()
}

pub fn find(files: Vec<Big>, stop: &std::sync::atomic::AtomicBool) -> Vec<Set> {
    // One entry per inode: a hard link is the same file.
    let mut seen = std::collections::HashSet::new();
    let files: Vec<Big> = files.into_iter().filter(|f| seen.insert((f.dev, f.ino))).collect();
    let mut out = Vec::new();
    for (_, by_size) in group(files, |f| Some((f.dev, f.len))) {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        for (_, by_edges) in group(by_size, |f| edges(&f.path, f.len)) {
            for (hash, mut same) in group(by_edges, |f| full(&f.path)) {
                // The oldest copy stays; the others share its blocks.
                same.sort_by_key(|f| f.mtime_ms);
                let keep = same.remove(0);
                let reclaim: u64 = same.iter().map(|f| private_size(&f.path).unwrap_or(f.len)).sum();
                if reclaim < 1024 * 1024 {
                    continue;
                }
                out.push(Set {
                    hash,
                    newest_ms: same.iter().map(|f| f.mtime_ms).max().unwrap_or(0),
                    len: keep.len,
                    keep: keep.path,
                    copies: same.into_iter().map(|f| f.path).collect(),
                    reclaim,
                });
            }
        }
    }
    out
}

/// Replace `copy` with an APFS clone of `keep`, after checking both still hold the same bytes.
/// The copy's permissions are kept; its own extended attributes become `keep`'s.
#[cfg(target_os = "macos")]
pub fn clone_over(keep: &Path, copy: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    unsafe extern "C" {
        fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32) -> libc::c_int;
    }
    const CLONE_NOFOLLOW: u32 = 0x1;
    let meta = std::fs::symlink_metadata(copy).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("the copy is no longer a plain file".into());
    }
    let same = full(keep);
    if same.is_none() || same != full(copy) {
        return Err("the files differ now".into());
    }
    let dir = copy.parent().ok_or("no folder")?;
    let temporary = dir.join(format!(".cortex-clone-{}", uuid::Uuid::new_v4().simple()));
    let src = std::ffi::CString::new(keep.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let dst = std::ffi::CString::new(temporary.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: two NUL-terminated paths that live through the call.
    if unsafe { clonefile(src.as_ptr(), dst.as_ptr(), CLONE_NOFOLLOW) } != 0 {
        return Err(format!("clonefile: {}", std::io::Error::last_os_error()));
    }
    let done = std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(meta.permissions().mode()))
        .and_then(|_| std::fs::rename(&temporary, copy));
    if let Err(error) = done {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}
