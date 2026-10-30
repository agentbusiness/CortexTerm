//! The two Gemma 4 variants, their pinned files, and getting them onto disk in the shared models
//! folder (`cc_shared_models`): with the revision's download lock held, a file already there at
//! its pinned size (another app may have just fetched it) is used when its SHA-256 matches, else it
//! is downloaded with resume to `<file>.part`, checked, and renamed into place. Every check is
//! recorded beside the file in `<file>.digest`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct FileSpec {
    pub name: &'static str,
    pub bytes: u64,
    pub sha256: &'static str,
}

#[derive(Debug)]
pub struct Spec {
    pub id: &'static str,
    pub label: &'static str,
    pub tier: &'static str,
    pub repo: &'static str,
    pub revision: &'static str,
    pub quant: &'static str,
    pub weights: FileSpec,
    /// The MTP draft head (`--spec-type draft-mtp`).
    pub drafter: FileSpec,
    pub notes: &'static str,
}

pub const E4B: Spec = Spec {
    id: "gemma-4-e4b-qat",
    label: "Gemma 4 E4B (QAT, UD-Q4_K_XL, MTP drafts)",
    tier: "e4b",
    repo: "unsloth/gemma-4-E4B-it-qat-GGUF",
    revision: "8c5a9e4fd5482e2be20fe0bf013b4c262a8f4265",
    quant: "UD-Q4_K_XL",
    weights: FileSpec {
        name: "gemma-4-E4B-it-qat-UD-Q4_K_XL.gguf",
        bytes: 4_215_695_776,
        sha256: "df0fd4ee07072c607c29a0a1cb4f98918426cca12f45a2776bdd6ee6d09a4de3",
    },
    drafter: FileSpec {
        name: "mtp-gemma-4-E4B-it.gguf",
        bytes: 59_678_016,
        sha256: "423074e537504b4f9ec5eafed5c639fac82c96631626efccacdd3c4039b20605",
    },
    notes: "The default above 8 GB of memory (4.2 GB of weights, memory-mapped).",
};

pub const E2B: Spec = Spec {
    id: "gemma-4-e2b-qat",
    label: "Gemma 4 E2B (QAT, UD-Q4_K_XL, MTP drafts)",
    tier: "e2b",
    repo: "unsloth/gemma-4-E2B-it-qat-GGUF",
    revision: "66a399f68ddd113b06dff02fca9523e55465d11d",
    quant: "UD-Q4_K_XL",
    weights: FileSpec {
        name: "gemma-4-E2B-it-qat-UD-Q4_K_XL.gguf",
        bytes: 2_620_370_976,
        sha256: "e531007218dfab990486a5de7676a6932d6ea8dea233d1f698d7c21cf8a16889",
    },
    drafter: FileSpec {
        name: "mtp-gemma-4-E2B-it.gguf",
        bytes: 59_235_648,
        sha256: "586f2460b909008640981ec34060aa864e03c144fbabfb3173c4335087e4aae0",
    },
    notes: "The default on 8 GB Macs (2.6 GB of weights, memory-mapped).",
};

pub const CATALOG: [&Spec; 2] = [&E4B, &E2B];

pub fn find(id: &str) -> Option<&'static Spec> {
    CATALOG.into_iter().find(|spec| spec.id == id)
}

/// The variant for this machine: E4B above 8 GiB of memory, E2B at 8 GiB or less.
pub fn for_memory(physical_bytes: u64) -> &'static Spec {
    if physical_bytes > 8 << 30 { &E4B } else { &E2B }
}

impl Spec {
    /// `<models>/<org>-<repo>/<revision>`.
    pub fn dir(&self, models: &Path) -> PathBuf {
        models.join(self.repo.replace('/', "-")).join(self.revision)
    }

    pub fn files(&self) -> [FileSpec; 2] {
        [self.weights, self.drafter]
    }

    pub fn model_id(&self) -> String {
        format!("{}@{}:{}", self.repo, &self.revision[..7], self.quant)
    }

    fn url(&self, file: &FileSpec) -> String {
        format!("https://huggingface.co/{}/resolve/{}/{}", self.repo, self.revision, file.name)
    }
}

#[derive(Serialize, Deserialize, PartialEq)]
struct DigestRecord {
    bytes: u64,
    modified_ns: u128,
    sha256: String,
}

fn modified_ns(path: &Path) -> Option<u128> {
    std::fs::metadata(path).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_nanos())
}

fn digest_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".digest");
    path.with_file_name(name)
}

/// Whether `path` is the pinned file by its recorded check (no hashing).
fn recorded_ok(path: &Path, file: &FileSpec) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if meta.len() != file.bytes {
        return false;
    }
    let Some(record) = std::fs::read(digest_path(path)).ok().and_then(|b| serde_json::from_slice::<DigestRecord>(&b).ok()) else {
        return false;
    };
    record.bytes == file.bytes && Some(record.modified_ns) == modified_ns(path) && record.sha256 == file.sha256
}

fn record(path: &Path, sha256: &str) {
    if let (Ok(meta), Some(modified)) = (std::fs::metadata(path), modified_ns(path)) {
        let record = DigestRecord { bytes: meta.len(), modified_ns: modified, sha256: sha256.to_owned() };
        if let Ok(text) = serde_json::to_vec_pretty(&record) {
            let _ = std::fs::write(digest_path(path), text);
        }
    }
}

fn sha256_file(path: &Path, on_progress: &mut dyn FnMut(u64)) -> Result<String, String> {
    let mut input = std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 8 << 20];
    let mut done = 0u64;
    let mut last = Instant::now();
    loop {
        let read = input.read(&mut buffer).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        done += read as u64;
        if last.elapsed() >= Duration::from_millis(500) {
            on_progress(done);
            last = Instant::now();
        }
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Whether every file of the variant is in place and checked (by record, no hashing).
pub fn installed(spec: &Spec, models: &Path) -> bool {
    let dir = spec.dir(models);
    spec.files().iter().all(|file| recorded_ok(&dir.join(file.name), file))
}

/// `model.install` progress.
#[derive(Debug, Clone, Serialize)]
pub struct InstallProgress {
    pub variant: String,
    /// verify | download | done | failed
    pub phase: String,
    pub file: String,
    pub bytes: u64,
    pub total: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

pub type Report = std::sync::Arc<dyn Fn(InstallProgress) + Send + Sync>;

/// Make the variant present and checked under `models`. Returns its directory.
pub async fn install(spec: &'static Spec, models: PathBuf, report: Report) -> Result<PathBuf, String> {
    let dir = spec.dir(&models);
    let total: u64 = spec.files().iter().map(|f| f.bytes).sum();
    // Another app downloading the same revision holds the lock: wait for it, then look again.
    let failed = |e: std::io::Error| format!("cannot lock {}: {e}", dir.join(cc_shared_models::LOCK).display());
    let _lock = match cc_shared_models::try_lock(&dir).map_err(failed)? {
        Some(lock) => lock,
        None => {
            let detail = "waiting while another Cortex app downloads this model".to_owned();
            report(InstallProgress { variant: spec.id.into(), phase: "download".into(), file: String::new(), bytes: 0, total, detail });
            let locked = dir.clone();
            tokio::task::spawn_blocking(move || cc_shared_models::lock(&locked)).await.map_err(|e| e.to_string())?.map_err(failed)?
        }
    };
    let mut before = 0u64;
    for file in spec.files() {
        let target = dir.join(file.name);
        let say = {
            let report = report.clone();
            move |phase: &str, done: u64, detail: String| {
                report(InstallProgress {
                    variant: spec.id.into(),
                    phase: phase.into(),
                    file: file.name.into(),
                    bytes: before + done,
                    total,
                    detail,
                })
            }
        };
        if recorded_ok(&target, &file) {
            before += file.bytes;
            continue;
        }
        if std::fs::metadata(&target).is_ok_and(|m| m.len() == file.bytes) {
            if verify(&target, &say).await? == file.sha256 {
                record(&target, file.sha256);
                before += file.bytes;
                continue;
            }
            tracing::warn!(file = %target.display(), "a model file does not match its pinned digest; downloading it again");
            let _ = std::fs::remove_file(&target);
        }
        let part = dir.join(format!("{}.part", file.name));
        download(&spec.url(&file), &file, &part, &say).await?;
        let sha = verify(&part, &say).await?;
        if sha != file.sha256 {
            let _ = std::fs::remove_file(&part);
            let message = format!("{} has sha256 {sha}, expected {}", part.display(), file.sha256);
            say("failed", 0, message.clone());
            return Err(message);
        }
        std::fs::rename(&part, &target).map_err(|e| format!("cannot move {} into place: {e}", part.display()))?;
        record(&target, &sha);
        before += file.bytes;
    }
    report(InstallProgress { variant: spec.id.into(), phase: "done".into(), file: String::new(), bytes: total, total, detail: dir.display().to_string() });
    Ok(dir)
}

/// The SHA-256 of `path`, hashed on a blocking thread.
async fn verify(path: &Path, say: &(impl Fn(&str, u64, String) + Clone + Send + Sync + 'static)) -> Result<String, String> {
    let (path, say) = (path.to_path_buf(), say.clone());
    tokio::task::spawn_blocking(move || sha256_file(&path, &mut |done| say("verify", done, String::new()))).await.map_err(|e| e.to_string())?
}

/// Fetch `file` into `part`, resuming what an earlier attempt left there.
async fn download(url: &str, file: &FileSpec, part: &Path, say: &(dyn Fn(&str, u64, String) + Send + Sync)) -> Result<(), String> {
    use futures_util::StreamExt;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let have = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        if have > file.bytes {
            let _ = std::fs::remove_file(&part);
            continue;
        }
        if have == file.bytes {
            break;
        }
        let mut request = client.get(url);
        if have > 0 {
            request = request.header(reqwest::header::RANGE, format!("bytes={have}-"));
        }
        let outcome: Result<(), String> = async {
            let response = request.send().await.map_err(|e| format!("download request failed: {e}"))?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("download of {url} returned HTTP {status}"));
            }
            let resumed = status == reqwest::StatusCode::PARTIAL_CONTENT;
            let mut out = std::fs::OpenOptions::new()
                .create(true)
                .append(resumed)
                .write(true)
                .truncate(!resumed)
                .open(&part)
                .map_err(|e| format!("cannot write {}: {e}", part.display()))?;
            let mut written = if resumed { have } else { 0 };
            let mut stream = response.bytes_stream();
            let mut last = Instant::now();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| format!("download interrupted: {e}"))?;
                if chunk.len() as u64 > file.bytes - written {
                    return Err("the server sent more than the pinned file size".into());
                }
                out.write_all(&chunk).map_err(|e| format!("cannot write {}: {e}", part.display()))?;
                written += chunk.len() as u64;
                if last.elapsed() >= Duration::from_secs(1) {
                    say("download", written, String::new());
                    last = Instant::now();
                }
            }
            out.flush().map_err(|e| e.to_string())?;
            if written != file.bytes {
                return Err(format!("download ended at {written} of {} bytes", file.bytes));
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {}
            Err(error) if attempts < 20 => {
                say("download", have, format!("retrying after: {error}"));
                tokio::time::sleep(Duration::from_secs(u64::from(attempts.min(10)) * 2)).await;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
