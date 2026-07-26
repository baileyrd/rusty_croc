//! Port of `src/croc` — the client file-transfer engine (phase 2).
//!
//! Wire-compatible with croc v10 peers. The full flow over a relay room:
//!
//! 1. Both sides join the room `hex(sha256(secret[:4] + "croc"))` on the
//!    relay's main port; the recipient sends the raw frame `handshake`
//!    (the optional pake1/ips? local-discovery dance is answered by our
//!    sender for stock recipients, but our recipient does not initiate it).
//! 2. Peer PAKE: recipient (role 0) sends a `pake` message with its curve
//!    choice; sender (role 1) replies with its PAKE bytes and a fresh 8-byte
//!    salt. Both derive `Key = PBKDF2(pake session key, salt)`.
//! 3. Both connect to every advertised transfer port with room `{room}-{j}`.
//!    Recipient sends `externalip`; sender echoes; channel is "secured".
//! 4. Sender sends `fileinfo` (SenderInfo JSON). Recipient answers each file
//!    with `recipientready` (missing-chunk ranges for resume), data flows on
//!    the transfer connections as `encrypt(maybe_compress(u64_le_pos ‖ data))`
//!    in 32 KiB chunks striped round-robin across connections, then
//!    `close-sender`/`close-recipient` advance to the next file and a final
//!    `finished`/`finished` closes the transfer.
//!
//! Not yet ported from Go (see MIGRATION.md): local-network discovery +
//! local relay, reconnect-and-resume on dropped relays, zip-folder mode,
//! throttling, imohash/highway hashing, QR codes, clipboard.

use crate::comm::Comm;
use crate::crypt;
use crate::message::{self, Message};
use crate::models;
use crate::pake::Pake;
use crate::tcp;
use crate::utils;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

const CHUNK_SIZE: usize = models::TCP_BUFFER_SIZE / 2; // 32 KiB, matches Go
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Our reconnect protocol version (croc's `ReconnectVersion`).
pub const RECONNECT_VERSION: i64 = 1;
const MAX_RECONNECT_ATTEMPTS: usize = 10;
const RECONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// 100ms · 2^(n−1), capped at 5 s — mirrors `reconnectBackoff`.
fn reconnect_backoff(attempt: usize) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let mut delay = Duration::from_millis(100);
    for _ in 1..attempt {
        delay *= 2;
        if delay >= Duration::from_secs(5) {
            return Duration::from_secs(5);
        }
    }
    delay
}

/// Random 32-byte hex room for reconnects (`generateReconnectRoom`).
fn generate_reconnect_room() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Mirrors the parts of Go's `croc.Options` that are ported.
#[derive(Debug, Clone)]
pub struct Options {
    pub is_sender: bool,
    pub shared_secret: String,
    pub relay_address: String,
    pub relay_password: String,
    pub curve: String,
    pub hash_algorithm: String,
    pub no_prompt: bool,
    pub overwrite: bool,
    pub no_compress: bool,
    pub no_multiplexing: bool,
    /// Disable the local-network path entirely (croc's `--no-local`).
    pub disable_local: bool,
    /// Only use the local-network path (croc's `--local`).
    pub only_local: bool,
    /// Direct peer address for the recipient (croc's `--ip`).
    pub ip: String,
    /// Upload rate limit like "10M", "500K", "1G" (bytes/sec; croc's `--throttle`).
    pub throttle_upload: String,
    /// The payload is text to display, not a file to keep (croc's `--text`).
    pub sending_text: bool,
    /// Zip folders before sending (croc's `--zip`).
    pub zip_folder: bool,
    /// Skip files whose remote path contains any of these lowercase
    /// substrings (croc's `--exclude`).
    pub exclude: Vec<String>,
    /// Respect `.gitignore` when collecting files (croc's `--git`).
    pub git_ignore: bool,
    /// SOCKS5 proxy (host:port); non-local relays are dialed through it.
    pub socks5_proxy: String,
    /// HTTP CONNECT proxy (host:port).
    pub http_proxy: String,
    /// Resolve the relay hostname via hardcoded public DNS servers
    /// (croc's `--internal-dns`).
    pub internal_dns: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            is_sender: false,
            shared_secret: String::new(),
            relay_address: format!("{}:{}", models::DEFAULT_RELAY, models::DEFAULT_PORT),
            relay_password: models::DEFAULT_PASSPHRASE.to_string(),
            curve: "p256".to_string(),
            hash_algorithm: "xxhash".to_string(),
            no_prompt: false,
            overwrite: false,
            no_compress: false,
            no_multiplexing: false,
            disable_local: false,
            only_local: false,
            ip: String::new(),
            throttle_upload: String::new(),
            sending_text: false,
            zip_folder: false,
            exclude: Vec::new(),
            git_ignore: false,
            socks5_proxy: String::new(),
            http_proxy: String::new(),
            internal_dns: false,
        }
    }
}

/// Apply proxy options to the process-wide `comm` proxy config. Call once
/// before any relay connection.
fn apply_proxy_options(opts: &Options) {
    if !opts.socks5_proxy.is_empty() {
        crate::comm::set_socks5_proxy(&opts.socks5_proxy);
    }
    if !opts.http_proxy.is_empty() {
        crate::comm::set_http_proxy(&opts.http_proxy);
    }
}

/// Parse croc's throttle syntax ("10M", "500K", "2G", or plain bytes/sec).
fn parse_throttle(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last().unwrap() {
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'k' | 'K' => (&s[..s.len() - 1], 1024),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Simple shared token-bucket rate limiter for upload throttling.
struct Throttle {
    rate: u64, // bytes per second
    state: Mutex<(f64, std::time::Instant)>,
}

impl Throttle {
    fn new(rate: u64) -> Self {
        Throttle {
            rate,
            state: Mutex::new((rate as f64, std::time::Instant::now())),
        }
    }

    /// Block until `n` bytes may be sent.
    fn take(&self, n: usize) {
        loop {
            let wait = {
                let mut st = self.state.lock().unwrap();
                let now = std::time::Instant::now();
                let elapsed = now.duration_since(st.1).as_secs_f64();
                st.0 = (st.0 + elapsed * self.rate as f64).min(self.rate as f64);
                st.1 = now;
                if st.0 >= n as f64 {
                    st.0 -= n as f64;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        ((n as f64 - st.0) / self.rate as f64).min(1.0),
                    ))
                }
            };
            match wait {
                None => return,
                Some(d) => std::thread::sleep(d),
            }
        }
    }
}

fn b64ser<S: Serializer>(b: &Vec<u8>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64.encode(b))
}

fn b64de<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    let o: Option<String> = Option::deserialize(d)?;
    match o {
        Some(s) => BASE64.decode(s).map_err(serde::de::Error::custom),
        None => Ok(Vec::new()),
    }
}

/// Mirrors Go's `croc.FileInfo` JSON (`n`,`fr`,`fs`,`h`,`s`,`m`,`md`,…).
/// `ModTime` is carried as its RFC3339 string; this port sends the zero time
/// (Go peers then simply skip their optional chtimes on skipped files).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileInfo {
    #[serde(rename = "n", default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(rename = "fr", default, skip_serializing_if = "String::is_empty")]
    pub folder_remote: String,
    #[serde(rename = "fs", default, skip_serializing_if = "String::is_empty")]
    pub folder_source: String,
    #[serde(
        rename = "h",
        default,
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "b64ser",
        deserialize_with = "b64de"
    )]
    pub hash: Vec<u8>,
    #[serde(rename = "s", default, skip_serializing_if = "is_zero_i64")]
    pub size: i64,
    #[serde(rename = "m", default = "zero_time")]
    pub mod_time: String,
    #[serde(rename = "c", default, skip_serializing_if = "is_false")]
    pub is_compressed: bool,
    #[serde(rename = "e", default, skip_serializing_if = "is_false")]
    pub is_encrypted: bool,
    #[serde(rename = "sy", default, skip_serializing_if = "String::is_empty")]
    pub symlink: String,
    #[serde(rename = "md", default, skip_serializing_if = "is_zero_u32")]
    pub mode: u32,
    #[serde(rename = "tf", default, skip_serializing_if = "is_false")]
    pub temp_file: bool,
    #[serde(rename = "ig", default, skip_serializing_if = "is_false")]
    pub is_ignored: bool,
}

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}
fn is_false(b: &bool) -> bool {
    !*b
}
fn zero_time() -> String {
    ZERO_TIME.to_string()
}

/// Mirrors Go's `croc.SenderInfo` (field names are Go's, no tags upstream).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SenderInfo {
    #[serde(rename = "FilesToTransfer")]
    pub files_to_transfer: Option<Vec<FileInfo>>,
    #[serde(rename = "EmptyFoldersToTransfer")]
    pub empty_folders_to_transfer: Option<Vec<FileInfo>>,
    #[serde(rename = "TotalNumberFolders")]
    pub total_number_folders: i64,
    #[serde(rename = "MachineID")]
    pub machine_id: String,
    #[serde(rename = "Ask")]
    pub ask: bool,
    #[serde(rename = "SendingText")]
    pub sending_text: bool,
    #[serde(rename = "NoCompress")]
    pub no_compress: bool,
    #[serde(rename = "HashAlgorithm")]
    pub hash_algorithm: String,
    #[serde(rename = "ReconnectVersion")]
    pub reconnect_version: i64,
    #[serde(rename = "NextReconnectRoom")]
    pub next_reconnect_room: String,
}

/// Mirrors Go's `croc.RemoteFileRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RemoteFileRequest {
    #[serde(rename = "CurrentFileChunkRanges")]
    pub current_file_chunk_ranges: Option<Vec<i64>>,
    #[serde(rename = "FilesToTransferCurrentNum")]
    pub files_to_transfer_current_num: usize,
    #[serde(rename = "MachineID")]
    pub machine_id: String,
    #[serde(rename = "ReconnectVersion")]
    pub reconnect_version: i64,
}

/// Mirrors Go's `croc.SimpleMessage` (pre-transfer handshake envelope).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SimpleMessage {
    #[serde(
        rename = "Bytes",
        serialize_with = "b64ser",
        deserialize_with = "b64de"
    )]
    pub bytes: Vec<u8>,
    #[serde(rename = "Kind")]
    pub kind: String,
}

/// `host:port` with croc's default port filled in (`normalizeRelayAddress`).
fn normalize_relay_address(address: &str) -> String {
    if address.is_empty() {
        return String::new();
    }
    match address.rsplit_once(':') {
        Some((_, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            address.to_string()
        }
        _ => format!("{address}:{}", models::DEFAULT_PORT),
    }
}

/// Room name on the relay: `hex(sha256(secret[:4] + "croc"))`.
pub fn room_name(shared_secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(&shared_secret.as_bytes()[..4]);
    h.update(b"croc");
    hex_encode(&h.finalize())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The PAKE password is everything after the pin + dash (Go: `secret[5:]`).
fn pake_secret(shared_secret: &str) -> &[u8] {
    &shared_secret.as_bytes()[5..]
}

fn machine_id() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "rusty-croc".to_string())
}

// ---------------------------------------------------------------------------
// Path collection (sender side) — mirrors croc.GetFilesInfo (non-zip path).
// ---------------------------------------------------------------------------

fn file_info_from(path: &Path, folder_remote: String) -> Result<FileInfo> {
    let meta = std::fs::symlink_metadata(path)?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let abs = std::fs::canonicalize(parent)?;
    let mut fi = FileInfo {
        name: path
            .file_name()
            .ok_or("bad file name")?
            .to_string_lossy()
            .to_string(),
        folder_remote,
        folder_source: abs.to_string_lossy().to_string(),
        size: meta.len() as i64,
        mod_time: ZERO_TIME.to_string(),
        mode: mode_perm(&meta),
        ..Default::default()
    };
    if meta.file_type().is_symlink() {
        fi.symlink = std::fs::read_link(path)?.to_string_lossy().to_string();
    }
    Ok(fi)
}

#[cfg(unix)]
fn mode_perm(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_perm(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

fn walk_dir(
    base: &Path,
    dir: &Path,
    files: &mut Vec<FileInfo>,
    empty_folders: &mut Vec<FileInfo>,
    total_folders: &mut i64,
    ignored: &std::collections::HashSet<PathBuf>,
) -> Result<()> {
    *total_folders += 1;
    let base_parent = base.parent().unwrap_or(Path::new(""));
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    if entries.is_empty() && dir != base {
        let rel = dir.strip_prefix(base_parent).unwrap_or(dir);
        empty_folders.push(FileInfo {
            folder_remote: format!("{}/", rel.to_string_lossy().replace('\\', "/")),
            mod_time: ZERO_TIME.to_string(),
            ..Default::default()
        });
        return Ok(());
    }
    for entry in entries {
        let p = entry.path();
        if ignored.contains(&p) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&p)?;
        if meta.is_dir() {
            walk_dir(base, &p, files, empty_folders, total_folders, ignored)?;
        } else {
            let rel_dir = p
                .parent()
                .and_then(|d| d.strip_prefix(base_parent).ok())
                .unwrap_or(Path::new(""));
            let folder_remote = format!("{}/", rel_dir.to_string_lossy().replace('\\', "/"));
            files.push(file_info_from(&p, folder_remote)?);
        }
    }
    Ok(())
}

/// Absolute paths under `dir` excluded by .gitignore rules (used by `--git`).
/// The `ignore` crate walks with the same gitignore semantics git uses.
fn gitignored_paths(dir: &Path) -> std::collections::HashSet<PathBuf> {
    let mut included = std::collections::HashSet::new();
    for entry in ignore::WalkBuilder::new(dir)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        // Apply .gitignore rules even when the folder isn't a git repo,
        // matching croc's --git behavior (it compiles .gitignore directly).
        .require_git(false)
        .hidden(false)
        .parents(false)
        .build()
        .flatten()
    {
        if let Ok(abs) = std::fs::canonicalize(entry.path()) {
            included.insert(abs);
        }
    }
    // Everything present on disk but NOT in the gitignore-respecting walk is
    // ignored.
    let mut ignored = std::collections::HashSet::new();
    for entry in ignore::WalkBuilder::new(dir)
        .standard_filters(false)
        .hidden(false)
        .build()
        .flatten()
    {
        if let Ok(abs) = std::fs::canonicalize(entry.path()) {
            if !included.contains(&abs) {
                ignored.insert(abs);
            }
        }
    }
    ignored
}

/// Collect files/folders to send. Mirrors `croc.GetFilesInfo` without the
/// gitignore options.
pub fn get_files_info(paths: &[String]) -> Result<(Vec<FileInfo>, Vec<FileInfo>, i64)> {
    get_files_info_opts(paths, false, false)
}

pub fn get_files_info_opts(
    paths: &[String],
    zip_folder: bool,
    git_ignore: bool,
) -> Result<(Vec<FileInfo>, Vec<FileInfo>, i64)> {
    let mut files = Vec::new();
    let mut empty_folders = Vec::new();
    let mut total_folders = 0i64;
    let empty_ignored = std::collections::HashSet::new();
    for p in paths {
        let path = PathBuf::from(p);
        let meta =
            std::fs::symlink_metadata(&path).map_err(|e| format!("cannot access '{p}': {e}"))?;
        if meta.is_dir() && zip_folder {
            let abs = std::fs::canonicalize(&path)?;
            let dest = format!(
                "{}.zip",
                abs.file_name().unwrap_or_default().to_string_lossy()
            );
            if Path::new(&dest).exists() {
                return Err(format!("file already exists: {dest}").into());
            }
            eprintln!("Zipping {} to {dest}", path.display());
            zip_directory(Path::new(&dest), &abs)?;
            let mut fi = file_info_from(Path::new(&dest), "./".to_string())?;
            fi.temp_file = true;
            files.push(fi);
        } else if meta.is_dir() {
            let abs = std::fs::canonicalize(&path)?;
            let ignored = if git_ignore {
                gitignored_paths(&abs)
            } else {
                empty_ignored.clone()
            };
            walk_dir(
                &abs,
                &abs,
                &mut files,
                &mut empty_folders,
                &mut total_folders,
                &ignored,
            )?;
        } else {
            files.push(file_info_from(&path, "./".to_string())?);
        }
    }
    Ok((files, empty_folders, total_folders))
}

/// Drop files/folders whose remote path contains any exclusion (lowercase
/// substring match, like the post-walk filter in croc's cli.go). Recomputes
/// the folder count from what's left.
fn apply_exclusions(
    exclude: &[String],
    mut files: Vec<FileInfo>,
    mut empty_folders: Vec<FileInfo>,
    total_folders: i64,
) -> (Vec<FileInfo>, Vec<FileInfo>, i64) {
    if exclude.is_empty() {
        return (files, empty_folders, total_folders);
    }
    let matches = |fr: &str, name: &str| {
        let joined = format!("{}/{}", fr.to_lowercase(), name.to_lowercase())
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        exclude.iter().any(|e| joined.contains(e))
    };
    files.retain(|f| !matches(&f.folder_remote, &f.name));
    empty_folders.retain(|f| !matches(&f.folder_remote, &f.name));
    let mut folder_set = std::collections::HashSet::new();
    for f in files.iter().chain(empty_folders.iter()) {
        folder_set.insert(f.folder_remote.clone());
    }
    (files, empty_folders, folder_set.len() as i64)
}

/// Zip `src_dir` into `dest`, entries prefixed with the folder's base name —
/// the layout `utils.ZipDirectory` produces (stored, since croc compresses
/// in flight).
fn zip_directory(dest: &Path, src_dir: &Path) -> Result<()> {
    use zip::write::SimpleFileOptions;
    let base = src_dir
        .file_name()
        .ok_or("bad source dir")?
        .to_string_lossy()
        .to_string();
    let f = File::create(dest)?;
    let mut zw = zip::ZipWriter::new(f);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true);
    let mut stack = vec![src_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let p = entry.path();
            let rel = p.strip_prefix(src_dir).unwrap_or(&p);
            let name = format!("{base}/{}", rel.to_string_lossy().replace('\\', "/"));
            if p.is_dir() {
                zw.add_directory(format!("{name}/"), options)?;
                stack.push(p);
            } else {
                zw.start_file(name, options)?;
                let mut f = File::open(&p)?;
                std::io::copy(&mut f, &mut zw)?;
            }
        }
    }
    zw.finish()?;
    Ok(())
}

/// Safely extract a received zip into `dest`, mirroring `utils.UnzipDirectory`.
fn unzip_directory(dest: &Path, zip_path: &Path) -> Result<()> {
    let f = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(f)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let Some(rel) = entry.enclosed_name() else {
            return Err(format!("unsafe zip entry: {}", entry.name()).into());
        };
        let out = dest.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut of = File::create(&out)?;
        std::io::copy(&mut entry, &mut of)?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            set_perm(&out, mode);
        }
        eprintln!("{}", out.display());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Receive-side path validation — mirrors croc's normalizeReceiveFilePath.
// ---------------------------------------------------------------------------

fn is_local_receive_path(p: &str) -> bool {
    let p = p.replace('\\', "/");
    if p.starts_with('/') || p.contains(':') {
        return false;
    }
    !p.split('/').any(|part| part == "..")
}

fn normalize_receive_folder(folder: &str) -> Result<String> {
    let mut clean = folder.replace('\\', "/");
    while clean.starts_with("./") {
        clean = clean[2..].to_string();
    }
    clean = clean.trim_end_matches('/').to_string();
    if clean.is_empty() {
        clean = ".".to_string();
    }
    if !is_local_receive_path(&clean) {
        return Err(format!("filename must be a local path: '{folder}'").into());
    }
    if clean.contains(".ssh") {
        return Err(format!("invalid path detected: '{folder}'").into());
    }
    Ok(clean)
}

fn normalize_receive_file_path(folder: &str, name: &str) -> Result<(String, PathBuf)> {
    let clean_folder = normalize_receive_folder(folder)?;
    let clean_name = name.replace('\\', "/");
    if clean_name.is_empty() || clean_name.contains('/') || clean_name == "." || clean_name == ".."
    {
        return Err(format!("filename must be a local path: '{name}'").into());
    }
    let dest = Path::new(&clean_folder).join(&clean_name);
    Ok((clean_folder, dest))
}

// ---------------------------------------------------------------------------
// Shared receive state for the data-connection reader threads.
// ---------------------------------------------------------------------------

struct RecvState {
    file: Option<File>,
    path: PathBuf,
    size: i64,
    closed: bool,
    total_sent: i64,
    chunks_expected: usize,
    chunks_transferred: usize,
    no_compress: bool,
    sending_text: bool,
    last_pct: i64,
}

impl RecvState {
    fn new() -> Self {
        RecvState {
            file: None,
            path: PathBuf::new(),
            size: 0,
            closed: true,
            total_sent: 0,
            chunks_expected: 0,
            chunks_transferred: 0,
            no_compress: false,
            sending_text: false,
            last_pct: -1,
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.clear_key();
    }
}

/// A won connection route (local or remote relay) for the sender.
struct Route {
    control: Comm,
    banner: String,
    ipaddr: String,
    host: String,
    control_address: String,
}

/// Mirrors senderWaitForHandshake: answer optional `pake1`/`ips?` probes
/// from recipients doing local discovery, until `handshake` arrives.
/// `local_info` is the ips? reply: `[local-relay-port, ip1, ip2, ...]`.
fn sender_wait_for_handshake(
    control: &mut Comm,
    opts: &Options,
    local_info: &Option<Vec<String>>,
) -> Result<()> {
    let mut k_b: Option<Vec<u8>> = None;
    loop {
        let raw = control.receive()?;
        // If a session key exists, frames may be encrypted. Short frames
        // (`handshake`, `[1]`) fall through crypt's minimum-length check
        // unchanged — the same trick Go relies on.
        let data = match &k_b {
            Some(k) => match crypt::decrypt(&raw, k) {
                Ok(d) => d,
                Err(crypt::CryptError::TooShort) => raw.clone(),
                Err(_) => return Err("handshake decryption failed (wrong code?)".into()),
            },
            None => raw.clone(),
        };
        if data == b"handshake" {
            return Ok(());
        }
        if data == [1] {
            continue;
        }
        if data == b"ips?" {
            let reply = match local_info {
                Some(ips) => serde_json::to_vec(ips)?,
                None => b"null".to_vec(),
            };
            let enc = match &k_b {
                Some(k) => crypt::encrypt(&reply, k)?,
                None => return Err("ips? before pake".into()),
            };
            control.send(&enc)?;
            continue;
        }
        if let Ok(sm) = serde_json::from_slice::<SimpleMessage>(&data) {
            if sm.kind == "pake1" {
                let mut b = Pake::init_curve(pake_secret(&opts.shared_secret), 1, &opts.curve)?;
                b.update(&sm.bytes)?;
                k_b = Some(b.session_key()?);
                let reply = SimpleMessage {
                    bytes: b.bytes(),
                    kind: "pake2".to_string(),
                };
                control.send(&serde_json::to_vec(&reply)?)?;
                continue;
            }
        }
        return Err("gracefully refusing using the public relay".into());
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

pub struct Client {
    opts: Options,
    key: Option<Vec<u8>>,
    pake: Option<Pake>,
    control: Comm,
    control_tx: Arc<Mutex<Comm>>,
    relay_host: String,
    relay_ports: Vec<String>,
    room: String,
    external_ip: String,
    external_ip_connected: String,

    step1_channel_secured: bool,
    step2_file_info_transferred: bool,
    step3_recipient_request_file: bool,
    step4_file_transferring: bool,
    success: bool,

    files: Vec<FileInfo>,
    empty_folders: Vec<FileInfo>,
    total_folders: i64,
    files_finished: HashSet<usize>,
    current_num: usize,
    transferred_files: usize,

    // sender side
    data_conns: Vec<Arc<Mutex<Comm>>>,
    sender_threads: Vec<JoinHandle<Result<()>>>,
    chunk_map: HashSet<u64>,

    // recipient side
    recv: Arc<Mutex<RecvState>>,
    data_streams: Vec<std::net::TcpStream>,

    throttle: Option<Arc<Throttle>>,

    // reconnect support (croc ReconnectVersion 1)
    control_address: String,
    relay_candidates: Vec<String>,
    peer_reconnect_version: i64,
    next_reconnect_room: String,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Client {
    fn connect_relay(opts: &Options) -> Result<(Comm, String, String, String, String)> {
        let address = &opts.relay_address;
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => (h.to_string(), p.to_string()),
            _ => (address.to_string(), models::DEFAULT_PORT.to_string()),
        };
        // With --internal-dns, resolve the hostname to an IP via public DNS
        // servers so the transfer ports connect to the same resolved host.
        let host = if opts.internal_dns {
            match models::resolve_host(&host, true) {
                Some(ip) => {
                    log::debug!("internal-dns resolved {host} -> {ip}");
                    ip.to_string()
                }
                None => {
                    return Err(format!("internal-dns could not resolve {host}").into());
                }
            }
        } else {
            host
        };
        let full = format!("{host}:{port}");
        let room = room_name(&opts.shared_secret);
        let (comm, banner, ipaddr) = tcp::connect_to_tcp_server(
            &full,
            &opts.relay_password,
            &room,
            Some(Duration::from_secs(5)),
        )
        .map_err(|e| -> Error { format!("could not connect to {full}: {e}").into() })?;
        Ok((comm, banner, ipaddr, host, full))
    }

    fn new(
        opts: Options,
        control: Comm,
        banner: &str,
        ipaddr: String,
        host: String,
    ) -> Result<Self> {
        let mut relay_ports: Vec<String> = banner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if relay_ports.is_empty() {
            return Err(format!("relay banner has no transfer ports: '{banner}'").into());
        }
        if opts.no_multiplexing {
            relay_ports.truncate(1);
        }
        let control_tx = Arc::new(Mutex::new(control.try_clone()?));
        let room = room_name(&opts.shared_secret);
        Ok(Client {
            opts,
            key: None,
            pake: None,
            control,
            control_tx,
            relay_host: host,
            relay_ports,
            room,
            external_ip: ipaddr,
            external_ip_connected: String::new(),
            step1_channel_secured: false,
            step2_file_info_transferred: false,
            step3_recipient_request_file: false,
            step4_file_transferring: false,
            success: false,
            files: Vec::new(),
            empty_folders: Vec::new(),
            total_folders: 0,
            files_finished: HashSet::new(),
            current_num: 0,
            transferred_files: 0,
            data_conns: Vec::new(),
            sender_threads: Vec::new(),
            chunk_map: HashSet::new(),
            recv: Arc::new(Mutex::new(RecvState::new())),
            data_streams: Vec::new(),
            throttle: None,
            control_address: String::new(),
            relay_candidates: Vec::new(),
            peer_reconnect_version: 0,
            next_reconnect_room: String::new(),
        })
    }

    /// Remember where the control connection actually went (plus the
    /// originally configured relay) as reconnect candidates.
    fn set_relay_control_address(&mut self, address: &str) {
        self.control_address = address.to_string();
        let mut candidates = vec![address.to_string()];
        let original = normalize_relay_address(&self.opts.relay_address);
        if !original.is_empty() && original != address {
            candidates.push(original);
        }
        for existing in std::mem::take(&mut self.relay_candidates) {
            if !candidates.contains(&existing) {
                candidates.push(existing);
            }
        }
        self.relay_candidates = candidates;
    }

    /// Install a new transfer key, wiping any previous one.
    fn set_key(&mut self, key: Vec<u8>) {
        self.clear_key();
        self.key = Some(key);
    }

    /// Wipe the current transfer key from memory.
    fn clear_key(&mut self) {
        use zeroize::Zeroize;
        if let Some(k) = self.key.as_mut() {
            k.zeroize();
        }
        self.key = None;
    }

    fn send_msg(&self, m: &Message) -> Result<()> {
        let payload = message::encode(self.key.as_deref(), m)?;
        self.control_tx
            .lock()
            .unwrap()
            .send(&payload)
            .map_err(|e| -> Error { e.into() })
    }

    fn send_error(&self, text: &str) {
        let _ = self.send_msg(&Message {
            typ: message::TYPE_ERROR.to_string(),
            message: text.to_string(),
            ..Default::default()
        });
    }

    // -----------------------------------------------------------------------
    // Sender entry point — mirrors croc.Client.Send, racing the local-relay
    // route against the remote-relay route like Go's errchan pattern.
    // -----------------------------------------------------------------------
    pub fn send(opts: Options, paths: &[String]) -> Result<()> {
        apply_proxy_options(&opts);
        let (files, empty_folders, total_folders) =
            get_files_info_opts(paths, opts.zip_folder, opts.git_ignore)?;
        let (mut files, empty_folders, total_folders) =
            apply_exclusions(&opts.exclude, files, empty_folders, total_folders);
        let mut total_size = 0i64;
        for fi in files.iter_mut() {
            let full = Path::new(&fi.folder_source).join(&fi.name);
            if fi.symlink.is_empty() {
                fi.hash = utils::hash_file(&full, &opts.hash_algorithm)
                    .map_err(|e| -> Error { format!("hashing {}: {e}", full.display()).into() })?;
            } else {
                fi.hash = Sha256::digest(fi.symlink.as_bytes())[..].to_vec();
            }
            total_size += fi.size;
        }
        let fname = if files.len() == 1 {
            format!("'{}'", files[0].name)
        } else {
            format!("{} files", files.len())
        };
        eprintln!(
            "Sending {} ({})",
            fname,
            utils::byte_count_decimal(total_size)
        );
        eprintln!("Code is: {}", opts.shared_secret);
        eprintln!("\nOn the other computer run:\n\nrusty-croc {}\n(or with stock croc: CROC_SECRET={:?} croc)", opts.shared_secret, opts.shared_secret);

        // Set up the local relay + discovery broadcast, mirroring
        // setupLocalRelay/broadcastOnLocalNetwork.
        let stop_broadcast = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut local_info: Option<Vec<String>> = None;
        let mut local_port = String::new();
        if !opts.disable_local {
            let ports = utils::find_open_ports("127.0.0.1", 9009, 5);
            if ports.len() == 5 {
                local_port = ports[0].to_string();
                let banner: String = ports[1..]
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                for (i, port) in ports.iter().enumerate() {
                    let b = if i == 0 {
                        banner.clone()
                    } else {
                        String::new()
                    };
                    let pass = opts.relay_password.clone();
                    let port = port.to_string();
                    std::thread::spawn(move || {
                        let _ = tcp::RelayServer::new("0.0.0.0", &port, &pass, &b).run();
                    });
                }
                let mut ips = vec![local_port.clone()];
                ips.extend(utils::get_local_ips());
                local_info = Some(ips);

                let payload = format!("croc{local_port}").into_bytes();
                let time_limit = if opts.only_local {
                    None
                } else {
                    Some(Duration::from_secs(30))
                };
                // Announce on both IPv4 and IPv6 groups, like croc.
                let v4 = crate::discovery::Settings {
                    payload: payload.clone(),
                    time_limit,
                    ..Default::default()
                };
                let v6 = crate::discovery::ipv6_settings(payload, time_limit);
                for settings in [v4, v6] {
                    let stop = Arc::clone(&stop_broadcast);
                    std::thread::spawn(move || {
                        let _ = crate::discovery::broadcast(&settings, stop);
                    });
                }
            } else {
                log::debug!("not enough open ports for a local relay");
            }
        }

        // Race the routes; first successful handshake wins.
        let (tx, rx) = std::sync::mpsc::channel::<Result<Route>>();
        let route_streams: Arc<Mutex<Vec<std::net::TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let mut n_routes = 0;

        if !local_port.is_empty() {
            n_routes += 1;
            let opts2 = opts.clone();
            let tx2 = tx.clone();
            let local_info2 = local_info.clone();
            let streams = Arc::clone(&route_streams);
            let local_addr = format!("127.0.0.1:{local_port}");
            std::thread::spawn(move || {
                let result = (|| -> Result<Route> {
                    std::thread::sleep(Duration::from_millis(500));
                    let room = room_name(&opts2.shared_secret);
                    let (mut control, banner, ipaddr) =
                        tcp::connect_to_tcp_server(&local_addr, &opts2.relay_password, &room, None)
                            .map_err(|e| -> Error { format!("local relay: {e}").into() })?;
                    streams.lock().unwrap().push(control.stream().try_clone()?);
                    sender_wait_for_handshake(&mut control, &opts2, &local_info2)?;
                    log::debug!("sender using local relay route");
                    Ok(Route {
                        control,
                        banner,
                        ipaddr,
                        host: "127.0.0.1".to_string(),
                        control_address: local_addr.clone(),
                    })
                })();
                let _ = tx2.send(result);
            });
        }

        if !opts.only_local {
            n_routes += 1;
            let opts2 = opts.clone();
            let tx2 = tx.clone();
            let local_info2 = local_info.clone();
            let streams = Arc::clone(&route_streams);
            std::thread::spawn(move || {
                let result = (|| -> Result<Route> {
                    let (mut control, banner, ipaddr, host, control_address) =
                        Client::connect_relay(&opts2)?;
                    streams.lock().unwrap().push(control.stream().try_clone()?);
                    sender_wait_for_handshake(&mut control, &opts2, &local_info2)?;
                    log::debug!("sender using remote relay route");
                    Ok(Route {
                        control,
                        banner,
                        ipaddr,
                        host,
                        control_address,
                    })
                })();
                let _ = tx2.send(result);
            });
        }
        drop(tx);
        if n_routes == 0 {
            return Err("no transfer routes available (local disabled and only-local set?)".into());
        }

        let mut route: Option<Route> = None;
        let mut last_err: Error = "no routes completed".into();
        for _ in 0..n_routes {
            match rx.recv() {
                Ok(Ok(r)) => {
                    route = Some(r);
                    break;
                }
                Ok(Err(e)) => last_err = e,
                Err(_) => break,
            }
        }
        let route = match route {
            Some(r) => r,
            None => return Err(last_err),
        };
        // Cut off the losing route(s).
        {
            let winner = route.control.stream().peer_addr().ok();
            for s in route_streams.lock().unwrap().iter() {
                if s.peer_addr().ok() != winner {
                    let _ = s.shutdown(Shutdown::Both);
                }
            }
        }

        let throttle = parse_throttle(&opts.throttle_upload).map(|r| Arc::new(Throttle::new(r)));
        let mut c = Self::new(opts, route.control, &route.banner, route.ipaddr, route.host)?;
        c.set_relay_control_address(&route.control_address);
        c.throttle = throttle;
        c.files = files;
        c.empty_folders = empty_folders;
        c.total_folders = total_folders;

        let result = c.transfer_with_reconnect();
        stop_broadcast.store(true, std::sync::atomic::Ordering::Relaxed);
        c.shutdown();
        match &result {
            Ok(()) => {
                // Clean up temporary payloads (zip-folder mode, --text).
                for fi in &c.files {
                    if fi.temp_file {
                        let full = Path::new(&fi.folder_source).join(&fi.name);
                        eprintln!("Removing {}", fi.name);
                        let _ = std::fs::remove_file(full);
                    }
                }
            }
            Err(e) => c.send_error(&e.to_string()),
        }
        result
    }

    // -----------------------------------------------------------------------
    // Recipient entry point — mirrors croc.Client.Receive: multicast
    // discovery, then the relay, then the ips? probe to jump to the
    // sender's local relay when reachable.
    // -----------------------------------------------------------------------
    pub fn receive(mut opts: Options) -> Result<()> {
        apply_proxy_options(&opts);
        eprintln!("connecting...");
        let is_ip_set = !opts.ip.is_empty();
        let mut using_local = false;
        if is_ip_set {
            opts.relay_address = opts.ip.clone();
        } else if !opts.disable_local {
            // Look for a sender broadcasting on the local network.
            // Discover on both IPv4 and IPv6 groups concurrently, like croc.
            let v4 = crate::discovery::Settings {
                payload: b"ok".to_vec(),
                time_limit: Some(Duration::from_millis(200)),
                limit: Some(1),
                ..Default::default()
            };
            let v6 = crate::discovery::Settings {
                limit: Some(1),
                ..crate::discovery::ipv6_settings(b"ok".to_vec(), Some(Duration::from_millis(200)))
            };
            let handles: Vec<_> = [v4, v6]
                .into_iter()
                .map(|s| {
                    std::thread::spawn(move || crate::discovery::discover(&s).unwrap_or_default())
                })
                .collect();
            let mut discoveries = Vec::new();
            for h in handles {
                if let Ok(found) = h.join() {
                    discoveries.extend(found);
                }
            }
            {
                for d in discoveries {
                    if let Some(port) = d.payload.strip_prefix(b"croc") {
                        let port = String::from_utf8_lossy(port);
                        let port = if port.is_empty() {
                            models::DEFAULT_PORT.to_string()
                        } else {
                            port.to_string()
                        };
                        let address = format!("{}:{}", d.address, port);
                        if tcp::ping_server(&address).is_ok() {
                            log::debug!("switching to local relay {address}");
                            opts.relay_address = address;
                            using_local = true;
                            break;
                        }
                    }
                }
            }
        }
        if opts.only_local && !using_local && !is_ip_set {
            return Err("could not find sender on the local network (--local set)".into());
        }

        let (control, banner, ipaddr, host, control_address) = Self::connect_relay(&opts)?;
        let mut c = Self::new(opts, control, &banner, ipaddr, host)?;
        c.set_relay_control_address(&control_address);
        c.external_ip_connected = if using_local {
            c.opts.relay_address.clone()
        } else {
            String::new()
        };

        // The ips? probe: ask the sender (via the relay) for its local relay
        // candidates and switch to one if reachable. Mirrors the closure in
        // Go's Receive; failures are non-fatal.
        if !using_local && !is_ip_set && !c.opts.disable_local {
            if let Err(e) = c.try_local_probe() {
                log::debug!("local probe failed (continuing over relay): {e}");
            }
        }

        c.control.send(b"handshake")?;
        eprintln!("securing channel...");
        // Recipient initiates the peer PAKE (role 0) with its curve choice.
        let pake = Pake::init_curve(pake_secret(&c.opts.shared_secret), 0, &c.opts.curve)?;
        c.send_msg(&Message {
            typ: message::TYPE_PAKE.to_string(),
            bytes: pake.bytes(),
            bytes2: c.opts.curve.as_bytes().to_vec(),
            ..Default::default()
        })?;
        c.pake = Some(pake);
        let result = c.transfer_with_reconnect();
        c.shutdown();
        match &result {
            Ok(()) => {
                let sending_text = c.recv.lock().unwrap().sending_text;
                for fi in &c.files {
                    let (_, dest) = normalize_receive_file_path(&fi.folder_remote, &fi.name)?;
                    if fi.temp_file && fi.name.ends_with(".zip") {
                        // Zip-folder mode: unpack transferred archives.
                        if dest.exists() {
                            unzip_directory(Path::new("."), &dest)?;
                            let _ = std::fs::remove_file(&dest);
                        }
                    } else if sending_text {
                        // Text was printed during receive; drop the temp file.
                        let _ = std::fs::remove_file(&dest);
                    }
                }
            }
            Err(e) => c.send_error(&e.to_string()),
        }
        result
    }

    /// Recipient's `ips?` probe over the relay: run a SimpleMessage PAKE,
    /// ask the sender for its local relay `[port, ip...]`, and if one of the
    /// candidates answers, switch the control connection to it.
    fn try_local_probe(&mut self) -> Result<()> {
        let mut a = Pake::init_curve(pake_secret(&self.opts.shared_secret), 0, &self.opts.curve)?;
        let msg = SimpleMessage {
            bytes: a.bytes(),
            kind: "pake1".to_string(),
        };
        self.control.send(&serde_json::to_vec(&msg)?)?;
        let reply: SimpleMessage = serde_json::from_slice(&self.control.receive()?)?;
        if reply.kind != "pake2" {
            return Err(format!("expected pake2, got '{}'", reply.kind).into());
        }
        a.update(&reply.bytes)?;
        let k_a = a.session_key()?;

        self.control.send(&crypt::encrypt(b"ips?", &k_a)?)?;
        let enc = self.control.receive()?;
        let data = crypt::decrypt(&enc, &k_a)?;
        let ips: Vec<String> = serde_json::from_slice(&data).unwrap_or_default();
        log::debug!("sender's local candidates: {ips:?}");
        if ips.len() <= 1 {
            return Ok(());
        }
        let port = &ips[0];
        let room = room_name(&self.opts.shared_secret);
        for ip in &ips[1..] {
            let address = format!("{ip}:{port}");
            match tcp::connect_to_tcp_server(
                &address,
                &self.opts.relay_password,
                &room,
                Some(Duration::from_millis(500)),
            ) {
                Ok((conn, banner, ipaddr)) => {
                    log::debug!("local connection established to {address}");
                    let _ = self.control.stream().shutdown(Shutdown::Both);
                    self.control = conn;
                    self.control_tx = Arc::new(Mutex::new(self.control.try_clone()?));
                    self.set_relay_control_address(&address);
                    self.relay_host = ip.clone();
                    self.relay_ports = banner
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if self.opts.no_multiplexing {
                        self.relay_ports.truncate(1);
                    }
                    self.external_ip = ipaddr;
                    self.external_ip_connected = address;
                    return Ok(());
                }
                Err(e) => log::debug!("could not connect to {address}: {e}"),
            }
        }
        Ok(())
    }

    fn shutdown(&mut self) {
        for s in &self.data_streams {
            let _ = s.shutdown(Shutdown::Both);
        }
        while let Some(h) = self.sender_threads.pop() {
            let _ = h.join();
        }
    }

    // -----------------------------------------------------------------------
    // Reconnect-and-resume (croc ReconnectVersion 1): when a transfer drops
    // mid-flight and both peers advertise version ≥ 1, they meet again in a
    // pre-agreed random room (announced in each fileinfo) and resume — the
    // recipient's missing-chunk request naturally skips completed data.
    // -----------------------------------------------------------------------
    fn transfer_with_reconnect(&mut self) -> Result<()> {
        let mut last_disconnect: Option<String> = None;
        let mut attempt = 0usize;
        loop {
            if attempt > 0 {
                std::thread::sleep(reconnect_backoff(attempt));
                self.reset_for_reconnect()?;
                if let Err(e) = self.reconnect_relay_attempt() {
                    return Err(format!(
                        "{} (reconnect attempt {attempt} failed: {e})",
                        last_disconnect.unwrap_or_default()
                    )
                    .into());
                }
                if !self.opts.is_sender {
                    // Recipient re-initiates the PAKE, as in Receive().
                    let pake_bytes = self.pake.as_ref().map(|p| p.bytes()).unwrap_or_default();
                    self.send_msg(&Message {
                        typ: message::TYPE_PAKE.to_string(),
                        bytes: pake_bytes,
                        bytes2: self.opts.curve.as_bytes().to_vec(),
                        ..Default::default()
                    })?;
                }
            }
            match self.transfer_loop() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempt += 1;
                    if !self.can_retry(&e, attempt) {
                        return Err(e);
                    }
                    let role = if self.opts.is_sender {
                        "Sender"
                    } else {
                        "Receiver"
                    };
                    eprintln!("\n{role} detected a transfer interruption. Retrying securely...");
                    last_disconnect = Some(e.to_string());
                    self.close_attempt();
                }
            }
        }
    }

    /// Mirrors `canRetryTransfer`.
    fn can_retry(&self, e: &Error, attempt: usize) -> bool {
        !self.success
            && attempt <= MAX_RECONNECT_ATTEMPTS
            && self.peer_reconnect_version >= RECONNECT_VERSION
            && !self.next_reconnect_room.is_empty()
            && e.to_string().starts_with("transfer disconnected")
    }

    /// Mirrors `closeAttempt`: tear down every connection and open file.
    fn close_attempt(&mut self) {
        let _ = self.control.stream().shutdown(Shutdown::Both);
        for s in &self.data_streams {
            let _ = s.shutdown(Shutdown::Both);
        }
        while let Some(h) = self.sender_threads.pop() {
            let _ = h.join();
        }
        self.data_conns.clear();
        self.data_streams.clear();
        let mut st = self.recv.lock().unwrap();
        st.file = None;
        st.closed = true;
    }

    /// Mirrors `resetForReconnectAttempt`.
    fn reset_for_reconnect(&mut self) -> Result<()> {
        if self.next_reconnect_room.is_empty() {
            return Err("transfer disconnected: missing reconnect room".into());
        }
        self.room = self.next_reconnect_room.clone();
        self.step1_channel_secured = false;
        self.step2_file_info_transferred = false;
        self.step3_recipient_request_file = false;
        self.step4_file_transferring = false;
        self.success = false;
        self.clear_key();
        self.chunk_map.clear();
        {
            let mut st = self.recv.lock().unwrap();
            *st = RecvState::new();
        }
        if !self.opts.is_sender {
            self.pake = Some(Pake::init_curve(
                pake_secret(&self.opts.shared_secret),
                0,
                &self.opts.curve,
            )?);
        }
        Ok(())
    }

    /// Mirrors `reconnectRelayAttempt`: rejoin the reconnect room on the
    /// first reachable relay candidate and redo the pre-transfer handshake.
    fn reconnect_relay_attempt(&mut self) -> Result<()> {
        let room = self.next_reconnect_room.clone();
        let mut errors: Vec<String> = Vec::new();
        for address in self.relay_candidates.clone() {
            let connected = tcp::connect_to_tcp_server(
                &address,
                &self.opts.relay_password,
                &room,
                Some(Duration::from_secs(5)),
            );
            let (conn, banner, ipaddr) = match connected {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{address}: {e}"));
                    continue;
                }
            };
            let (conn, banner, ipaddr) = if self.opts.is_sender {
                // Wait for the recipient's `handshake` with an overall
                // deadline, like Go's 2s reconnect handshake window.
                let stream = conn.stream().try_clone()?;
                let opts = self.opts.clone();
                let (tx, rx) = std::sync::mpsc::channel();
                let mut moved = conn;
                std::thread::spawn(move || {
                    let r = sender_wait_for_handshake(&mut moved, &opts, &None);
                    let _ = tx.send((moved, r));
                });
                match rx.recv_timeout(RECONNECT_HANDSHAKE_TIMEOUT) {
                    Ok((conn, Ok(()))) => (conn, banner, ipaddr),
                    Ok((_, Err(e))) => {
                        errors.push(format!("{address}: {e}"));
                        continue;
                    }
                    Err(_) => {
                        let _ = stream.shutdown(Shutdown::Both);
                        errors.push(format!(
                            "{address}: timed out waiting for reconnect handshake"
                        ));
                        continue;
                    }
                }
            } else {
                let mut conn = conn;
                if let Err(e) = conn.send(b"handshake") {
                    errors.push(format!("{address}: {e}"));
                    continue;
                }
                (conn, banner, ipaddr)
            };
            log::debug!("reconnected via {address}");
            self.control = conn;
            self.control_tx = Arc::new(Mutex::new(self.control.try_clone()?));
            self.room = room;
            self.relay_host = address
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or(address.clone());
            self.relay_ports = banner
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if self.opts.no_multiplexing {
                self.relay_ports.truncate(1);
            }
            self.external_ip = ipaddr;
            self.set_relay_control_address(&address);
            return Ok(());
        }
        Err(format!("could not reconnect to any relay: {}", errors.join("; ")).into())
    }

    // -----------------------------------------------------------------------
    // The message loop — mirrors croc.Client.transfer + processMessage.
    // -----------------------------------------------------------------------
    fn transfer_loop(&mut self) -> Result<()> {
        let result = self.transfer_loop_inner();
        // Mirror Go's transfer(): errors after a successful transfer (e.g. the
        // peer's in-process local relay dying with it) are purged.
        if self.success {
            if let Err(e) = &result {
                log::debug!("purging error after successful transfer: {e}");
            }
            return Ok(());
        }
        result
    }

    fn transfer_loop_inner(&mut self) -> Result<()> {
        loop {
            let data = self.control.receive().map_err(|e| -> Error {
                if !self.step1_channel_secured {
                    "could not secure channel".into()
                } else {
                    format!("transfer disconnected: {e}").into()
                }
            })?;
            if data == [1] {
                continue; // relay keep-alive
            }
            let m = message::decode(self.key.as_deref(), &data)
                .map_err(|e| -> Error { format!("problem with decoding: {e}").into() })?;
            if m.typ != message::TYPE_PAKE && self.key.is_none() {
                return Err("unencrypted communication rejected".into());
            }
            match m.typ.as_str() {
                message::TYPE_FINISHED => {
                    let _ = self.send_msg(&Message {
                        typ: message::TYPE_FINISHED.to_string(),
                        ..Default::default()
                    });
                    self.success = true;
                    break;
                }
                message::TYPE_PAKE => self.process_pake(&m)?,
                message::TYPE_EXTERNAL_IP => {
                    if self.opts.is_sender {
                        self.send_msg(&Message {
                            typ: message::TYPE_EXTERNAL_IP.to_string(),
                            message: self.external_ip.clone(),
                            ..Default::default()
                        })?;
                    }
                    if self.external_ip_connected.is_empty() {
                        self.external_ip_connected = m.message.clone();
                    }
                    self.step1_channel_secured = true;
                }
                message::TYPE_ERROR => {
                    return Err(format!("peer error: {}", m.message).into());
                }
                message::TYPE_FILEINFO => {
                    if self.process_file_info(&m)? {
                        break;
                    }
                }
                message::TYPE_RECIPIENT_READY => self.process_recipient_ready(&m)?,
                message::TYPE_CLOSE_SENDER => {
                    // Recipient finished the current file; wind down our
                    // data threads and acknowledge.
                    while let Some(h) = self.sender_threads.pop() {
                        let _ = h.join();
                    }
                    self.step4_file_transferring = false;
                    self.step3_recipient_request_file = false;
                    self.send_msg(&Message {
                        typ: message::TYPE_CLOSE_RECIPIENT.to_string(),
                        ..Default::default()
                    })?;
                }
                message::TYPE_CLOSE_RECIPIENT => {
                    self.step4_file_transferring = false;
                    self.step3_recipient_request_file = false;
                }
                other => {
                    log::debug!("ignoring unknown message type: {other}");
                }
            }
            self.update_state()?;
        }
        Ok(())
    }

    /// Mirrors processMessagePake: derive the transfer key, open the data
    /// connections, and (recipient) start the reader threads.
    fn process_pake(&mut self, m: &Message) -> Result<()> {
        let salt;
        if self.opts.is_sender {
            let curve = String::from_utf8_lossy(&m.bytes2).to_string();
            log::debug!("using curve {curve}");
            let mut pake = Pake::init_curve(pake_secret(&self.opts.shared_secret), 1, &curve)?;
            pake.update(&m.bytes)
                .map_err(|e| -> Error { format!("pake not successful: {e}").into() })?;
            let mut s = vec![0u8; 8];
            rand::thread_rng().fill_bytes(&mut s);
            salt = s;
            // Reply (unencrypted — the peer has no key yet).
            self.send_msg(&Message {
                typ: message::TYPE_PAKE.to_string(),
                bytes: pake.bytes(),
                bytes2: salt.clone(),
                ..Default::default()
            })?;
            self.pake = Some(pake);
        } else {
            let pake = self.pake.as_mut().ok_or("pake not initialized")?;
            pake.update(&m.bytes)
                .map_err(|e| -> Error { format!("pake not successful: {e}").into() })?;
            salt = m.bytes2.clone();
        }
        let mut session = self.pake.as_ref().unwrap().session_key()?;
        let (key, _) = crypt::new_key(&session, Some(&salt))?;
        log::debug!("generated transfer key with salt {salt:02x?}");
        use zeroize::Zeroize;
        session.zeroize();
        self.set_key(key);

        // Connect to every transfer port (room "{room}-{j}") in parallel,
        // matching Go's goroutine fan-out. Each connection runs its own SIEC
        // relay handshake; doing them sequentially would serialize N slow
        // PAKEs and dominate startup latency. The relay pairs peers by room
        // name, so arrival order doesn't matter.
        let n = self.relay_ports.len();
        let mut handles = Vec::with_capacity(n);
        for j in 0..n {
            let server = format!("{}:{}", self.relay_host, self.relay_ports[j]);
            let pass = self.opts.relay_password.clone();
            let room = format!("{}-{}", self.room, j);
            handles.push(std::thread::spawn(move || -> Result<Comm> {
                let (conn, _, _) = tcp::connect_to_tcp_server(
                    &server,
                    &pass,
                    &room,
                    Some(Duration::from_secs(10)),
                )
                .map_err(|e| -> Error {
                    format!("could not connect transfer port {server}: {e}").into()
                })?;
                Ok(conn)
            }));
        }
        // Collect in index order so the "{room}-{j}" ↔ stripe mapping holds.
        let mut conns = Vec::with_capacity(n);
        for h in handles {
            let conn = h
                .join()
                .map_err(|_| -> Error { "transfer-port connect thread panicked".into() })??;
            conns.push(conn);
        }
        for conn in conns {
            self.data_streams.push(conn.stream().try_clone()?);
            if self.opts.is_sender {
                self.data_conns.push(Arc::new(Mutex::new(conn)));
            } else {
                // Recipient: persistent reader thread per data connection.
                let recv = Arc::clone(&self.recv);
                let key = self.key.clone().unwrap();
                let control_tx = Arc::clone(&self.control_tx);
                std::thread::spawn(move || receive_data_loop(conn, key, recv, control_tx));
            }
        }
        if !self.opts.is_sender {
            self.send_msg(&Message {
                typ: message::TYPE_EXTERNAL_IP.to_string(),
                message: self.external_ip.clone(),
                bytes: m.bytes.clone(),
                ..Default::default()
            })?;
        }
        Ok(())
    }

    /// Recipient: mirrors processMessageFileInfo.
    /// Returns true when the whole transfer is already complete.
    fn process_file_info(&mut self, m: &Message) -> Result<bool> {
        let si: SenderInfo = serde_json::from_slice(&m.bytes)?;
        self.opts.no_compress = si.no_compress;
        self.opts.hash_algorithm = if si.hash_algorithm.is_empty() {
            "xxhash".to_string()
        } else {
            si.hash_algorithm.clone()
        };
        {
            let mut st = self.recv.lock().unwrap();
            st.no_compress = si.no_compress;
            st.sending_text = si.sending_text;
        }
        self.peer_reconnect_version = si.reconnect_version;
        self.next_reconnect_room = si.next_reconnect_room.clone();
        self.total_folders = si.total_number_folders;
        let mut files = si.files_to_transfer.unwrap_or_default();
        // Mirror Go: text payloads named croc-stdin-* get a random local name
        // so they never collide with an existing temp file (e.g. the sender's
        // own, when both run in one directory).
        if si.sending_text {
            for fi in files.iter_mut() {
                if fi.name.starts_with("croc-stdin-") {
                    fi.name = format!("croc-text-{}", rand::random::<u32>());
                }
            }
        }
        // Validate every destination before accepting anything.
        for fi in &files {
            normalize_receive_file_path(&fi.folder_remote, &fi.name)?;
        }
        let empty_folders = si.empty_folders_to_transfer.unwrap_or_default();
        for fi in &empty_folders {
            normalize_receive_folder(&fi.folder_remote)?;
        }

        let total_size: i64 = files.iter().map(|f| f.size).sum();
        let fname = if files.len() == 1 {
            format!("'{}'", files[0].name)
        } else {
            format!("{} files", files.len())
        };
        if !self.opts.no_prompt || si.ask {
            eprint!(
                "Accept {} ({})? (Y/n) ",
                fname,
                utils::byte_count_decimal(total_size)
            );
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let choice = line.trim().to_lowercase();
            if !choice.is_empty() && choice != "y" && choice != "yes" {
                self.send_error("refusing files");
                return Err("refused files".into());
            }
        } else {
            eprintln!(
                "Receiving {} ({})",
                fname,
                utils::byte_count_decimal(total_size)
            );
        }

        for fi in &empty_folders {
            let folder = normalize_receive_folder(&fi.folder_remote)?;
            if !Path::new(&folder).exists() {
                std::fs::create_dir_all(&folder)?;
                eprintln!("{folder}/");
            }
        }

        self.files = files;
        self.empty_folders = empty_folders;
        if self.files.is_empty() {
            self.success = true;
            self.step3_recipient_request_file = true;
            self.step4_file_transferring = true;
            self.send_msg(&Message {
                typ: message::TYPE_FINISHED.to_string(),
                ..Default::default()
            })?;
        }
        self.step2_file_info_transferred = true;
        Ok(false)
    }

    /// Sender: mirrors the TypeRecipientReady branch.
    fn process_recipient_ready(&mut self, m: &Message) -> Result<()> {
        while let Some(h) = self.sender_threads.pop() {
            let _ = h.join();
        }
        let req: RemoteFileRequest = serde_json::from_slice(&m.bytes)?;
        self.peer_reconnect_version = req.reconnect_version;
        self.current_num = req.files_to_transfer_current_num;
        let ranges = req.current_file_chunk_ranges.unwrap_or_default();
        let chunks = utils::chunk_ranges_to_chunks(&ranges);
        self.chunk_map = chunks.iter().map(|&c| c as u64).collect();
        self.step3_recipient_request_file = true;
        Ok(())
    }

    /// Mirrors updateState: advance whichever step is now unblocked.
    fn update_state(&mut self) -> Result<()> {
        // Sender: channel secured → send the file manifest.
        if self.opts.is_sender && self.step1_channel_secured && !self.step2_file_info_transferred {
            // Each manifest announces a fresh rendezvous room for reconnects.
            self.next_reconnect_room = generate_reconnect_room();
            let si = SenderInfo {
                files_to_transfer: if self.files.is_empty() {
                    None
                } else {
                    Some(self.files.clone())
                },
                empty_folders_to_transfer: if self.empty_folders.is_empty() {
                    None
                } else {
                    Some(self.empty_folders.clone())
                },
                total_number_folders: self.total_folders,
                machine_id: machine_id(),
                hash_algorithm: self.opts.hash_algorithm.clone(),
                no_compress: self.opts.no_compress,
                sending_text: self.opts.sending_text,
                reconnect_version: RECONNECT_VERSION,
                next_reconnect_room: self.next_reconnect_room.clone(),
                ..Default::default()
            };
            self.send_msg(&Message {
                typ: message::TYPE_FILEINFO.to_string(),
                bytes: serde_json::to_vec(&si)?,
                ..Default::default()
            })?;
            self.step2_file_info_transferred = true;
        }

        // Recipient: manifest received and no active file → pick next file.
        if !self.opts.is_sender
            && self.step2_file_info_transferred
            && !self.step3_recipient_request_file
        {
            self.recipient_next_file()?;
        }

        // Sender: recipient asked for a file → stream it.
        if self.opts.is_sender && self.step3_recipient_request_file && !self.step4_file_transferring
        {
            self.step4_file_transferring = true;
            self.spawn_send_data()?;
        }
        Ok(())
    }

    /// Recipient: mirrors updateIfRecipientHasFileInfo + recipientGetFileReady.
    fn recipient_next_file(&mut self) -> Result<()> {
        let mut finished = true;
        let mut ranges: Vec<i64> = Vec::new();
        for i in 0..self.files.len() {
            if self.files_finished.contains(&i) || i < self.current_num {
                continue;
            }
            let fi = self.files[i].clone();
            let (folder, dest) = normalize_receive_file_path(&fi.folder_remote, &fi.name)?;

            // Zero-byte files and symlinks are created directly.
            if fi.size == 0 || !fi.symlink.is_empty() {
                if folder != "." {
                    std::fs::create_dir_all(&folder)?;
                }
                if !fi.symlink.is_empty() {
                    make_symlink(&fi.symlink, &dest)?;
                } else {
                    File::create(&dest)?;
                }
                self.files_finished.insert(i);
                self.transferred_files += 1;
                eprintln!("{}", dest.display());
                continue;
            }

            // Same-size local file: hash to decide skip / resume.
            let local_hash = match std::fs::metadata(&dest) {
                Ok(meta) if meta.len() as i64 == fi.size => {
                    utils::hash_file(&dest, &self.opts.hash_algorithm).ok()
                }
                _ => None,
            };
            if let Some(h) = &local_hash {
                if *h == fi.hash {
                    log::debug!("{} already complete", dest.display());
                    self.files_finished.insert(i);
                    continue;
                }
                // Existing file with same size but different content.
                if !self.opts.overwrite {
                    eprint!(
                        "\nOverwrite/resume '{}'? (y/N) (use --overwrite to omit) ",
                        dest.display()
                    );
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    let choice = line.trim().to_lowercase();
                    if choice != "y" && choice != "yes" {
                        eprintln!("Skipping '{}'", dest.display());
                        self.files_finished.insert(i);
                        continue;
                    }
                }
                ranges = utils::missing_chunks(&dest, fi.size, CHUNK_SIZE);
            }

            // This is the next file to receive.
            finished = false;
            self.current_num = i;
            self.transferred_files += 1;
            if folder != "." {
                std::fs::create_dir_all(&folder)?;
            }
            let file = open_receive_file(&dest, &fi)?;
            {
                let mut st = self.recv.lock().unwrap();
                st.file = Some(file);
                st.path = dest.clone();
                st.size = fi.size;
                st.closed = false;
                st.total_sent = 0;
                st.chunks_expected = utils::chunk_ranges_to_chunks(&ranges).len();
                st.chunks_transferred = 0;
                st.last_pct = -1;
            }
            break;
        }

        if finished {
            self.send_msg(&Message {
                typ: message::TYPE_FINISHED.to_string(),
                ..Default::default()
            })?;
            self.success = true;
            self.files_finished.insert(self.current_num);
            return Ok(());
        }

        let req = RemoteFileRequest {
            current_file_chunk_ranges: Some(ranges),
            files_to_transfer_current_num: self.current_num,
            machine_id: machine_id(),
            reconnect_version: RECONNECT_VERSION,
        };
        eprintln!(
            "Receiving {} ({})",
            self.files[self.current_num].name,
            utils::byte_count_decimal(self.files[self.current_num].size)
        );
        self.send_msg(&Message {
            typ: message::TYPE_RECIPIENT_READY.to_string(),
            bytes: serde_json::to_vec(&req)?,
            ..Default::default()
        })?;
        self.step3_recipient_request_file = true;
        Ok(())
    }

    /// Sender: mirrors the sendData goroutines — stripe chunks round-robin
    /// across the data connections, honoring a resume chunk map.
    fn spawn_send_data(&mut self) -> Result<()> {
        let fi = &self.files[self.current_num];
        let path = Path::new(&fi.folder_source).join(&fi.name);
        let size = fi.size;
        let nconns = self.data_conns.len();
        eprintln!("Sending {} ({})", fi.name, utils::byte_count_decimal(size));

        // Precompute each connection's chunk list (position, length).
        let mut assignments: Vec<Vec<(u64, usize)>> = vec![Vec::new(); nconns];
        let mut pos: u64 = 0;
        let mut idx: usize = 0;
        while (pos as i64) < size {
            let len = std::cmp::min(CHUNK_SIZE as i64, size - pos as i64) as usize;
            let wanted = self.chunk_map.is_empty() || self.chunk_map.contains(&pos);
            if wanted {
                assignments[idx % nconns].push((pos, len));
            }
            pos += len as u64;
            idx += 1;
        }

        let key = self.key.clone().ok_or("no key")?;
        let no_compress = self.opts.no_compress;
        let started = now_secs();
        for (i, chunk_list) in assignments.into_iter().enumerate() {
            let conn = Arc::clone(&self.data_conns[i]);
            let key = key.clone();
            let path = path.clone();
            let throttle = self.throttle.clone();
            self.sender_threads.push(std::thread::spawn(move || {
                let mut f = File::open(&path)
                    .map_err(|e| -> Error { format!("open {}: {e}", path.display()).into() })?;
                let mut conn = conn.lock().unwrap();
                let mut buf = vec![0u8; CHUNK_SIZE];
                for (pos, len) in chunk_list {
                    f.seek(SeekFrom::Start(pos))?;
                    f.read_exact(&mut buf[..len])?;
                    if let Some(t) = &throttle {
                        t.take(len);
                    }
                    let mut payload = Vec::with_capacity(8 + len);
                    payload.extend_from_slice(&pos.to_le_bytes());
                    payload.extend_from_slice(&buf[..len]);
                    let framed = if no_compress {
                        crypt::encrypt(&payload, &key)?
                    } else {
                        crypt::encrypt(&crate::compress::compress(&payload), &key)?
                    };
                    conn.send(&framed)?;
                }
                Ok(())
            }));
        }
        log::debug!(
            "spawned {} sender threads at t={}",
            self.data_conns.len(),
            started
        );
        Ok(())
    }
}

fn make_symlink(_target: &str, dest: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dest).is_ok() {
        std::fs::remove_file(dest)?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(_target, dest)?;
    #[cfg(not(unix))]
    return Err("symlinks not supported on this platform".into());
    #[cfg(unix)]
    Ok(())
}

fn open_receive_file(dest: &Path, fi: &FileInfo) -> Result<File> {
    // Refuse to write through a symlink, mirroring rejectSymlinkDestination.
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            return Err(
                format!("refusing to open symlink destination: '{}'", dest.display()).into(),
            );
        }
    }
    let file = match std::fs::OpenOptions::new().write(true).open(dest) {
        Ok(f) => {
            let need_truncate = f
                .metadata()
                .map(|m| m.len() as i64 != fi.size)
                .unwrap_or(true);
            if need_truncate {
                f.set_len(fi.size as u64)?;
            }
            f
        }
        Err(_) => {
            let f = File::create(dest)?;
            f.set_len(fi.size as u64)?;
            set_perm(dest, fi.mode);
            f
        }
    };
    Ok(file)
}

#[cfg(unix)]
fn set_perm(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if mode & 0o777 != 0 {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777));
    }
}

#[cfg(not(unix))]
fn set_perm(_path: &Path, _mode: u32) {}

/// Recipient data-connection reader — mirrors croc.Client.receiveData.
fn receive_data_loop(
    mut conn: Comm,
    key: Vec<u8>,
    recv: Arc<Mutex<RecvState>>,
    control_tx: Arc<Mutex<Comm>>,
) {
    loop {
        let data = match conn.receive() {
            Ok(d) => d,
            Err(_) => return,
        };
        if data == [1] {
            continue;
        }
        let data = match crypt::decrypt(&data, &key) {
            Ok(d) => d,
            Err(e) => {
                log::debug!("data decrypt error: {e}");
                return;
            }
        };
        let mut st = recv.lock().unwrap();
        let data = if st.no_compress {
            data
        } else {
            crate::compress::decompress(&data)
        };
        if data.len() < 8 {
            log::debug!("short data frame");
            return;
        }
        let pos = u64::from_le_bytes(data[..8].try_into().unwrap());
        if st.closed || st.file.is_none() {
            log::debug!("chunk arrived for closed file");
            return;
        }
        if let Err(e) = write_at(st.file.as_mut().unwrap(), &data[8..], pos) {
            log::debug!("write error: {e}");
            return;
        }
        st.total_sent += (data.len() - 8) as i64;
        st.chunks_transferred += 1;
        let pct = if st.size > 0 {
            st.total_sent * 100 / st.size
        } else {
            100
        };
        if pct / 10 > st.last_pct / 10 {
            eprint!("\r{:3}%", pct.min(100));
            st.last_pct = pct;
        }
        let complete =
            !st.closed && (st.chunks_transferred == st.chunks_expected || st.total_sent == st.size);
        if complete {
            st.closed = true;
            let path = st.path.clone();
            let sending_text = st.sending_text;
            st.file = None; // drop → close
            eprintln!("\r100% {}", path.display());
            if sending_text {
                // Print now; the temp file itself is removed in the
                // end-of-transfer cleanup (deleting it here would make the
                // next-file scan re-request it forever, mirroring Go).
                if let Ok(text) = std::fs::read_to_string(&path) {
                    print!("{text}");
                    let _ = std::io::stdout().flush();
                }
            }
            drop(st);
            let payload = match message::encode(
                Some(&key),
                &Message {
                    typ: message::TYPE_CLOSE_SENDER.to_string(),
                    ..Default::default()
                },
            ) {
                Ok(p) => p,
                Err(_) => return,
            };
            if control_tx.lock().unwrap().send(&payload).is_err() {
                return;
            }
        }
    }
}

#[cfg(unix)]
fn write_at(f: &mut File, data: &[u8], pos: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(data, pos)
}

#[cfg(not(unix))]
fn write_at(f: &mut File, data: &[u8], pos: u64) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(pos))?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_name_matches_go_scheme() {
        // hex(sha256("8888" + "croc"))
        let mut h = Sha256::new();
        h.update(b"8888croc");
        let expect: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(room_name("8888-test-interop-run"), expect);
    }

    // Exact JSON produced by Go for the same structs (see MIGRATION.md).
    #[test]
    fn fileinfo_json_matches_go() {
        let fi = FileInfo {
            name: "hello.txt".into(),
            folder_remote: "./".into(),
            folder_source: "/tmp/src".into(),
            hash: vec![1, 2, 3, 4, 5, 6, 7, 8],
            size: 1234,
            mod_time: "2026-07-20T12:34:56.789012345Z".into(),
            mode: 0o644,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&fi).unwrap(),
            r#"{"n":"hello.txt","fr":"./","fs":"/tmp/src","h":"AQIDBAUGBwg=","s":1234,"m":"2026-07-20T12:34:56.789012345Z","md":420}"#
        );
        // And we can parse Go's empty FileInfo.
        let empty: FileInfo = serde_json::from_str(r#"{"m":"0001-01-01T00:00:00Z"}"#).unwrap();
        assert_eq!(empty.size, 0);
        assert!(empty.hash.is_empty());
    }

    #[test]
    fn senderinfo_json_round_trips_with_go() {
        let go = r#"{"FilesToTransfer":[{"n":"hello.txt","fr":"./","fs":"/tmp/src","h":"AQIDBAUGBwg=","s":1234,"m":"2026-07-20T12:34:56.789012345Z","md":420}],"EmptyFoldersToTransfer":null,"TotalNumberFolders":0,"MachineID":"mid","Ask":false,"SendingText":false,"NoCompress":false,"HashAlgorithm":"xxhash","ReconnectVersion":0,"NextReconnectRoom":""}"#;
        let si: SenderInfo = serde_json::from_str(go).unwrap();
        assert_eq!(si.files_to_transfer.as_ref().unwrap().len(), 1);
        assert_eq!(si.hash_algorithm, "xxhash");
        assert!(si.empty_folders_to_transfer.is_none());
        let back = serde_json::to_string(&si).unwrap();
        // must at least parse identically on the Go side field names
        assert!(back.contains("\"FilesToTransfer\""));
        assert!(back.contains("\"HashAlgorithm\":\"xxhash\""));
    }

    #[test]
    fn rfr_json_matches_go() {
        let go = r#"{"CurrentFileChunkRanges":[],"FilesToTransferCurrentNum":0,"MachineID":"mid2","ReconnectVersion":0}"#;
        let r: RemoteFileRequest = serde_json::from_str(go).unwrap();
        assert_eq!(r.current_file_chunk_ranges.as_deref(), Some(&[][..]));
        let null = r#"{"CurrentFileChunkRanges":null,"FilesToTransferCurrentNum":2,"MachineID":"m","ReconnectVersion":1}"#;
        let r: RemoteFileRequest = serde_json::from_str(null).unwrap();
        assert!(r.current_file_chunk_ranges.is_none());
        assert_eq!(r.files_to_transfer_current_num, 2);
    }

    #[test]
    fn simple_message_matches_go() {
        let sm = SimpleMessage {
            bytes: b"xyz".to_vec(),
            kind: "pake1".to_string(),
        };
        assert_eq!(
            serde_json::to_string(&sm).unwrap(),
            r#"{"Bytes":"eHl6","Kind":"pake1"}"#
        );
    }

    #[test]
    fn receive_path_validation() {
        assert!(normalize_receive_file_path("./", "ok.txt").is_ok());
        assert!(normalize_receive_file_path("sub/dir/", "ok.txt").is_ok());
        assert!(normalize_receive_file_path("../evil", "x").is_err());
        assert!(normalize_receive_file_path("/abs", "x").is_err());
        assert!(normalize_receive_file_path("./", "../x").is_err());
        assert!(normalize_receive_file_path(".ssh/", "authorized_keys").is_err());
    }
}
