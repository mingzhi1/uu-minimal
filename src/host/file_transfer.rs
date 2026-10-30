//! 文件传输（FILE_DATA_CHANNEL）。
//!
//! 走的是 RPC 信封：`Message 21 RpcRequest { 1 header{1 request_id}, 8 FileTransferFtpRequest }`
//! 与 `Message 22 RpcResponse { 1 header, 4 FileTransferFtpResponse }`。请求/响应里再按
//! oneof 字段号区分具体动作：
//!
//! | case | 方向 | 内容 |
//! |------|------|------|
//! | 10 → 7  | 浏览 | read_dir → file_directory（3 entries + 5 dir_data[zlib]） |
//! | 2 → 2   | 下载 | send_request → send_response，随后 host 主动推 3/4/9 |
//! | 1 → 1   | 上传 | receive_request → receive_response |
//! | 3 → 3   | 上传 | file_ask → file_confirm（skip / err / resume） |
//! | 4 → 4   | 双向 | file_block → block_confirm |
//! | 9 → 6   | 上传 | complete → result |
//! | 5/6/7/8 → 5 或 6 | 文件操作 | rename / dir_create / remove_file / remove_dir |
//! | 11 → 8  | 同名检查 | file_exist → file_exist_response |
//! | 12 → 5  | 清理临时 | clear_send_temp |
//!
//! 字段号与语义对齐官方 host（同 VallierDev/uu-remote-linux 的 file_trans.rs）。

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};

use crate::proto::{self, Field, Value as WireValue};

const CHANNEL: &str = "FILE_DATA_CHANNEL";

// FileTransferError
const FT_SUCCEEDED: u64 = 1;
const FT_UNEXPECTED: u64 = 2;
const FT_PROTOCOL: u64 = 3;
const FT_PERMISSION: u64 = 4;
const FT_DISK: u64 = 5;
const FT_IO: u64 = 6;
const FT_CANCELED: u64 = 7;
const FT_NOT_FOUND: u64 = 9;
// FileType
const FT_DIR: u64 = 0;
const FT_DIR_DRIVE: u64 = 3;
const FT_FILE: u64 = 4;
// FileOperationStrategy
const FOS_DUPLICATE: u64 = 2;
const FOS_SKIP: u64 = 3;
const FOS_RESUME: u64 = 4;

const BLOCK_SIZE: usize = 32 * 1024;
/// 下载时的在飞块数。官方 host 用 16；`UU_FTP_WINDOW` 可覆盖（1 = 退回顺序）。
fn window() -> usize {
    std::env::var("UU_FTP_WINDOW")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(16)
}

// ---------- protobuf 写入 ----------

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn uint(mut self, field: u32, value: u64) -> Self {
        if value != 0 {
            varint(u64::from(field) << 3, &mut self.0);
            varint(value, &mut self.0);
        }
        self
    }

    fn boolean(self, field: u32, value: bool) -> Self {
        self.uint(field, value as u64)
    }

    fn bytes(mut self, field: u32, value: &[u8]) -> Self {
        varint((u64::from(field) << 3) | 2, &mut self.0);
        varint(value.len() as u64, &mut self.0);
        self.0.extend_from_slice(value);
        self
    }

    fn text(self, field: u32, value: &str) -> Self {
        if value.is_empty() {
            self
        } else {
            self.bytes(field, value.as_bytes())
        }
    }

    fn msg(self, field: u32, value: Enc) -> Self {
        self.bytes(field, &value.0)
    }
}

// ---------- 读取 ----------

fn get_uint(fields: &[Field], number: u32) -> u64 {
    fields
        .iter()
        .rev()
        .find_map(|field| match (field.number == number, &field.value) {
            (true, WireValue::Varint(value)) => Some(*value),
            _ => None,
        })
        .unwrap_or(0)
}

fn get_bytes<'a>(fields: &'a [Field], number: u32) -> Option<&'a [u8]> {
    fields
        .iter()
        .rev()
        .find_map(|field| match (field.number == number, &field.value) {
            (true, WireValue::Bytes(value)) => Some(*value),
            _ => None,
        })
}

fn get_all<'a>(fields: &'a [Field], number: u32) -> Vec<&'a [u8]> {
    fields
        .iter()
        .filter_map(|field| match (field.number == number, &field.value) {
            (true, WireValue::Bytes(value)) => Some(*value),
            _ => None,
        })
        .collect()
}

fn get_text(fields: &[Field], number: u32) -> String {
    get_bytes(fields, number)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default()
}

fn decode(bytes: &[u8]) -> Option<Vec<Field<'_>>> {
    proto::read_fields(bytes).ok()
}

/// 应答里取 case 子消息的某个整数字段：ftp{case: body{field}}。
fn case_uint(ftp: &[u8], case: u32, field: u32) -> u64 {
    let Some(inner) = decode(ftp).and_then(|fields| {
        fields
            .iter()
            .find(|entry| entry.number == case)
            .and_then(|entry| entry.blob().map(<[u8]>::to_vec))
    }) else {
        return 0;
    };
    decode(&inner).map(|fields| get_uint(&fields, field)).unwrap_or(0)
}

/// `block_confirm.err`: FT_SUCCEEDED is 1 on the Android viewer, but some
/// clients leave the enum at its proto3 default 0. Treat both as success.
fn block_code(confirm: &[u8]) -> u64 {
    match case_uint(confirm, 4, 3) {
        0 => FT_SUCCEEDED,
        code => code,
    }
}

/// GvPb_TaskId {1 task_id, 2 file_index}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
struct TaskId {
    task: u64,
    index: u64,
}

impl TaskId {
    fn parse(fields: &[Field]) -> Self {
        get_bytes(fields, 1)
            .and_then(decode)
            .map(|inner| TaskId { task: get_uint(&inner, 1), index: get_uint(&inner, 2) })
            .unwrap_or_default()
    }

    fn enc(self) -> Enc {
        Enc::default().uint(1, self.task).uint(2, self.index)
    }
}

/// GvPb_FileInfo {1 rel_path, 2 size, 3 modified_time}
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileInfo {
    rel_path: String,
    size: u64,
    modified: u64,
}

impl FileInfo {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let fields = decode(bytes)?;
        Some(Self { rel_path: get_text(&fields, 1), size: get_uint(&fields, 2), modified: get_uint(&fields, 3) })
    }

    fn enc(&self) -> Enc {
        Enc::default().text(1, &self.rel_path).uint(2, self.size).uint(3, self.modified)
    }
}

/// 文件列表既可能是内联的重复字段，也可能在 list_data 里（FileList {1 files}，zlib 压缩）。
fn parse_files(inline: Vec<&[u8]>, list_data: Option<&[u8]>) -> Vec<FileInfo> {
    let files: Vec<FileInfo> = inline.into_iter().filter_map(FileInfo::parse).collect();
    if !files.is_empty() {
        return files;
    }
    let Some(data) = list_data.filter(|data| !data.is_empty()) else { return files };
    let mut candidates = Vec::new();
    for inflate in [
        inflate_zlib as fn(&[u8]) -> Option<Vec<u8>>,
        inflate_gzip,
        inflate_deflate,
    ] {
        if let Some(plain) = inflate(data) {
            candidates.push(plain);
        }
    }
    candidates.push(data.to_vec());
    for candidate in candidates {
        if let Some(fields) = decode(&candidate) {
            let parsed: Vec<FileInfo> = get_all(&fields, 1).into_iter().filter_map(FileInfo::parse).collect();
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }
    log::warn!("文件传输 list_data 解不出来: bytes={} magic={:02x?}", data.len(), &data[..data.len().min(2)]);
    files
}

fn inflate_zlib(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data).read_to_end(&mut out).ok().map(|_| out)
}

fn inflate_gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out).ok().map(|_| out)
}

fn inflate_deflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data).read_to_end(&mut out).ok().map(|_| out)
}

/// zlib(FileList{1 files})
fn list_data(files: &[FileInfo]) -> Vec<u8> {
    let mut list = Enc::default();
    for file in files {
        list = list.msg(1, file.enc());
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = encoder.write_all(&list.0);
    encoder.finish().unwrap_or_default()
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

fn unix_secs(time: std::io::Result<SystemTime>) -> u64 {
    time.ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn io_error(error: &std::io::Error) -> u64 {
    match error.kind() {
        std::io::ErrorKind::NotFound => FT_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => FT_PERMISSION,
        _ if error.raw_os_error() == Some(libc::ENOSPC) => FT_DISK,
        _ => FT_IO,
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

/// 客户端的路径是按 PC（Windows）风格给的：反斜杠、盘符、`~`。
pub fn normalize(path: &str) -> PathBuf {
    let path = path.replace('\\', "/");
    let path = match path.split_once(':') {
        Some((drive, rest))
            if drive.len() <= 1 && drive.chars().all(|c| c.is_ascii_alphabetic())
                && (rest.is_empty() || rest.starts_with('/')) =>
        {
            rest.to_string()
        }
        _ => path,
    };
    let (mut out, rest) = match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => (home(), rest.to_string()),
        _ => (PathBuf::from("/"), path),
    };
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// “此电脑”：没有盘符的 `:/` 或空路径。
fn is_this_pc(path: &str) -> bool {
    let path = path.trim().replace('\\', "/");
    if path.is_empty() {
        return true;
    }
    let path = path.trim_end_matches('/');
    path.ends_with(':') && path.len() <= 2 && path[..path.len() - 1].chars().all(|c| c.is_ascii_alphabetic())
}

/// GvPb_FileEntry {1 entry_type, 2 name, 3 size, 4 modified_time, 5 full_path}
fn entry(kind: u64, name: &str, size: u64, modified: u64, full: &str) -> Enc {
    Enc::default().uint(1, kind).text(2, name).uint(3, size).uint(4, modified).text(5, full)
}

fn xdg_dir(key: &str) -> Option<PathBuf> {
    let home = home();
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let text = std::fs::read_to_string(config.join("user-dirs.dirs")).ok()?;
    let value = text
        .lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))?
        .trim()
        .trim_matches('"')
        .to_string();
    let path = PathBuf::from(value.replace("$HOME", &home.to_string_lossy()));
    (path != home && path.is_dir()).then_some(path)
}

fn this_pc() -> Vec<Enc> {
    let home = home();
    let name = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned())
    };
    let modified = |path: &Path| unix_secs(std::fs::metadata(path).and_then(|meta| meta.modified()));
    let mut out = Vec::new();
    for key in ["XDG_DOCUMENTS_DIR", "XDG_DESKTOP_DIR", "XDG_DOWNLOAD_DIR"] {
        if let Some(dir) = xdg_dir(key) {
            out.push(entry(FT_DIR, &name(&dir), 0, modified(&dir), &dir.to_string_lossy()));
        }
    }
    out.push(entry(FT_DIR, &name(&home), 0, modified(&home), &home.to_string_lossy()));
    out.push(entry(FT_DIR_DRIVE, "/", 0, 0, "/"));
    out
}

fn list_directory(path: &str) -> Result<Vec<Enc>, u64> {
    if is_this_pc(path) {
        return Ok(this_pc());
    }
    let dir = normalize(path);
    let read = std::fs::read_dir(&dir).map_err(|error| io_error(&error))?;
    let mut list = Vec::new();
    for item in read.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        let full = dir.join(&name);
        let Ok(meta) = std::fs::metadata(&full).or_else(|_| item.metadata()) else { continue };
        let kind = if meta.is_dir() { FT_DIR } else { FT_FILE };
        let size = if meta.is_dir() { 0 } else { meta.len() };
        list.push((
            meta.is_dir(),
            name.to_lowercase(),
            entry(kind, &name, size, unix_secs(meta.modified()), &full.to_string_lossy()),
        ));
    }
    list.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    Ok(list.into_iter().map(|(_, _, entry)| entry).collect())
}

/// 下载用的递归列表：(folder_name, files)。单个文件时 folder_name 为空。
fn collect_download(root: &Path) -> std::io::Result<(String, Vec<(FileInfo, PathBuf)>)> {
    let meta = std::fs::metadata(root)?;
    let name = root.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Vec::new();
    if !meta.is_dir() {
        out.push((
            FileInfo { rel_path: name, size: meta.len(), modified: unix_secs(meta.modified()) },
            root.to_path_buf(),
        ));
        return Ok((String::new(), out));
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for item in std::fs::read_dir(&dir)?.flatten() {
            let path = item.path();
            let Ok(meta) = std::fs::metadata(&path) else { continue };
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let rel = path.strip_prefix(root).map(|rel| rel.to_string_lossy().into_owned()).unwrap_or_default();
            out.push((FileInfo { rel_path: rel, size: meta.len(), modified: unix_secs(meta.modified()) }, path));
        }
    }
    Ok((name, out))
}

/// Resolve one entry from `send_request.list_data` against the requested path.
/// The viewer may put relative names in `list_data` (relative to `path`) or a full
/// PC-style path; both forms have been observed across clients.
fn join_selected(base: &Path, info: &FileInfo) -> PathBuf {
    let rel = info.rel_path.replace('\\', "/");
    let bytes = rel.as_bytes();
    let absolute = rel.starts_with('/')
        || rel.starts_with('~')
        || rel.starts_with("//")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if absolute {
        return normalize(&rel);
    }
    let mut path = base.to_path_buf();
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                path.pop();
            }
            other => path.push(other),
        }
    }
    path
}

/// Download only the files selected by the viewer (`send_request.list_data`).
/// Without this, a multi-select download falls back to recursively sending the
/// whole parent directory.
fn collect_selected(base: &Path, selected: &[FileInfo]) -> std::io::Result<(String, Vec<(FileInfo, PathBuf)>)> {
    let mut out = Vec::new();
    for info in selected {
        let candidate = join_selected(base, info);
        let path = if candidate.exists() {
            candidate
        } else if base.is_file() && selected.len() == 1 {
            base.to_path_buf()
        } else {
            // Some clients send paths rooted at the filesystem rather than the
            // requested directory.
            let rooted = normalize(&info.rel_path);
            if rooted.exists() {
                rooted
            } else {
                continue;
            }
        };
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.is_dir() {
            let (_, files) = collect_download(&path)?;
            let rel = info.rel_path.replace('\\', "/");
            let prefix = Path::new(rel.trim_end_matches('/'))
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (mut file, file_path) in files {
                if !prefix.is_empty() {
                    file.rel_path = format!("{prefix}/{}", file.rel_path);
                }
                out.push((file, file_path));
            }
        } else if meta.is_file() {
            out.push((
                FileInfo { rel_path: info.rel_path.clone(), size: meta.len(), modified: unix_secs(meta.modified()) },
                path,
            ));
        }
    }
    if out.is_empty() {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    } else {
        Ok((String::new(), out))
    }
}

fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let stem = path.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = path.extension().map(|ext| format!(".{}", ext.to_string_lossy())).unwrap_or_default();
    for index in 1..10_000 {
        let candidate = path.with_file_name(format!("{stem} ({index}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    path.to_path_buf()
}

struct UploadTask {
    target: PathBuf,
    folder: String,
    strategy: u64,
    files: Vec<FileInfo>,
    open: HashMap<u64, (std::fs::File, PathBuf, u64)>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// 一条连接上的文件传输状态。下载时 host 会反向发 RpcRequest，所以需要保存待应答表。
pub struct Session {
    out: mpsc::UnboundedSender<(String, Vec<u8>)>,
    sequence: Arc<AtomicU64>,
    next_request: AtomicU64,
    /// 与官方 host 一致：host 主动请求的应答按 (case, task, index, block) 配对，
    /// 因为客户端的 RpcResponse header 不回显 request_id。
    pending: Mutex<HashMap<(u32, u64, u64, u64), oneshot::Sender<Vec<u8>>>>,
    uploads: Mutex<HashMap<u64, UploadTask>>,
    downloading: tokio::sync::Mutex<()>,
    first_upload_block: Mutex<Option<u64>>,
}

impl Session {
    pub fn new(out: mpsc::UnboundedSender<(String, Vec<u8>)>, sequence: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            out,
            sequence,
            next_request: AtomicU64::new(1 << 32),
            pending: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
            downloading: tokio::sync::Mutex::new(()),
            first_upload_block: Mutex::new(None),
        })
    }

    fn send(&self, which: u32, body: Enc) {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let message = proto::envelope(sequence, now(), which, &body.0);
        let _ = self.out.send((CHANNEL.to_owned(), message));
    }

    /// RpcResponse{1 header{1 request_id}, 4 ftp{case}}
    fn respond(&self, request_id: u64, case: u32, body: Enc) {
        let header = Enc::default().uint(1, request_id);
        self.send(22, Enc::default().msg(1, header).msg(4, Enc::default().msg(case, body)));
    }

    /// host 主动发 RpcRequest{1 header, 8 ftp{case}}，等客户端按 key 回 RpcResponse。
    async fn request(&self, case: u32, body: Enc, key: (u32, u64, u64, u64)) -> Option<Vec<u8>> {
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(key, tx);
        let header = Enc::default().uint(1, request_id);
        self.send(21, Enc::default().msg(1, header).msg(8, Enc::default().msg(case, body)));
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(response)) => Some(response),
            _ => {
                self.pending.lock().unwrap().remove(&key);
                None
            }
        }
    }

    /// FileTransferFtpResponse 的 key：3 file_confirm{id}、4 block_confirm{id, block_id}、6 result{id}。
    fn response_key(ftp: &[u8]) -> Option<(u32, u64, u64, u64)> {
        let fields = decode(ftp)?;
        let case = fields.iter().find(|field| matches!(field.value, WireValue::Bytes(_)))?;
        let WireValue::Bytes(inner) = case.value else { return None };
        let inner = decode(inner)?;
        let id = TaskId::parse(&inner);
        let block = if case.number == 4 { get_uint(&inner, 2) } else { 0 };
        Some((case.number, id.task, id.index, block))
    }

    /// 处理一条已解码的消息；返回 true 表示这条消息属于文件传输。
    pub async fn handle(self: &Arc<Self>, fields: &[Field<'_>]) -> bool {
        let mut handled = false;
        for field in fields {
            match (field.number, &field.value) {
                (21, WireValue::Bytes(rpc)) => {
                    let Some(rpc) = decode(rpc) else { continue };
                    let Some(ftp) = get_bytes(&rpc, 8) else { continue };
                    let request_id = get_bytes(&rpc, 1)
                        .and_then(decode)
                        .map(|header| get_uint(&header, 1))
                        .unwrap_or(0);
                    handled = true;
                    if let Some(ftp) = decode(ftp) {
                        self.clone().on_request(request_id, &ftp).await;
                    }
                }
                (22, WireValue::Bytes(rpc)) => {
                    let Some(rpc) = decode(rpc) else { continue };
                    let Some(ftp) = get_bytes(&rpc, 4) else { continue };
                    handled = true;
                    match Self::response_key(ftp) {
                        Some(key) => match self.pending.lock().unwrap().remove(&key) {
                            Some(tx) => {
                                let _ = tx.send(ftp.to_vec());
                            }
                            None => log::debug!("文件传输应答没有对应请求: case={} task={} index={} block={}", key.0, key.1, key.2, key.3),
                        },
                        None => log::warn!("文件传输应答解不出来: bytes={}", ftp.len()),
                    }
                }
                _ => {}
            }
        }
        handled
    }

    async fn on_request(self: Arc<Self>, request_id: u64, ftp: &[Field<'_>]) {
        let Some(case) = ftp.iter().find(|field| matches!(field.value, WireValue::Bytes(_))) else {
            log::warn!("文件传输请求没有载荷: fields={:?}", ftp.iter().map(|field| field.number).collect::<Vec<_>>());
            return;
        };
        let WireValue::Bytes(body) = case.value else { return };
        let Some(fields) = decode(body) else {
            log::warn!("文件传输请求 {} 解不出来", case.number);
            return;
        };
        match case.number {
            10 => self.read_dir(request_id, &fields).await,
            1 => self.receive_request(request_id, &fields),
            3 => self.file_ask(request_id, &fields),
            4 => self.file_block(request_id, &fields),
            9 => self.complete(request_id, &fields),
            2 => self.send_request(request_id, &fields).await,
            5 | 6 | 7 | 8 => self.file_operation(request_id, case.number, &fields).await,
            11 => self.file_exist(request_id, &fields),
            12 => {
                log::info!("文件传输 clear_send_temp");
                self.respond(request_id, 5, Enc::default().uint(1, FT_SUCCEEDED));
            }
            other => log::info!(
                "文件传输 case {} 未实现: fields={:?}",
                other,
                fields.iter().map(|field| field.number).collect::<Vec<_>>()
            ),
        }
    }

    /// read_dir {1 id, 2 path} → file_directory {1 id, 2 path, 3 entries, 4 file_error, 5 dir_data}
    async fn read_dir(&self, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let requested = get_text(fields, 2);
        // A large directory can take seconds to stat/compress; keep it off the
        // async worker that also serves terminal and port-mapping traffic.
        let listed = {
            let path = requested.clone();
            tokio::task::spawn_blocking(move || {
                let entries = list_directory(&path)?;
                let mut listing = Enc::default();
                for entry in &entries {
                    listing = listing.bytes(1, &entry.0);
                }
                let compressed = zlib(&listing.0);
                // 内联副本只在消息还装得下时带：SCTP 单条上限 256 KB。
                let inline = listing.0.len() + compressed.len() < 200_000;
                Ok::<(Vec<Enc>, Vec<u8>, bool, usize), u64>((entries, compressed, inline, listing.0.len()))
            })
            .await
            .unwrap_or_else(|_| Err(FT_IO))
        };
        let mut body = Enc::default().msg(1, id.enc()).text(2, &requested);
        match listed {
            Ok((entries, compressed, inline, plain_len)) => {
                if inline {
                    for entry in entries {
                        body = body.msg(3, entry);
                    }
                }
                body = body.uint(4, FT_SUCCEEDED).bytes(5, &compressed);
                log::info!("文件传输 read_dir: root={} entries={} dir_data={} inline={}", requested.is_empty(), plain_len, compressed.len(), inline);
            }
            Err(code) => {
                log::info!("文件传输 read_dir 失败: error={code}");
                body = body.uint(4, code);
            }
        }
        self.respond(request_id, 7, body);
    }

    /// rename{1 path,2 new_name} dir_create{1 path} remove_file{1 path} remove_dir{1 id,2 path}
    async fn file_operation(&self, request_id: u64, case: u32, fields: &[Field<'_>]) {
        let path_field = if case == 8 { 2 } else { 1 };
        let raw = get_text(fields, path_field);
        let path = normalize(&raw);
        let new_name = get_text(fields, 2);
        // remove_dir_all can walk a large tree; rename/create/unlink are cheap but
        // sharing one blocking hop keeps every filesystem call off the async worker.
        let result = tokio::task::spawn_blocking(move || match case {
            5 => {
                if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
                    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
                } else {
                    std::fs::rename(&path, path.with_file_name(new_name))
                }
            }
            6 => std::fs::create_dir_all(&path),
            7 => std::fs::remove_file(&path),
            // remove_dir：客户端对选中的任何条目都发它，文件就当 unlink 处理。
            _ => match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&path),
                Ok(_) => std::fs::remove_file(&path),
                Err(error) => Err(error),
            },
        })
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::Other)));
        let code = match &result {
            Ok(()) => FT_SUCCEEDED,
            Err(error) => io_error(error),
        };
        log::info!("文件传输操作: case={case} result={code}");
        if case == 8 {
            // remove_dir 的应答是 result(6) = FileTransferResult{1 id, 2 file_error}。
            self.respond(
                request_id,
                6,
                Enc::default().msg(1, TaskId::parse(fields).enc()).uint(2, code),
            );
            return;
        }
        let message = result.err().map(|error| error.to_string()).unwrap_or_default();
        self.respond(request_id, 5, Enc::default().uint(1, code).text(2, &message).text(3, &raw));
    }

    /// file_exist{1 path, 2 names} → file_exist_response{1 path, 2 results{1 name,2 has_same}}
    fn file_exist(&self, request_id: u64, fields: &[Field<'_>]) {
        let raw = get_text(fields, 1);
        let dir = normalize(&raw);
        let mut body = Enc::default().text(1, &raw);
        let names = get_all(fields, 2);
        let mut existing = 0;
        for name in &names {
            let name = String::from_utf8_lossy(name);
            let exists = dir.join(name.as_ref()).exists();
            existing += exists as usize;
            body = body.msg(2, Enc::default().text(1, &name).boolean(2, exists));
        }
        log::info!("文件传输 file_exist: names={} existing={existing}", names.len());
        self.respond(request_id, 8, body);
    }

    /// 上传：receive_request{1 id,2 path,3 files,4 strategy,5 folder_name,6 list_data}
    fn receive_request(&self, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let target = normalize(&get_text(fields, 2));
        let folder = get_text(fields, 5);
        let strategy = get_uint(fields, 4);
        let files = parse_files(get_all(fields, 3), get_bytes(fields, 6));
        log::info!(
            "文件传输 receive_request: task={} files={} bytes={} folder={} strategy={} target_dir={}",
            id.task,
            files.len(),
            files.iter().map(|file| file.size).sum::<u64>(),
            !folder.is_empty(),
            strategy,
            target.is_dir()
        );
        let code = if target.is_dir() { FT_SUCCEEDED } else { FT_NOT_FOUND };
        let mut body = Enc::default().msg(1, id.enc());
        for file in &files {
            body = body.msg(2, file.enc());
        }
        body = body.uint(3, code);
        if code == FT_SUCCEEDED {
            if !folder.is_empty() {
                let mut dir = target.clone();
                for part in folder.replace('\\', "/").split('/') {
                    match part {
                        "" | "." | ".." => {}
                        other => dir.push(other),
                    }
                }
                if let Err(error) = std::fs::create_dir_all(&dir) {
                    log::warn!("文件传输创建目录失败: {}", io_error(&error));
                }
            }
            self.uploads.lock().unwrap().insert(
                id.task,
                UploadTask { target, folder, strategy, files, open: HashMap::new() },
            );
        }
        self.respond(request_id, 1, body);
    }

    /// TaskId.file_index 从 1 开始。
    fn file_slot(index: u64) -> Option<usize> {
        (index as usize).checked_sub(1)
    }

    fn upload_path(task: &UploadTask, index: u64) -> Option<PathBuf> {
        let info = task.files.get(Self::file_slot(index)?)?;
        let rel = info.rel_path.replace('\\', "/");
        let rel = if !task.folder.is_empty() && !rel.starts_with(&format!("{}/", task.folder)) {
            format!("{}/{rel}", task.folder)
        } else {
            rel
        };
        let mut path = task.target.clone();
        for part in rel.split('/') {
            match part {
                "" | "." | ".." => {}
                other => path.push(other),
            }
        }
        Some(path)
    }

    /// file_ask{1 id,2 last_modified,3 file_size} → file_confirm{1 id,2 skip,3 err,4 resume_point}
    fn file_ask(&self, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let size = get_uint(fields, 3);
        let mut uploads = self.uploads.lock().unwrap();
        let (skip, code, resume) = match uploads.get_mut(&id.task) {
            None => (false, FT_PROTOCOL, 0),
            Some(task) => match Self::upload_path(task, id.index) {
                None => (false, FT_PROTOCOL, 0),
                Some(mut path) => {
                    let existing = std::fs::metadata(&path).ok().filter(|meta| meta.is_file()).map(|meta| meta.len());
                    if existing.is_some() && task.strategy == FOS_SKIP {
                        (true, FT_SUCCEEDED, 0)
                    } else {
                        let resume = if task.strategy == FOS_RESUME {
                            existing.filter(|size_existing| *size_existing <= size).unwrap_or(0)
                        } else {
                            0
                        };
                        if existing.is_some() && task.strategy == FOS_DUPLICATE {
                            path = unique_path(&path);
                        }
                        let opened = path
                            .parent()
                            .map(std::fs::create_dir_all)
                            .unwrap_or(Ok(()))
                            .and_then(|_| {
                                std::fs::OpenOptions::new()
                                    .create(true)
                                    .write(true)
                                    .truncate(resume == 0)
                                    .open(&path)
                            })
                            .and_then(|mut file| {
                                file.seek(SeekFrom::Start(resume))?;
                                Ok(file)
                            });
                        match opened {
                            Ok(file) => {
                                task.open.insert(id.index, (file, path, resume));
                                (false, FT_SUCCEEDED, resume)
                            }
                            Err(error) => (false, io_error(&error), 0),
                        }
                    }
                }
            },
        };
        log::info!("文件传输 file_ask: task={} index={} size={size} skip={skip} result={code} resume={resume}", id.task, id.index);
        self.respond(
            request_id,
            3,
            Enc::default().msg(1, id.enc()).boolean(2, skip).uint(3, code).uint(4, resume),
        );
    }

    /// file_block{1 id,2 block_id,3 data} → block_confirm{1 id,2 block_id,3 err,4 block_len}
    fn file_block(&self, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let block = get_uint(fields, 2);
        let data = get_bytes(fields, 3).unwrap_or_default();
        {
            let mut first = self.first_upload_block.lock().unwrap();
            if first.is_none() {
                *first = Some(block);
                log::info!("文件传输首个上传块: block_id={block} len={}", data.len());
            }
        }
        let code = match self
            .uploads
            .lock()
            .unwrap()
            .get_mut(&id.task)
            .and_then(|task| task.open.get_mut(&id.index))
        {
            None => FT_PROTOCOL,
            Some((file, _, written)) => match file.write_all(data) {
                Ok(()) => {
                    *written += data.len() as u64;
                    FT_SUCCEEDED
                }
                Err(error) => io_error(&error),
            },
        };
        if code != FT_SUCCEEDED {
            log::warn!("文件传输写块失败: task={} index={} block={block} err={code}", id.task, id.index);
        }
        self.respond(
            request_id,
            4,
            Enc::default().msg(1, id.enc()).uint(2, block).uint(3, code).uint(4, data.len() as u64),
        );
    }

    /// complete{1 id,2 error} → result{1 id,2 file_error}
    fn complete(&self, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let error = get_uint(fields, 2);
        let mut uploads = self.uploads.lock().unwrap();
        let mut code = FT_SUCCEEDED;
        if let Some(task) = uploads.get_mut(&id.task) {
            if let Some((file, path, written)) = task.open.remove(&id.index) {
                let expected = Self::file_slot(id.index)
                    .and_then(|slot| task.files.get(slot))
                    .map(|file| file.size)
                    .unwrap_or(written);
                drop(file);
                if error != FT_SUCCEEDED && error != 0 {
                    let _ = std::fs::remove_file(&path);
                    code = error;
                } else if written != expected {
                    code = FT_IO;
                }
                log::info!("文件传输上传完成: task={} index={} bytes={written} expected={expected} viewer_error={error} result={code}", id.task, id.index);
            }
            if task.open.is_empty() && id.index as usize >= task.files.len() {
                uploads.remove(&id.task);
            }
        }
        self.respond(request_id, 6, Enc::default().msg(1, id.enc()).uint(2, code));
    }

    /// 下载：send_request{1 id,2 path} → send_response{1 id,2 err,3 files,4 folder_name,5 list_data}
    async fn send_request(self: &Arc<Self>, request_id: u64, fields: &[Field<'_>]) {
        let id = TaskId::parse(fields);
        let path = normalize(&get_text(fields, 2));
        // `list_data` carries the viewer's selection for a multi-file download.
        // Empty selection means "download the path" (single file or whole folder).
        // Decompressing/parsing the list and walking the tree both happen on a
        // blocking worker: a big list or directory must not stall other channels.
        let selection = get_bytes(fields, 3).map(<[u8]>::to_vec);
        let collected = tokio::task::spawn_blocking(move || {
            let selected = selection.map(|data| parse_files(Vec::new(), Some(&data))).unwrap_or_default();
            if selected.is_empty() {
                collect_download(&path)
            } else {
                collect_selected(&path, &selected)
            }
        })
        .await
        .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::Other)));
        let mut body = Enc::default().msg(1, id.enc());
        match collected {
            Ok((folder, files)) => {
                log::info!(
                    "文件传输 send_request: task={} files={} bytes={} folder={}",
                    id.task,
                    files.len(),
                    files.iter().map(|(info, _)| info.size).sum::<u64>(),
                    !folder.is_empty()
                );
                body = body.uint(2, FT_SUCCEEDED);
                for (info, _) in &files {
                    body = body.msg(3, info.enc());
                }
                let infos: Vec<FileInfo> = files.iter().map(|(info, _)| info.clone()).collect();
                body = body.text(4, &folder).bytes(5, &list_data(&infos));
                self.respond(request_id, 2, body);
                let me = self.clone();
                tokio::spawn(async move {
                    let _turn = me.downloading.lock().await;
                    me.run_download(id.task, files).await;
                });
            }
            Err(error) => {
                let code = io_error(&error);
                log::info!("文件传输 send_request 失败: task={} error={code}", id.task);
                self.respond(request_id, 2, body.uint(2, code));
            }
        }
    }

    async fn run_download(self: &Arc<Self>, task: u64, files: Vec<(FileInfo, PathBuf)>) {
        let ok = self.download_files(task, &files).await;
        // 最后一个文件之后发 complete{id{task, index=-1}}：客户端把越界的 index 当作任务结束。
        let id = TaskId { task, index: u64::MAX };
        let body = Enc::default()
            .msg(1, Enc::default().uint(1, self.next_request.fetch_add(1, Ordering::Relaxed)))
            .msg(
                8,
                Enc::default().msg(9, Enc::default().msg(1, id.enc()).uint(2, if ok { FT_SUCCEEDED } else { FT_UNEXPECTED })),
            );
        self.send(21, body);
        log::info!("文件传输下载任务结束: task={task} files={} ok={ok}", files.len());
    }

    async fn download_files(self: &Arc<Self>, task: u64, files: &[(FileInfo, PathBuf)]) -> bool {
        // 块号跟随客户端上传时用过的首个块号（观测到从 0 开始）；文件序号从 1 开始。
        let first_block = self.first_upload_block.lock().unwrap().unwrap_or(0);
        for (offset, (info, path)) in files.iter().enumerate() {
            let index = offset as u64 + 1;
            let id = TaskId { task, index };
            let confirm = self
                .request(
                    3,
                    Enc::default().msg(1, id.enc()).uint(2, info.modified).uint(3, info.size),
                    (3, id.task, id.index, 0),
                )
                .await;
            let Some(confirm) = confirm else {
                log::warn!("文件传输下载: 客户端没回 file_confirm task={task} index={index}");
                return false;
            };
            let skip = case_uint(&confirm, 3, 2) != 0;
            let error = case_uint(&confirm, 3, 3);
            let resume = case_uint(&confirm, 3, 4);
            log::info!("文件传输下载 file_confirm: task={task} index={index} skip={skip} err={error} resume={resume}");
            if error == FT_CANCELED {
                return false;
            }
            if skip || (error != FT_SUCCEEDED && error != 0) {
                continue;
            }
            let code = match self.send_file(id, path, resume.min(info.size), first_block).await {
                Ok(()) => FT_SUCCEEDED,
                Err(code) => code,
            };
            let reply = self
                .request(9, Enc::default().msg(1, id.enc()).uint(2, code), (6, id.task, id.index, 0))
                .await;
            let viewer_result = reply.map(|reply| case_uint(&reply, 6, 2)).unwrap_or(0);
            log::info!("文件传输下载完成: task={task} index={index} bytes={} result={code} viewer_result={viewer_result}", info.size);
            if code == FT_CANCELED {
                return false;
            }
        }
        true
    }

    /// 推块：窗口内并发，最多 `window()` 个块在等确认（官方 host 是 16）。
    /// 顺序等确认等于每 32 KiB 一个 RTT，RTT 40 ms 时只有 ~0.8 MB/s。
    async fn send_file(self: &Arc<Self>, id: TaskId, path: &Path, resume: u64, first_block: u64) -> Result<(), u64> {
        let window = window();
        let mut file = std::fs::File::open(path).map_err(|error| io_error(&error))?;
        file.seek(SeekFrom::Start(resume)).map_err(|error| io_error(&error))?;
        let mut block_id = first_block + resume / BLOCK_SIZE as u64;
        let mut inflight = tokio::task::JoinSet::new();
        loop {
            let mut buffer = vec![0u8; BLOCK_SIZE];
            let read = file.read(&mut buffer).map_err(|error| io_error(&error))?;
            if read == 0 {
                break;
            }
            buffer.truncate(read);
            while inflight.len() >= window {
                if let Some(joined) = inflight.join_next().await {
                    let code = joined.unwrap_or(FT_UNEXPECTED);
                    if code != FT_SUCCEEDED {
                        return Err(code);
                    }
                }
            }
            let me = self.clone();
            let key = (4, id.task, id.index, block_id);
            let body = Enc::default().msg(1, id.enc()).uint(2, block_id).bytes(3, &buffer);
            inflight.spawn(async move {
                me.request(4, body, key).await.map(|confirm| block_code(&confirm)).unwrap_or(FT_UNEXPECTED)
            });
            block_id += 1;
        }
        while let Some(joined) = inflight.join_next().await {
            let code = joined.unwrap_or(FT_UNEXPECTED);
            if code != FT_SUCCEEDED {
                return Err(code);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(which: u32, payload: &[u8]) -> Vec<u8> {
        proto::envelope(1, 1, which, payload)
    }

    /// 客户端发 RpcRequest{1 header, 8 ftp{case: body}}。
    fn request(case: u32, body: Enc) -> Vec<u8> {
        let rpc = Enc::default()
            .msg(1, Enc::default().uint(1, 7))
            .msg(8, Enc::default().msg(case, body));
        envelope(21, &rpc.0)
    }

    fn session() -> (Arc<Session>, mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Session::new(tx, Arc::new(AtomicU64::new(1))), rx)
    }

    #[tokio::test]
    async fn read_dir_lists_the_home_directory() {
        let dir = std::env::temp_dir().join(format!("uu-ft-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();

        let (session, mut out) = session();
        let message = request(10, Enc::default().uint(1, 1).text(2, &dir.to_string_lossy()));
        let fields = decode(&message).unwrap();
        assert!(session.handle(&fields).await);

        let (_, reply) = out.try_recv().expect("应该有应答");
        let fields = decode(&reply).unwrap();
        let rpc = decode(get_bytes(&fields, 22).unwrap()).unwrap();
        let ftp = decode(get_bytes(&rpc, 4).unwrap()).unwrap();
        let directory = decode(get_bytes(&ftp, 7).unwrap()).unwrap();
        assert_eq!(get_uint(&directory, 4), FT_SUCCEEDED);
        let compressed = get_bytes(&directory, 5).expect("dir_data 必须有");
        let listing = inflate_zlib(compressed).unwrap();
        let listing = decode(&listing).unwrap();
        let entries = get_all(&listing, 1);
        assert_eq!(entries.len(), 2);
        let first = decode(entries[0]).unwrap();
        assert_eq!(get_text(&first, 2), "sub");
        assert_eq!(get_uint(&first, 1), FT_DIR);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn upload_writes_blocks_and_confirms() {
        let dir = std::env::temp_dir().join(format!("uu-up-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (session, mut out) = session();
        let id = TaskId { task: 3, index: 1 };
        let info = FileInfo { rel_path: "x.bin".into(), size: 6, modified: 0 };

        for message in [
            request(1, Enc::default().msg(1, id.enc()).text(2, &dir.to_string_lossy()).msg(3, info.enc())),
            request(3, Enc::default().msg(1, id.enc()).uint(3, 6)),
            request(4, Enc::default().msg(1, id.enc()).uint(2, 1).bytes(3, b"abc")),
            request(4, Enc::default().msg(1, id.enc()).uint(2, 2).bytes(3, b"def")),
            request(9, Enc::default().msg(1, id.enc()).uint(2, FT_SUCCEEDED)),
        ] {
            let fields = decode(&message).unwrap();
            assert!(session.handle(&fields).await);
            let _ = out.try_recv().expect("每一步都该有应答");
        }

        assert_eq!(std::fs::read(dir.join("x.bin")).unwrap(), b"abcdef");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// 下载走并发窗口：4 个块应当全部发出去（而不是发一块等一块）。
    #[tokio::test]
    async fn download_sends_blocks_with_a_window() {
        let dir = std::env::temp_dir().join(format!("uu-dl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.bin");
        std::fs::write(&path, vec![7u8; 4 * BLOCK_SIZE + 10]).unwrap();

        let (session, mut out) = session();
        let responder = {
            let session = session.clone();
            tokio::spawn(async move {
                let mut blocks = Vec::new();
                while let Some((_, message)) = out.recv().await {
                    let fields = decode(&message).unwrap();
                    let Some(rpc) = get_bytes(&fields, 21) else { continue };
                    let rpc = decode(rpc).unwrap();
                    let Some(ftp) = get_bytes(&rpc, 8) else { continue };
                    let ftp = decode(ftp).unwrap();
                    let Some(case) = ftp.iter().find(|field| matches!(field.value, WireValue::Bytes(_))) else { continue };
                    if case.number != 4 {
                        continue;
                    }
                    let inner = decode(case.blob().unwrap()).unwrap();
                    let id = TaskId::parse(&inner);
                    let block = get_uint(&inner, 2);
                    let len = get_bytes(&inner, 3).unwrap().len() as u64;
                    blocks.push(block);
                    let confirm = Enc::default()
                        .msg(1, id.enc())
                        .uint(2, block)
                        .uint(3, FT_SUCCEEDED)
                        .uint(4, len);
                    let rpc = Enc::default()
                        .msg(1, Enc::default().uint(1, 0))
                        .msg(4, Enc::default().msg(4, confirm));
                    let reply = proto::envelope(1, 1, 22, &rpc.0);
                    session.handle(&decode(&reply).unwrap()).await;
                    if blocks.len() == 5 {
                        break;
                    }
                }
                blocks
            })
        };

        let result = session.send_file(TaskId { task: 5, index: 1 }, &path, 0, 0).await;
        assert_eq!(result, Ok(()));
        let blocks = responder.await.unwrap();
        assert_eq!(blocks, vec![0, 1, 2, 3, 4]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn zero_block_error_is_success() {
        let id = TaskId { task: 1, index: 1 };
        let ftp = Enc::default().msg(4, Enc::default().msg(1, id.enc()).uint(2, 7)).0;
        assert_eq!(case_uint(&ftp, 4, 3), 0, "字段确实缺省");
        assert_eq!(block_code(&ftp), FT_SUCCEEDED);
    }

    /// 多选下载只能返回 list_data 里列出的文件，不能把整个目录带回去。
    #[tokio::test]
    async fn download_honors_the_selected_file_list() {
        let dir = std::env::temp_dir().join(format!("uu-sel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.join("b.txt"), b"other").unwrap();

        let (session, mut out) = session();
        let id = TaskId { task: 9, index: 0 };
        let selected = list_data(&[FileInfo { rel_path: "a.txt".into(), size: 5, modified: 0 }]);
        let message = request(
            2,
            Enc::default()
                .msg(1, id.enc())
                .text(2, &dir.to_string_lossy())
                .bytes(3, &selected),
        );
        let fields = decode(&message).unwrap();
        assert!(session.handle(&fields).await);

        let (_, reply) = out.try_recv().expect("应该有 send_response");
        let fields = decode(&reply).unwrap();
        let rpc = decode(get_bytes(&fields, 22).unwrap()).unwrap();
        let ftp = decode(get_bytes(&rpc, 4).unwrap()).unwrap();
        let response = decode(get_bytes(&ftp, 2).unwrap()).unwrap();
        let files = get_all(&response, 3);
        assert_eq!(files.len(), 1, "只应返回 a.txt");
        let info = decode(files[0]).unwrap();
        assert_eq!(get_text(&info, 1), "a.txt");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_data_round_trips() {
        let files = vec![FileInfo { rel_path: "d/a.txt".into(), size: 3, modified: 9 }];
        assert_eq!(parse_files(vec![], Some(&list_data(&files))), files);
    }

    #[test]
    fn normalize_accepts_pc_style_paths() {
        let home = home();
        assert_eq!(normalize("~"), home);
        assert_eq!(normalize("C:\\Windows"), PathBuf::from("/Windows"));
        assert_eq!(normalize("/a/../b"), PathBuf::from("/b"));
    }
}
