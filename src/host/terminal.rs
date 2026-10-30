//! 终端链路（CT_TERMINAL，走 BINARY_DATA_CHANNEL）。
//!
//! 帧头 16 字节：`"TERM"`、version=1、type、两个 flag、session_id(u32 LE)、
//! payload_len(u32 LE，≤1 MiB)，随后是载荷；type 的取值是协议里的 case 序号 + 1。
//! 控制帧载荷是 JSON（cols/rows/shell、code/message、exit_code）。
//! 会话独立于 viewer 连接存活（与官方 host 的 tmux 会话一致），重连时回放一段有上限的
//! scrollback。终端的输入输出字节从不写日志。

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc::UnboundedSender;

const MAGIC: &[u8; 4] = b"TERM";
const HEADER: usize = 16;
const MAX_PAYLOAD: usize = 0x10_0000;
/// 每个会话保留的回放字节数。
const JOURNAL_LIMIT: usize = 256 * 1024;
/// 单帧载荷上限：超过 SCTP 默认的 64 KiB 出向消息上限会被对端拒绝。
const CHUNK: usize = 16 * 1024;

/// 帧类型；`wire` 是协议里的编号（也等于枚举序号 + 1）。
/// 变体由协议定义，被控端只构造其中一部分（其余仅在收到时匹配），所以整体放行 dead_code。
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Type {
    Open = 1,
    Stdin = 2,
    Resize = 3,
    Close = 4,
    Stdout = 5,
    Exit = 6,
    Signal = 7,
    Error = 8,
    ListReq = 9,
    ListResp = 10,
    KillReq = 11,
    KillResp = 12,
    OpenResp = 13,
    UnlockReq = 14,
    UnlockResp = 15,
    Detach = 16,
}

impl Type {
    fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Open,
            2 => Self::Stdin,
            3 => Self::Resize,
            4 => Self::Close,
            5 => Self::Stdout,
            6 => Self::Exit,
            7 => Self::Signal,
            8 => Self::Error,
            9 => Self::ListReq,
            10 => Self::ListResp,
            11 => Self::KillReq,
            12 => Self::KillResp,
            13 => Self::OpenResp,
            14 => Self::UnlockReq,
            15 => Self::UnlockResp,
            16 => Self::Detach,
            _ => return None,
        })
    }

    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Type,
    pub flags: [u8; 2],
    pub session: u32,
    pub payload: Vec<u8>,
}

/// 组一帧。flag 恒为 0（官方 host 也只在内部用到，线上一律 0）。
pub fn frame(kind: Type, session: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[1, kind.wire(), 0, 0]);
    out.extend_from_slice(&session.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// 解析一帧；长度、魔数、类型任何一项对不上都返回 None（数据通道上还会有别的报文）。
pub fn parse(data: &[u8]) -> Option<Frame> {
    if data.len() < HEADER || &data[..4] != MAGIC {
        return None;
    }
    let kind = Type::from_wire(data[5])?;
    let session = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let length = u32::from_le_bytes(data[12..16].try_into().ok()?) as usize;
    if length > MAX_PAYLOAD || data.len() != HEADER + length {
        return None;
    }
    Some(Frame { kind, flags: [data[6], data[7]], session, payload: data[HEADER..].to_vec() })
}

/// 只看魔数：数据通道上混有 protobuf 报文，先按 4 字节区分。
pub fn is_frame(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == MAGIC
}

struct Term {
    id: u32,
    shell: String,
    started_ms: u64,
    master: OwnedFd,
    /// 进程组（setsid 之后 pgrp == pid），信号打到整组。
    group: i32,
    /// 当前 viewer 的下行队列，带所属 peer 的 token；None 表示已 detach。
    /// token 让 peer 被拆除时能精确解绑，不会把队列和任务留在内存里。
    link: Mutex<Option<(u64, UnboundedSender<Vec<u8>>)>>,
    journal: Mutex<VecDeque<u8>>,
    window: Mutex<(u16, u16)>,
}

impl Term {
    /// 先拿 link 再拿 journal：OPEN 的回放快照也按这个顺序，保证一段输出只会出现在
    /// 「回放」或「实时」其中一边。
    fn absorb(&self, chunk: &[u8]) {
        let mut link = self.link.lock().unwrap();
        {
            let mut journal = self.journal.lock().unwrap();
            journal.extend(chunk);
            let excess = journal.len().saturating_sub(JOURNAL_LIMIT);
            journal.drain(..excess);
        }
        if let Some((_, tx)) = link.as_ref() {
            if tx.send(frame(Type::Stdout, self.id, chunk)).is_err() {
                *link = None;
            }
        }
    }

    fn push(&self, kind: Type, payload: &[u8]) -> bool {
        let mut link = self.link.lock().unwrap();
        if let Some((_, tx)) = link.as_ref() {
            if tx.send(frame(kind, self.id, payload)).is_ok() {
                return true;
            }
            *link = None;
        }
        false
    }

    /// size 锁要一直拿着跨过 ioctl，否则延迟的恢复可能把新尺寸改回旧值。
    fn resize(&self, cols: u16, rows: u16) {
        let mut window = self.window.lock().unwrap();
        *window = (cols, rows);
        self.set_window(cols, rows);
    }

    fn set_window(&self, cols: u16, rows: u16) {
        let size = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        // ioctl 失败只意味着 pty 已经没了，没有可补救的动作。
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &size) };
    }

    /// 全屏程序只在收到 SIGWINCH 时重绘，尺寸没变就不会发；先少一行再改回来。
    fn nudge_redraw(self: &Arc<Self>) {
        {
            let window = self.window.lock().unwrap();
            if window.1 <= 1 {
                return;
            }
            self.set_window(window.0, window.1 - 1);
        }
        let term = self.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            let window = term.window.lock().unwrap();
            term.set_window(window.0, window.1);
        });
    }

    fn type_in(&self, bytes: &[u8]) {
        let mut offset = 0;
        while offset < bytes.len() {
            let written = unsafe {
                libc::write(self.master.as_raw_fd(), bytes[offset..].as_ptr().cast(), bytes.len() - offset)
            };
            if written <= 0 {
                return;
            }
            offset += written as usize;
        }
    }

    fn kill(&self, signal: i32) {
        unsafe { libc::kill(-self.group, signal) };
    }
}

fn hub() -> &'static Mutex<HashMap<u32, Arc<Term>>> {
    static HUB: OnceLock<Mutex<HashMap<u32, Arc<Term>>>> = OnceLock::new();
    HUB.get_or_init(Default::default)
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);
/// 每条 viewer 终端端点一个 token，用来在连接被拆除时精确解绑会话。
static NEXT_PEER: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// 分配会话号：viewer 给了就用它的，否则取一个没被占用的。
fn allocate(wanted: u32) -> u32 {
    if wanted != 0 {
        return wanted;
    }
    loop {
        let candidate = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if candidate != 0 && !hub().lock().unwrap().contains_key(&candidate) {
            return candidate;
        }
    }
}

fn spawn_shell(wanted_id: u32, cols: u16, rows: u16, shell: Option<&str>) -> Result<Arc<Term>, String> {
    use std::os::unix::process::CommandExt;

    let size = nix::pty::Winsize { ws_row: rows.max(1), ws_col: cols.max(1), ws_xpixel: 0, ws_ypixel: 0 };
    let pty = nix::pty::openpty(Some(&size), None).map_err(|error| format!("openpty failed: {error}"))?;
    let shell = shell
        .filter(|path| path.starts_with('/') && std::path::Path::new(path).exists())
        .map(str::to_owned)
        .or_else(|| std::env::var("SHELL").ok().filter(|path| std::path::Path::new(path).exists()))
        .unwrap_or_else(|| "/bin/bash".into());
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let slave = pty.slave;
    let dup = |fd: &OwnedFd| fd.try_clone().map(std::process::Stdio::from).map_err(|error| format!("pty dup failed: {error}"));

    let mut command = std::process::Command::new(&shell);
    command
        .arg("-l")
        .current_dir(&home)
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("LANG", std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into()))
        .stdin(dup(&slave)?)
        .stdout(dup(&slave)?)
        .stderr(dup(&slave)?);
    // 子进程要成为新会话的首进程，并把 pty 设成控制终端，否则 Ctrl-C/job control 全不工作。
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| format!("shell spawn failed: {error}"))?;
    drop(slave);

    let id = allocate(wanted_id);
    let term = Arc::new(Term {
        id,
        shell,
        started_ms: now_ms(),
        group: child.id() as i32,
        master: pty.master,
        link: Mutex::new(None),
        journal: Mutex::new(VecDeque::new()),
        window: Mutex::new((cols, rows)),
    });

    let mut reader = std::fs::File::from(term.master.try_clone().map_err(|error| format!("pty dup failed: {error}"))?);
    let drain = term.clone();
    // 先登记再起读线程：读线程退出时会按 id 摘除，顺序反了会留下死会话。
    hub().lock().unwrap().insert(id, term.clone());
    let spawned = std::thread::Builder::new().name(format!("uu-term-{id}")).spawn(move || {
        let mut buffer = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => drain.absorb(&buffer[..read]),
            }
        }
        let code = child.wait().ok().and_then(|status| status.code()).unwrap_or(-1);
        log::info!("Terminal session exited: id={} exit_code={}", drain.id, code);
        drain.push(Type::Exit, serde_json::json!({"exit_code": code}).to_string().as_bytes());
        hub().lock().unwrap().remove(&drain.id);
    });
    if let Err(error) = spawned {
        hub().lock().unwrap().remove(&id);
        return Err(format!("reader thread failed: {error}"));
    }
    log::info!("Terminal session spawned: id={} cols={} rows={}", id, cols, rows);
    Ok(term)
}

/// 关掉所有会话（交互式 shell 不响应 SIGTERM，不主动收掉会让 systemd 卡到超时）。
pub fn shutdown_all() {
    let terms: Vec<Arc<Term>> = hub().lock().unwrap().values().cloned().collect();
    for term in &terms {
        term.kill(libc::SIGHUP);
    }
    if !terms.is_empty() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        for term in &terms {
            term.kill(libc::SIGKILL);
        }
        log::info!("Terminal sessions closed on shutdown: count={}", terms.len());
    }
}

fn json_of(payload: &[u8]) -> serde_json::Value {
    serde_json::from_slice(payload).unwrap_or(serde_json::Value::Null)
}

/// 尺寸：JSON 里可能是整数也可能是浮点，缺省 80×24，限制在 1..=1000。
fn size_of(payload: &serde_json::Value) -> (u16, u16) {
    let value = |key: &str, default: u64| {
        let raw = payload
            .get(key)
            .and_then(|value| value.as_u64().or_else(|| value.as_f64().map(|float| float as u64)))
            .unwrap_or(default);
        raw.clamp(1, 1000) as u16
    };
    (value("cols", 80), value("rows", 24))
}

/// 信号：可以是 `"SIGTERM"`、`"TERM"`、`{"signal":"SIGKILL"}`，认不出就 SIGINT。
fn signal_of(payload: &[u8]) -> i32 {
    let value = json_of(payload);
    if let Some(number) = value.as_object().and_then(|object| object.values().find_map(|item| item.as_i64())) {
        return number as i32;
    }
    let name = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_object().and_then(|object| object.values().find_map(|item| item.as_str().map(str::to_owned))))
        .unwrap_or_else(|| String::from_utf8_lossy(payload).into_owned());
    match name.trim().trim_start_matches("SIG") {
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "HUP" => libc::SIGHUP,
        "QUIT" => libc::SIGQUIT,
        "ABRT" => libc::SIGABRT,
        "PIPE" => libc::SIGPIPE,
        "FPE" => libc::SIGFPE,
        "SEGV" => libc::SIGSEGV,
        "ILL" => libc::SIGILL,
        _ => libc::SIGINT,
    }
}

fn reply(code: i64, message: &str) -> Vec<u8> {
    serde_json::json!({"code": code, "message": message}).to_string().into_bytes()
}

/// 一条 viewer 连接的终端端点；`out` 发到 BINARY_DATA_CHANNEL。
pub struct TerminalConn {
    out: UnboundedSender<Vec<u8>>,
    /// 这条端点属于哪个 peer；会话的 `link` 里记的就是它。
    peer: u64,
}

impl TerminalConn {
    pub fn new(out: UnboundedSender<Vec<u8>>) -> Self {
        Self { out, peer: NEXT_PEER.fetch_add(1, Ordering::Relaxed) }
    }

    fn send(&self, kind: Type, session: u32, payload: &[u8]) {
        let _ = self.out.send(frame(kind, session, payload));
    }

    pub fn handle(&self, data: &[u8]) {
        let Some(frame) = parse(data) else {
            log::warn!("Terminal frame rejected: bytes={}", data.len());
            return;
        };
        if frame.kind != Type::Stdin {
            log::info!("Terminal frame: type={} session={} payload_bytes={}", frame.kind.wire(), frame.session, frame.payload.len());
        }
        let target = hub().lock().unwrap().get(&frame.session).cloned();
        match frame.kind {
            Type::Open => self.open(frame.session, &frame.payload, target),
            Type::Stdin => {
                if let Some(term) = target {
                    term.type_in(&frame.payload);
                }
            }
            Type::Resize => {
                if let Some(term) = target {
                    let (cols, rows) = size_of(&json_of(&frame.payload));
                    term.resize(cols, rows);
                }
            }
            Type::Signal => {
                if let Some(term) = target {
                    term.kill(signal_of(&frame.payload));
                }
            }
            // CLOSE 挂断 shell，DETACH 只是解绑（会话继续活着）。
            Type::Close => {
                if let Some(term) = target {
                    *term.link.lock().unwrap() = None;
                    term.kill(libc::SIGHUP);
                }
            }
            Type::Detach => {
                if let Some(term) = target {
                    *term.link.lock().unwrap() = None;
                }
            }
            Type::KillReq => self.kill_request(frame.session, &frame.payload),
            Type::ListReq => self.list(frame.session),
            Type::UnlockReq => self.send(Type::UnlockResp, frame.session, &reply(0, "ok")),
            _ => self.send(Type::Error, frame.session, &reply(1, "unsupported frame")),
        }
    }

    fn open(&self, session: u32, payload: &[u8], existing: Option<Arc<Term>>) {
        let request = json_of(payload);
        let (cols, rows) = size_of(&request);
        let reattach = existing.is_some();
        let opened = match existing {
            Some(term) => {
                term.resize(cols, rows);
                Ok(term)
            }
            None => spawn_shell(session, cols, rows, request.get("shell").and_then(|value| value.as_str())),
        };
        let term = match opened {
            Ok(term) => term,
            Err(error) => {
                log::warn!("Terminal open failed: {}", error);
                self.send(Type::OpenResp, session, &reply(1, &error));
                return;
            }
        };
        // 先回 OPEN_RESP 再挂上行，读线程不会抢在应答前面发实时输出。
        let mut link = term.link.lock().unwrap();
        self.send(Type::OpenResp, term.id, &reply(0, "ok"));
        *link = Some((self.peer, self.out.clone()));
        let journal: Vec<u8> = term.journal.lock().unwrap().iter().copied().collect();
        for chunk in journal.chunks(CHUNK) {
            self.send(Type::Stdout, term.id, chunk);
        }
        drop(link);
        if reattach {
            // 回放从全屏程序的一次重绘中间开始，逼它整屏重画。
            term.nudge_redraw();
        }
    }

    fn kill_request(&self, session: u32, payload: &[u8]) {
        let id = if session != 0 {
            session
        } else {
            json_of(payload).get("session_id").and_then(|value| value.as_u64()).unwrap_or(0) as u32
        };
        let target = hub().lock().unwrap().get(&id).cloned();
        match target {
            Some(term) => {
                *term.link.lock().unwrap() = None;
                term.kill(libc::SIGHUP);
                term.kill(libc::SIGKILL);
                self.send(Type::KillResp, id, &reply(0, "ok"));
            }
            None => self.send(Type::KillResp, id, &reply(1, "Session not found")),
        }
    }

    fn list(&self, session: u32) {
        let sessions: Vec<serde_json::Value> = hub()
            .lock()
            .unwrap()
            .values()
            .map(|term| {
                let attached = term.link.lock().unwrap().is_some();
                serde_json::json!({
                    "session_id": term.id,
                    "name": format!("bash-{}", term.id),
                    "shell": term.shell,
                    "state": if attached { "running" } else { "detached" },
                    "created_at_ms": term.started_ms,
                })
            })
            .collect();
        log::info!("Terminal list sessions: count={}", sessions.len());
        // 官方 Mac 4.42.0 的 handleListSessionsReq 回的是裸数组，session 字段用请求里的 ID。
        self.send(Type::ListResp, session, serde_json::Value::Array(sessions).to_string().as_bytes());
    }
}

impl Drop for TerminalConn {
    /// peer 被拆除时解绑它的会话：否则 `Term.link` 会一直攥着这条连接的下行 sender，
    /// 让下游任务永不退出（每次重连泄漏两个任务 + 一条无界队列），
    /// 并且在断线期间对每一帧输出打一条发送失败日志。
    fn drop(&mut self) {
        let peer = self.peer;
        for term in hub().lock().unwrap().values() {
            let mut link = term.link.lock().unwrap();
            let mine = link.as_ref().map(|(owner, _)| *owner == peer).unwrap_or(false);
            if mine {
                *link = None;
            }
        }
    }
}

/// Message 21 里的终端 RPC：28 check_env → RpcResponse 24，29 rename_session → RpcResponse 26。
/// 返回 RpcResponse 的 body；不认识的 RPC 返回 None。
pub fn rpc_response(request: &[crate::proto::Field]) -> Option<Vec<u8>> {
    use crate::proto::read_fields;

    // 24/26 这类字段号的 tag 已经超过一个字节，必须按 varint 写。
    fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn text_field(out: &mut Vec<u8>, number: u32, text: &[u8]) {
        varint(out, (u64::from(number) << 3) | 2);
        varint(out, text.len() as u64);
        out.extend_from_slice(text);
    }
    fn int_field(out: &mut Vec<u8>, number: u32, value: u64) {
        varint(out, u64::from(number) << 3);
        varint(out, value);
    }

    let header = request.iter().find(|field| field.number == 1).and_then(|field| field.blob()).unwrap_or(&[]);
    let mut out = Vec::new();
    text_field(&mut out, 1, header);

    if request.iter().any(|field| field.number == 28) {
        let mut body = Vec::new();
        text_field(&mut body, 2, b"ok"); // code 0 = 可用
        text_field(&mut out, 24, &body);
        log::info!("Terminal check_env answered: available");
        return Some(out);
    }

    let rename = request.iter().find(|field| field.number == 29).and_then(|field| field.blob());
    let Some(rename) = rename else { return None };
    let fields = read_fields(rename).ok()?;
    let session = fields.iter().find(|field| field.number == 1).and_then(|field| field.int()).unwrap_or(0);
    let mut body = Vec::new();
    if session != 0 {
        int_field(&mut body, 1, session);
    }
    text_field(&mut body, 3, b"ok");
    text_field(&mut out, 26, &body);
    log::info!("Terminal rename answered: session={}", session);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Frame {
        parse(&rx.try_recv().unwrap()).unwrap()
    }

    #[test]
    fn rpc_replies_write_field_numbers_above_15_as_varints() {
        use crate::proto::{Field, Value};
        let request = |number: u32, payload: &'static [u8]| Field { number, value: Value::Bytes(payload) };

        let check = vec![request(1, b"H"), request(28, b"")];
        assert_eq!(
            rpc_response(&check).unwrap(),
            vec![0x0A, 1, b'H', 0xC2, 0x01, 4, 0x12, 2, b'o', b'k'],
            "24 的 tag 是 0xC2 0x01，不能截成单字节"
        );

        let rename = vec![request(1, b"H"), request(29, &[0x08, 0x07])];
        assert_eq!(
            rpc_response(&rename).unwrap(),
            vec![0x0A, 1, b'H', 0xD2, 0x01, 6, 0x08, 7, 0x1A, 2, b'o', b'k']
        );
    }

    #[test]
    fn frame_layout_matches_the_protocol() {
        let bytes = frame(Type::OpenResp, 7, b"{}");
        assert_eq!(&bytes[..8], &[b'T', b'E', b'R', b'M', 1, 13, 0, 0]);
        assert_eq!(&bytes[8..16], &[7, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(parse(&bytes), Some(Frame { kind: Type::OpenResp, flags: [0, 0], session: 7, payload: b"{}".to_vec() }));
    }

    #[test]
    fn parse_rejects_bad_type_and_length() {
        let good = frame(Type::Open, 1, b"x");
        assert_eq!(parse(&good[..good.len() - 1]), None, "声明长度与实际不符");
        assert_eq!(parse(&good[..8]), None, "不足一帧");
        let mut unknown = good.clone();
        unknown[5] = 17;
        assert_eq!(parse(&unknown), None, "类型必须落在 1..=16");
    }

    #[test]
    fn signal_names_map_to_posix_numbers() {
        assert_eq!(signal_of(b"SIGTERM"), libc::SIGTERM);
        assert_eq!(signal_of(br#"{"signal":"SIGKILL"}"#), libc::SIGKILL);
        assert_eq!(signal_of(br#"{"signal":15}"#), libc::SIGTERM);
        assert_eq!(signal_of(b"whatever"), libc::SIGINT);
    }

    #[test]
    fn resize_payload_clamps_to_a_sane_window() {
        let value = serde_json::json!({"cols": 120.0, "rows": 0});
        assert_eq!(size_of(&value), (120, 1), "显式 0 行夹到 1");
        assert_eq!(size_of(&serde_json::json!({})), (80, 24));
        let value = serde_json::json!({"cols": 5000, "rows": 1});
        assert_eq!(size_of(&value), (1000, 1));
    }

    #[test]
    fn list_reply_is_an_array_and_echoes_the_request_id() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = TerminalConn::new(tx);
        for request in [0, 7, u32::MAX] {
            conn.handle(&frame(Type::ListReq, request, &[]));
            let reply = drain(&mut rx);
            assert_eq!(reply.kind, Type::ListResp);
            assert_eq!(reply.session, request);
            assert!(json_of(&reply.payload).is_array());
        }
    }

    #[test]
    fn reattach_replays_history_in_chunks_the_transport_accepts() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let id = u32::MAX - 1;
        let history: Vec<u8> = (0..JOURNAL_LIMIT).map(|index| (index % 251) as u8).collect();
        let term = Arc::new(Term { id, shell: "/bin/sh".into(), started_ms: now_ms(), group: 0, master: pty.master,
            link: Mutex::new(None), journal: Mutex::new(history.iter().copied().collect()), window: Mutex::new((80, 24)) });
        hub().lock().unwrap().insert(id, term.clone());
        struct Guard(u32);
        impl Drop for Guard { fn drop(&mut self) { hub().lock().unwrap().remove(&self.0); } }
        let _guard = Guard(id);

        for _ in 0..2 {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let conn = TerminalConn::new(tx);
            conn.handle(&frame(Type::Open, id, br#"{"cols":80,"rows":24}"#));
            assert_eq!(drain(&mut rx).kind, Type::OpenResp);
            let mut replay = Vec::new();
            while replay.len() < history.len() {
                let packet = rx.try_recv().unwrap();
                assert!(packet.len() <= 65536, "回放帧超过 SCTP 出向消息上限");
                let frame = parse(&packet).unwrap();
                assert_eq!(frame.kind, Type::Stdout);
                replay.extend(frame.payload);
            }
            assert!(replay == history, "回放必须逐字节、按序");
            assert!(term.push(Type::Stdout, b"live output"));
            assert_eq!(drain(&mut rx).payload, b"live output");
            conn.handle(&frame(Type::Detach, id, &[]));
        }
    }

    #[test]
    fn dropping_the_endpoint_detaches_its_sessions() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let id = u32::MAX - 3;
        let term = Arc::new(Term { id, shell: "/bin/sh".into(), started_ms: now_ms(), group: 0, master: pty.master,
            link: Mutex::new(None), journal: Mutex::new(VecDeque::new()), window: Mutex::new((80, 24)) });
        hub().lock().unwrap().insert(id, term.clone());
        struct Guard(u32);
        impl Drop for Guard { fn drop(&mut self) { hub().lock().unwrap().remove(&self.0); } }
        let _guard = Guard(id);

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = TerminalConn::new(tx);
        conn.handle(&frame(Type::Open, id, br#"{"cols":80,"rows":24}"#));
        assert!(term.link.lock().unwrap().is_some(), "attach 后会话必须挂到这条连接");
        drop(conn);
        assert!(term.link.lock().unwrap().is_none(), "连接拆除后必须解绑，否则下游任务永不退出");
    }

    #[test]
    fn open_spawns_a_shell_and_streams_its_output() {
        for requested in [0, u32::MAX] {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let conn = TerminalConn::new(tx);
            conn.handle(&frame(Type::Open, requested, br#"{"cols":100,"rows":30,"shell":"/bin/sh"}"#));
            let opened = parse(&rx.blocking_recv().unwrap()).unwrap();
            assert_eq!(opened.kind, Type::OpenResp);
            assert_eq!(json_of(&opened.payload)["code"], 0);
            assert_ne!(opened.session, 0);
            if requested != 0 {
                assert_eq!(opened.session, requested);
            }

            let (list_tx, mut list_rx) = tokio::sync::mpsc::unbounded_channel();
            TerminalConn::new(list_tx).handle(&frame(Type::ListReq, 7, &[]));
            let listed = parse(&list_rx.try_recv().unwrap()).unwrap();
            let sessions: Vec<serde_json::Value> = serde_json::from_slice(&listed.payload).unwrap();
            let session = sessions.iter().find(|item| item["session_id"] == opened.session).unwrap();
            assert_eq!(session["shell"], "/bin/sh");
            assert_eq!(session["state"], "running");

            conn.handle(&frame(Type::Stdin, opened.session, b"echo uu-term-ok; exit 3\n"));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut seen = Vec::new();
            let mut exit = None;
            while std::time::Instant::now() < deadline && exit.is_none() {
                match rx.try_recv() {
                    Ok(packet) => {
                        let frame = parse(&packet).unwrap();
                        assert_eq!(frame.session, opened.session);
                        match frame.kind {
                            Type::Stdout => seen.extend(frame.payload),
                            Type::Exit => exit = Some(json_of(&frame.payload)["exit_code"].clone()),
                            _ => {}
                        }
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
            assert!(String::from_utf8_lossy(&seen).contains("uu-term-ok"));
            assert_eq!(exit, Some(serde_json::json!(3)));
        }
    }

    #[test]
    fn redraw_shrinks_then_restores_the_latest_size() {
        let pty = nix::pty::openpty(None, None).unwrap();
        let term = Arc::new(Term { id: u32::MAX - 2, shell: "/bin/sh".into(), started_ms: now_ms(), group: 0, master: pty.master,
            link: Mutex::new(None), journal: Mutex::new(VecDeque::new()), window: Mutex::new((80, 24)) });
        let rows = |term: &Term| {
            let mut size = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
            unsafe { libc::ioctl(term.master.as_raw_fd(), libc::TIOCGWINSZ as _, &mut size) };
            (size.ws_col, size.ws_row)
        };
        term.resize(100, 30);
        term.nudge_redraw();
        assert_eq!(rows(&term), (100, 29));
        term.resize(120, 40);
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(rows(&term), (120, 40), "恢复时必须用最新的请求尺寸");
    }
}
