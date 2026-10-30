//! 内嵌 SSH 客户端（russh）：把一条 `Message 27` 流当成 socket，直接跑 SSH，
//! 不需要 `~/.ssh/config`、也不需要系统 `ssh`。
//!
//! 主机密钥用自带的 TOFU 存储（`~/.config/uuremote/known_hosts`），首次连接打印指纹并记录，
//! 之后不一致就拒绝——不碰 `~/.ssh/known_hosts`。

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::{self, Config, Handle, Msg};
use russh::keys::PrivateKeyWithHashAlg;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::rtc::FlowHandle;

pub struct Options {
    pub user: String,
    pub port: u16,
    pub password: Option<String>,
    pub key: Option<PathBuf>,
    pub command: Option<String>,
    pub known_hosts: PathBuf,
}

/// 一条端口映射流 ⇄ SSH 的字节流。
struct Tunnel {
    out: mpsc::UnboundedSender<Option<Vec<u8>>>,
    input: mpsc::UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl Tunnel {
    fn new(flow: FlowHandle) -> Self {
        let (writer, mut reader) = flow.into_parts();
        let (out, mut out_rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        tokio::spawn(async move {
            while let Some(item) = out_rx.recv().await {
                match item {
                    Some(data) => {
                        if writer.send(&data).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = writer.fin().await;
                        break;
                    }
                }
            }
        });
        let (sink, input) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(chunk) = reader.recv().await {
                if sink.send(chunk).is_err() {
                    break;
                }
            }
        });
        Self { out, input, buf: Vec::new(), pos: 0 }
    }
}

impl AsyncRead for Tunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pos >= self.buf.len() {
            match self.input.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                // 对端 FIN / 连接断开 → 0 字节即 EOF。
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let count = out.remaining().min(self.buf.len() - self.pos);
        out.put_slice(&self.buf[self.pos..self.pos + count]);
        self.pos += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.out.send(Some(data.to_vec())) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "隧道已关闭"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.out.send(None);
        Poll::Ready(Ok(()))
    }
}

struct Verifier {
    host: String,
    port: u16,
    store: PathBuf,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let public = key.public_key();
        let material = public.to_openssh().unwrap_or_else(|_| format!("{public:?}"));
        let fingerprint = sha256_hex(material.as_bytes());
        match read_pin(&self.store, &self.host, self.port) {
            Some(pinned) if pinned == fingerprint => Ok(true),
            Some(_) => {
                log::error!("{}:{} 的主机密钥变了，拒绝连接（确认无误后从 {} 删掉那一行）", self.host, self.port, self.store.display());
                Ok(false)
            }
            None => {
                println!(
                    "首次连接 {}:{}，主机密钥 SHA256:{}…（已记录到 {}）",
                    self.host,
                    self.port,
                    &fingerprint[..16.min(fingerprint.len())],
                    self.store.display()
                );
                append_pin(&self.store, &self.host, self.port, &fingerprint);
                Ok(true)
            }
        }
    }
}

pub async fn run(flow: FlowHandle, host: &str, options: Options) -> Result<(), String> {
    let tunnel = Tunnel::new(flow);
    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(15)),
        ..Default::default()
    });
    let verifier = Verifier { host: host.to_owned(), port: options.port, store: options.known_hosts.clone() };
    let mut handle: Handle<Verifier> = client::connect_stream(config, tunnel, verifier)
        .await
        .map_err(|e| format!("SSH 握手失败: {e}"))?;
    authenticate(&mut handle, &options).await?;

    let channel: russh::Channel<Msg> = handle.channel_open_session().await.map_err(|e| format!("打开会话通道失败: {e}"))?;
    match &options.command {
        Some(command) => {
            channel.exec(true, command.clone()).await.map_err(|e| format!("执行命令失败: {e}"))?;
        }
        None => {
            let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
            let (cols, rows) = window_size();
            channel
                .request_pty(true, &term, cols, rows, 0, 0, &[])
                .await
                .map_err(|e| format!("申请 PTY 失败: {e}"))?;
            channel.request_shell(true).await.map_err(|e| format!("打开 shell 失败: {e}"))?;
        }
    }

    // 交互式会话把本地终端切成 raw，避免本地回显和 Ctrl-C 干扰远端 shell。
    let raw = if options.command.is_none() { Some(RawMode::enable()) } else { None };
    let stream = channel.into_stream();
    let (mut read, mut write) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let up = async {
        let _ = tokio::io::copy(&mut stdin, &mut write).await;
        let _ = write.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut read, &mut stdout).await;
    };
    tokio::pin!(up, down);
    tokio::select! {
        // 远端先结束：直接收工（up 被 drop）。
        _ = &mut down => {}
        // 本地 stdin EOF（Ctrl-D）：关掉写方向，继续读剩余输出。
        _ = &mut up => { let _ = (&mut down).await; }
    }
    drop(raw);
    Ok(())
}

async fn authenticate(handle: &mut Handle<Verifier>, options: &Options) -> Result<(), String> {
    if let Some(password) = options.password.as_deref() {
        match handle.authenticate_password(options.user.as_str(), password).await {
            Ok(client::AuthResult::Success) => return Ok(()),
            Ok(_) => log::warn!("密码认证被拒绝"),
            Err(e) => log::warn!("密码认证失败: {e}"),
        }
    }

    if let Some(path) = options.key.clone().or_else(default_key) {
        match russh::keys::load_secret_key(&path, None) {
            Ok(key) => {
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), Some(russh::keys::HashAlg::Sha256));
                match handle.authenticate_publickey(options.user.as_str(), key).await {
                    Ok(client::AuthResult::Success) => return Ok(()),
                    Ok(_) => log::warn!("公钥被拒绝: {}", path.display()),
                    Err(e) => log::warn!("公钥认证失败: {e}"),
                }
            }
            Err(_) => log::warn!("读不了私钥 {}（加密私钥暂不支持，可加 --password）", path.display()),
        }
    }

    if let Some(password) = prompt_password(options.user.as_str()) {
        if let Ok(client::AuthResult::Success) = handle.authenticate_password(options.user.as_str(), password).await {
            return Ok(());
        }
    }
    Err("SSH 认证失败".into())
}

fn default_key() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .find(|path| path.exists())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn pin_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

fn read_pin(store: &Path, host: &str, port: u16) -> Option<String> {
    let text = std::fs::read_to_string(store).ok()?;
    let wanted = pin_key(host, port);
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next()? == wanted).then(|| parts.next().map(str::to_owned)).flatten()
    })
}

fn append_pin(store: &Path, host: &str, port: u16, fingerprint: &str) {
    use std::io::Write;
    if let Some(dir) = store.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(store) {
        let _ = writeln!(file, "{} {}", pin_key(host, port), fingerprint);
    }
}

/// 本地终端 raw 模式，Drop 时恢复。
struct RawMode {
    saved: libc::termios,
    active: bool,
}

impl RawMode {
    fn enable() -> Self {
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut saved) != 0 {
                return Self { saved, active: false };
            }
            let mut raw = saved;
            libc::cfmakeraw(&mut raw);
            let active = libc::tcsetattr(0, libc::TCSANOW, &raw) == 0;
            Self { saved, active }
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &self.saved);
            }
        }
    }
}

fn window_size() -> (u32, u32) {
    unsafe {
        let mut size: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut size) == 0 && size.ws_col > 0 && size.ws_row > 0 {
            (u32::from(size.ws_col), u32::from(size.ws_row))
        } else {
            (80, 24)
        }
    }
}

fn prompt_password(user: &str) -> Option<String> {
    use std::io::{BufRead, Write};
    if !stdin_is_tty() {
        return None;
    }
    print!("{user} 的密码: ");
    let _ = io::stdout().flush();
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let active = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if active {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &quiet);
        }
    }
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    if active {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &saved);
        }
    }
    println!();
    Some(line.trim_end_matches(['\r', '\n']).to_owned()).filter(|text| !text.is_empty())
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}
