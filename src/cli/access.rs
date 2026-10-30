//! 控制端工具：`portmap` / `ssh` / `sftp` / `tunnel`。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::args::Args;
use crate::cli::current_user;
use crate::cli::ui;
use crate::cloud::api::Api;
use crate::cloud::config;
use crate::cloud::creds::Credentials;
use crate::net::controller::{self, rtc::FlowHandle, ssh as russh_client};

/// 信令或 WebRTC 链路断开时的统一提示（控制端不做重连，交给用户重跑）。
fn link_lost() -> String {
    "连接已断开：信令或 WebRTC 链路丢失".into()
}

pub async fn portmap_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let device = args.require_device()?;
    let positional = args.positionals();
    if positional.len() != 3 {
        return Err("用法: uu-minimal portmap --device <id> <本地端口> <目标主机> <目标端口>".into());
    }
    let local: u16 = positional[0].parse().map_err(|_| "本地端口无效".to_string())?;
    let port: u16 = positional[2].parse().map_err(|_| "目标端口无效".to_string())?;
    portmap_run(device, local, positional[1], port).await
}

pub async fn portmap_run(device: &str, local: u16, host: &str, port: u16) -> Result<(), String> {
    let host = host.to_owned();
    let api = loaded_api()?;
    let session = controller::join(&api, device, controller::signal::CAPTURE_PORT_MAP).await?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local))
        .await
        .map_err(|e| format!("监听 127.0.0.1:{local} 失败: {e}"))?;
    println!("{}", ui::bold("隧道就绪"));
    println!("  127.0.0.1:{local} → {host}:{port}");
    ui::hint("  Ctrl-C 退出");
    let mut closed = session.closed.clone();
    loop {
        // 信令/WebRTC 断了就不再接新连接：否则本地 accept 成功、对端却永远没数据。
        let (socket, _) = tokio::select! {
            _ = closed.changed() => return Err(link_lost()),
            accepted = listener.accept() => accepted.map_err(|e| e.to_string())?,
        };
        let peer = session.peer.clone();
        let host = host.clone();
        tokio::spawn(async move {
            match peer.open_flow(&host, port).await {
                Ok(flow) => pump_socket(socket, flow).await,
                Err(e) => log::warn!("打开流失败: {e}"),
            }
        });
    }
}

/// 内嵌 SSH（russh）：一条端口映射流直接当 socket，不碰 `~/.ssh/config`。

pub async fn ssh_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let device = args.require_device()?;
    let positional = args.positionals();
    if positional.len() > 1 {
        return Err(
            "用法: uu-minimal ssh --device <id> [--user 用户] [--port 22] [--key 私钥] [--command 命令] [主机]".into(),
        );
    }
    let (default_host, default_port) = config::ssh_target();
    let host = positional.first().map(|host| (*host).to_owned()).unwrap_or(default_host);
    let port = match args.value("--port") {
        Some(value) => value.parse::<u16>().map_err(|_| format!("--port 不是有效端口: {value}"))?,
        None => default_port,
    };
    let user = args.value("--user").map(str::to_owned).unwrap_or_else(current_user);
    ssh_session(
        device,
        &host,
        port,
        &user,
        args.value("--key").map(std::path::PathBuf::from),
        args.value("--command").map(str::to_owned),
        args.value("--password").map(str::to_owned),
    )
    .await
}

async fn ssh_session(
    device: &str,
    host: &str,
    port: u16,
    user: &str,
    key: Option<std::path::PathBuf>,
    command: Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    let user = if user.trim().is_empty() { current_user() } else { user.trim().to_owned() };
    let api = loaded_api()?;
    let session = controller::join(&api, device, controller::signal::CAPTURE_PORT_MAP).await?;
    let flow = session.peer.open_flow(host, port).await?;
    let known_hosts = config::path().with_file_name("known_hosts");
    let mut closed = session.closed.clone();
    let run = russh_client::run(
        flow,
        host,
        russh_client::Options { user, port, password, key, command, known_hosts },
    );
    tokio::select! {
        result = run => result,
        // 链路断了要报错退出，不能让本地终端卡在一个已经死掉的会话上。
        _ = closed.changed() => Err(link_lost()),
    }
}

/// stdio 桥：给 `ssh -o ProxyCommand=…` / `sftp -o ProxyCommand=…` 用。

pub async fn tunnel_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let device = args.require_device()?;
    let positional = args.positionals();
    if positional.len() != 2 {
        return Err("用法: uu-minimal tunnel --device <id> <主机> <端口>".into());
    }
    let host = positional[0];
    let port: u16 = positional[1].parse().map_err(|_| "端口无效".to_string())?;

    let api = loaded_api()?;
    let session = controller::join(&api, device, controller::signal::CAPTURE_PORT_MAP).await?;
    let flow = session.peer.open_flow(host, port).await?;
    let (writer, mut reader) = flow.into_parts();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = writer.fin().await;
                    break;
                }
                Ok(n) => {
                    if writer.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let down = async {
        while let Some(chunk) = reader.recv().await {
            if stdout.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    };
    let mut closed = session.closed.clone();
    tokio::select! {
        _ = up => {}
        _ = down => {}
        // stdio 桥是给 `ssh`/`sftp` 当 ProxyCommand 用的：链路断了必须非零退出。
        _ = closed.changed() => return Err(link_lost()),
    }
    Ok(())
}

pub async fn sftp_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let device = args.require_device()?;
    // 其余位置参数原样交给系统 sftp（`用户@主机`、路径、-P 之类）。
    let extra: Vec<String> = args.positionals().into_iter().map(str::to_owned).collect();
    spawn_sftp(device, &extra).await
}

async fn spawn_sftp(device: &str, extra: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("找不到自身路径: {e}"))?;
    let proxy = format!("{} tunnel --device {} %h %p", exe.display(), device);
    let mut command = tokio::process::Command::new("sftp");
    command.arg("-o").arg(format!("ProxyCommand={proxy}")).args(extra);
    let status = command.status().await.map_err(|e| format!("启动 sftp 失败: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("sftp 退出码 {}", status.code().unwrap_or(-1)))
    }
}

async fn pump_socket(socket: tokio::net::TcpStream, flow: FlowHandle) {
    let (writer, mut reader) = flow.into_parts();
    let (mut read, mut write) = socket.into_split();
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = writer.fin().await;
                    break;
                }
                Ok(n) => {
                    if writer.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let down = async {
        while let Some(chunk) = reader.recv().await {
            if write.write_all(&chunk).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

pub fn loaded_api() -> Result<Api, String> {
    let file = config::read()?;
    Ok(Api::new(Credentials::load(file.as_ref())?))
}

// ---------------------------------------------------------------- 命令行参数


pub async fn exec_ssh(device: &str, host: &str, port: u16, user: &str) -> Result<(), String> {
    ssh_session(device, host, port, user, None, None, None).await
}

pub async fn exec_sftp(device: &str, host: &str, user: &str, path: &str) -> Result<(), String> {
    let target = if user.trim().is_empty() { host.to_owned() } else { format!("{}@{}", user.trim(), host) };
    let target = if path.trim().is_empty() { target } else { format!("{target}:{}", path.trim()) };
    spawn_sftp(device, &[target]).await
}
