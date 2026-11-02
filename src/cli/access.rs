//! 控制端工具：`portmap` / `ssh` / `sftp` / `tunnel`。

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
    // 本地 listener 只绑一次：重连的是信令/WebRTC，本地端口不能跟着变，
    // 否则调用方（浏览器、ssh 客户端）还得重新指一遍。
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local))
        .await
        .map_err(|e| format!("监听 127.0.0.1:{local} 失败: {e}"))?;
    println!("{}", ui::bold("隧道就绪"));
    println!("  127.0.0.1:{local} → {host}:{port}");
    ui::hint("  Ctrl-C 退出");

    // 链路断掉（TURN 分配被回收、云端回收房间…）就重建，而不是退出让用户重跑。
    // 已在传的连接没法救——它们的流在旧 peer 上——但新连接立刻可用。
    let mut attempt: u32 = 0;
    loop {
        let session = match controller::join(&api, device, controller::signal::CAPTURE_PORT_MAP).await {
            Ok(session) => {
                if attempt > 0 {
                    log::info!("隧道已重建（第 {attempt} 次重试后）");
                }
                attempt = 0;
                session
            }
            Err(error) => {
                // 指数退避，上限 30s：云端短暂故障时不要打爆 join 接口。
                let delay = reconnect_delay(attempt);
                attempt = attempt.saturating_add(1);
                log::warn!("重建隧道失败（{error}），{}s 后重试", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        };
        let mut closed = session.closed.clone();
        let self_failure_flag = Arc::new(AtomicU32::new(0));
        let mut failure_tick = tokio::time::interval(LIVENESS_TICK);
        failure_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // 信令/WebRTC 断了就不再接新连接：否则本地 accept 成功、对端却永远没数据。
            let (socket, _) = tokio::select! {
                _ = closed.changed() => {
                    log::warn!("链路断开，重建隧道");
                    break;
                }
                _ = failure_tick.tick() => {
                    // 连续 3 次建流失败（每次都要等 SYN_ACK 超时）就认定链路已死。
                    // 单次失败可能只是目标服务没起来，不能据此重连。
                    let failures = self_failure_flag.load(Ordering::Relaxed);
                    if failures >= 3 {
                        log::warn!("连续 {failures} 次建流失败，判定链路已断并重建隧道");
                        break;
                    }
                    continue;
                }
                accepted = listener.accept() => accepted.map_err(|e| e.to_string())?,
            };
            let peer = session.peer.clone();
            let host = host.clone();
            // 打流失败是最可靠的断线信号：TURN 分配被回收后 PeerConnection 仍报 Connected，
            // 状态回调不触发，`idle` 也不会涨（SCTP 心跳还在收）。只有真正建流才会暴露。
            let broken = self_failure_flag.clone();
            tokio::spawn(async move {
                match peer.open_flow(&host, port).await {
                    Ok(flow) => {
                        // 能建流说明链路是好的，把连续失败计数清零。
                        broken.store(0, Ordering::Relaxed);
                        pump_socket(socket, flow).await;
                    }
                    Err(e) => {
                        log::warn!("打开流失败: {e}");
                        broken.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
        // 断线后稍等一下再 join：云端回收房间也需要时间。
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// 重建退避：1s、2s、4s…封顶 30s。第一次重建不等待（链路断时云端通常已就绪）。
fn reconnect_delay(attempt: u32) -> Duration {
    let seconds = 1u64 << attempt.min(5);
    Duration::from_secs(seconds.min(30))
}

/// 多久检查一次「连续建流失败」计数器。
const LIVENESS_TICK: Duration = Duration::from_secs(15);

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
                Ok(0) | Err(_) => break,
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
    // 两个方向都跑完才算这条流结束。之前用 `select!` 意味着一方结束另一方立刻被取消：
    // 上行结束后不发 FIN，host 侧继续往这条流发数据，控制端收到一堆无法归属的帧
    // （`端口映射帧没有对应的流`）——iperf3 断开后刷几千条就是这个原因。
    tokio::join!(up, down);
    // 无论如何都要告诉 host 关流，否则它在目标连接上的读循环会一直跑。
    let _ = writer.fin().await;
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

#[cfg(test)]
mod tests {
    use super::reconnect_delay;
    use std::time::Duration;

    #[test]
    fn backoff_doubles_then_caps_at_thirty_seconds() {
        let seconds = |attempt| reconnect_delay(attempt).as_secs();
        assert_eq!(seconds(0), 1);
        assert_eq!(seconds(1), 2);
        assert_eq!(seconds(2), 4);
        assert_eq!(seconds(3), 8);
        assert_eq!(seconds(4), 16);
        // 封顶 30s：不能再翻倍到 32，否则云端恢复后要等半分钟才重连。
        assert_eq!(seconds(5), 30);
        assert_eq!(seconds(6), 30);
        assert_eq!(seconds(u32::MAX), 30);
    }

    #[test]
    fn first_retry_is_immediate_enough() {
        // 断线瞬间云端通常已经就绪，等一秒是给房间回收留的余量。
        assert!(reconnect_delay(0) <= Duration::from_secs(1));
    }
}
