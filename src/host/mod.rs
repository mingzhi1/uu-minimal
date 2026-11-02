//! 被控端：`run` 的房间循环，以及终端与端口映射两条数据通道。

pub mod file_transfer;
pub mod portmap;
/// 终端会话能力（openpty + shell）。`--no-default-features` 时退化成空实现，
/// 数据面代码不需要任何 `cfg`。
#[cfg(feature = "terminal")]
pub mod terminal;
#[cfg(not(feature = "terminal"))]
#[path = "terminal_stub.rs"]
pub mod terminal;

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use crate::cloud::api::{Api, RoomError};
use crate::cloud::config;
use crate::cloud::creds::Credentials;
use crate::net::ice;
use crate::net::peer;
use crate::net::signaling::{Event, Signaling};

/// `be-controlled` 到 offer 之间允许的最长间隔；超过就认为这份 ICE 配置已经没用了。
const ICE_TTL: Duration = Duration::from_secs(60);
/// 信令活够这么久才重置退避：连上就断的循环要继续累加，不能形成快速重试。
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// 重连退避：1s 起步、指数增长到 32s 封顶，再叠加最多 30% 抖动。
/// 云端发版重启时，所有设备不该在同一秒一起重试。
fn backoff(attempt: u32) -> Duration {
    let millis = (1u64 << attempt.saturating_sub(1).min(5)) * 1000;
    let jitter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as u64 % 300;
    Duration::from_millis(millis + millis * jitter / 1000)
}

pub async fn run() -> Result<(), String> {
    let file = config::read()?;
    let creds = Credentials::load(file.as_ref())?;
    log::info!("已加载本机凭据（内容不打印）");
    let api = Arc::new(Api::new(creds));

    let mut attempt = 0u32;
    let mut stopping = false;
    'rooms: loop {
        log::info!("向云端申请房间凭据…");
        let room = match api.create_room().await {
            Ok(room) => room,
            Err(RoomError::LoginExpired) => return Err("登录已失效，请重新执行 `uu-minimal login`".into()),
            Err(RoomError::Other(e)) => {
                attempt = attempt.saturating_add(1);
                let delay = backoff(attempt);
                log::error!("建房失败: {e}，{}s 后重试", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        };
        let server = room.server().to_owned();
        log::info!("拿到信令地址，开始 Socket.IO 握手");

        let (tx, mut rx) = mpsc::channel::<Event>(64);
        let signaling = match Signaling::connect(&server, &room.token, tx).await {
            Ok(signaling) => signaling,
            Err(e) => {
                attempt = attempt.saturating_add(1);
                let delay = backoff(attempt);
                log::error!("信令连接失败: {e}，{}s 后重试", delay.as_secs());
                tokio::time::sleep(delay).await;
                continue;
            }
        };
        let started = Instant::now();
        // 云端回收房间（房间级 `leave`）与真掉线分开计：前者是我们自己就要重建，
        // 不是故障。与前者一起累加退避的话，连着被回收几次之后每次都要等 30s，
        // 期间设备在云端就是离线的——别人再发起远控只会看到一直「正在连接」。
        let mut recycle = false;

        // 一个 ice_id = 一个 peer（桌面 / 文件 / 终端 / 端口映射各一条）。
        // pending_ice 带时间戳：凭据过期后不能拿来建连。
        let mut pending_ice: HashMap<String, (ice::SessionIce, u64, Instant)> = HashMap::new();
        let mut fallback_ice: Option<(ice::SessionIce, u64, Instant)> = None;
        // 表要交给 handler：连接断掉时由它摘掉自己，否则重连一次就多一条死 peer。
        let peers: Arc<StdMutex<HashMap<String, Arc<dyn webrtc::peer_connection::PeerConnection>>>> =
            Arc::new(StdMutex::new(HashMap::new()));

        loop {
            let event = tokio::select! {
                _ = tokio::signal::ctrl_c() => { stopping = true; break },
                event = rx.recv() => match event { Some(event) => event, None => break },
            };
            match event {
                Event::Connected => log::info!("信令就绪，等待遥控端接入"),
                Event::Connect { capture_type, ice_id, ice } => {
                    log::info!("准备接受连接: capture_type={capture_type} ice_id_present={}", ice_id.is_some());
                    match ice_id {
                        Some(id) => {
                            pending_ice.insert(id, (ice, capture_type, Instant::now()));
                        }
                        None => fallback_ice = Some((ice, capture_type, Instant::now())),
                    }
                }
                Event::Offer(soac) => {
                    let ice_id = soac.ice_id.as_ref().map(value_text).unwrap_or_default();
                    let client_id = soac.client_id.clone().unwrap_or_default();
                    // capture_type 和 ICE 配置一起记：offer 来的时候才知道这次是不是桌面（要不要推画面）。
                    let taken = pending_ice.remove(&ice_id).or_else(|| fallback_ice.take());
                    let Some((transport, capture_type, _)) = taken.filter(|(_, _, at)| at.elapsed() <= ICE_TTL) else {
                        // 没有 be-controlled 前置（或凭据已过期）就去建连，只会拿一份空 ICE
                        // 配置换回一条连不上的连接，不如明确拒绝。
                        log::error!("offer 没有可用的 be-controlled 前置（ice_id_present={}），拒绝", !ice_id.is_empty());
                        continue;
                    };
                    let sdp = soac.sdp.clone().unwrap_or_default();
                    match peer::answer(
                        &transport,
                        &sdp,
                        signaling.clone(),
                        client_id,
                        ice_id.clone(),
                        soac.app_control_id.clone(),
                        peers.clone(),
                        capture_type,
                    )
                    .await
                    {
                        Ok(pc) => {
                            // 同一 ice_id 重连时替换旧连接；guard 不能跨 await，先取出来再关。
                            let old = { peers.lock().unwrap().insert(ice_id.clone(), pc) };
                            if let Some(old) = old {
                                close_peer(&old).await;
                            }
                            let count = peers.lock().unwrap().len();
                            log::info!("已回复 answer: ice_id_present={} peers={count}", !ice_id.is_empty());
                        }
                        Err(e) => log::error!("处理 offer 失败: {e}"),
                    }
                }
                Event::Candidate(soac) => {
                    let ice_id = soac.ice_id.as_ref().map(value_text).unwrap_or_default();
                    let target = { peers.lock().unwrap().get(&ice_id).cloned() };
                    match target {
                        Some(pc) => {
                            if let Err(e) = peer::add_candidate(&pc, &soac).await {
                                log::warn!("{e}");
                            }
                        }
                        None => log::warn!("收到未知 ice_id 的候选，忽略"),
                    }
                }
                Event::Released(id) => {
                    log::info!("遥控端断开（仅清理对应连接）");
                    pending_ice.remove(&id);
                    let pc = { peers.lock().unwrap().remove(&id) };
                    if let Some(pc) = pc {
                        close_peer(&pc).await;
                    }
                }
                Event::Closed => {
                    log::warn!("信令断开，重建房间");
                    recycle = true;
                    break;
                }
            }
        }

        // 先把信令拆干净再重建：旧 WebSocket 留着，云端会把新房间的 leave 当成这台的。
        signaling.shutdown();
        let drained: Vec<Arc<dyn webrtc::peer_connection::PeerConnection>> = {
            peers.lock().unwrap().drain().map(|(_, pc)| pc).collect()
        };
        for pc in drained {
            close_peer(&pc).await;
        }
        drop(signaling);
        if stopping {
            break 'rooms;
        }
        // 活得够久说明链路是通的：重置退避，掉线后能快速回来；连上就断则继续累加，
        // 不会对云端形成 1s 一次的重试风暴。
        attempt = if recycle || started.elapsed() >= STABLE_SESSION {
            0
        } else {
            attempt.saturating_add(1)
        };
        let delay = backoff(attempt.max(1));
        log::info!("{}s 后重建房间", delay.as_secs());
        tokio::time::sleep(delay).await;
    }

    // Ctrl-C：交互式 shell 不响应 SIGTERM，这里显式收掉所有终端会话。
    terminal::shutdown_all();
    Ok(())
}

fn value_text(value: &Value) -> String {
    value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string())
}

/// `close()` 在连接已经卡死时可能一直不返回；卡住它会把整个重建房间的流程堵住。
async fn close_peer(pc: &Arc<dyn webrtc::peer_connection::PeerConnection>) {
    if tokio::time::timeout(Duration::from_secs(10), pc.close()).await.is_err() {
        log::warn!("关闭旧连接超时，继续恢复房间");
    }
}

// ---------------------------------------------------------------- 客户端子命令
