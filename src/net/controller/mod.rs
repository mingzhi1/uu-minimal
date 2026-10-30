//! 控制端：join 房间 → `control` 拿 ICE → offer/answer → 打开通道。
//! `ssh` / `sftp` / `portmap` 都建立在这上面。

pub mod rtc;
pub mod signal;
pub mod ssh;

use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

use crate::cloud::api::Api;
use rtc::Peer;
use signal::Signal;

pub struct Session {
    /// 只要它活着，信令连接就不会被回收（事件泵在后台用它投递 soac）。
    #[allow(dead_code)]
    pub signal: Arc<Signal>,
    pub peer: Arc<Peer>,
    /// 信令或 PeerConnection 断开会变成 `true`（`changed()` 唤醒）。
    /// 控制端不做重连，调用方靠它知道“这条隧道已经废了”，而不是干等超时。
    pub closed: watch::Receiver<bool>,
}

/// 设备鉴权 + 建房 + 信令 + offer/answer，直到 FILE 通道可用。
pub async fn join(api: &Api, device: &str, capture_type: u32) -> Result<Session, String> {
    let room = api.join_room(device).await.map_err(|e| e.to_string())?;
    let server = room.server().to_owned();
    if server.is_empty() || room.token.is_empty() {
        return Err("房间信息不完整（缺信令地址或票据）".into());
    }
    // 断线通知：信令读/写任务退出、PeerConnection 进 Failed/Disconnected 都会把它置 true。
    let (closed_tx, closed_rx) = watch::channel(false);
    let (events, mut event_rx) = mpsc::channel::<Value>(256);
    let signal =
        Signal::connect(&server, &room.token, Duration::from_secs(10), events, closed_tx.clone()).await?;

    let app = uuid();
    // 先自报 room_info：官方 host 连上后也这么做。拿不到也不影响后续（ack 里有对端路由），
    // 只当作能力探测/调试信息。
    match signal.room_info().await {
        Ok(info) => log::debug!(
            "room_info: publisher={} subscribers={}",
            info.get("publisher").and_then(|p| p.get("role")).and_then(Value::as_str).unwrap_or("-"),
            info.get("subscribers").and_then(Value::as_array).map_or(0, Vec::len),
        ),
        Err(e) => log::warn!("room_info 失败（继续）: {e}"),
    }
    let ack = signal.control(&app, device, capture_type).await?;
    // 只记结构：TURN 凭据不能进日志。
    log::debug!(
        "control ack: code={} client_id={} ice_id={} ice_servers={} relay={}",
        ack.get("code").and_then(Value::as_i64).unwrap_or(-1),
        ack.get("client_id").and_then(Value::as_str).is_some(),
        ack.get("ice_id").and_then(Value::as_str).is_some(),
        ack.get("iceServers").and_then(Value::as_array).map_or(0, Vec::len),
        ack.get("force_relay").and_then(Value::as_bool).unwrap_or(false),
    );
    // 信封里的 `client_id` 是收件方：offer 发给 ack 指派的对端。
    let remote = ack
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("control ack 缺少 client_id（对端路由）")?
        .to_owned();
    // 官方云端在 ack 里指派 ice_id，不回显我们给的那个。
    let ice = ack
        .get("ice_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(str::to_owned)
        .unwrap_or_else(|| random_hex(16));
    let config = rtc::configuration(&ack)?;
    let peer = Arc::new(Peer::new(config, app, ice, remote, signal.clone(), closed_tx.clone()).await?);

    // 事件泵必须先挂上：answer 要经过它才会落到 PeerConnection。
    {
        let peer = peer.clone();
        let closed = closed_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if matches!(event_name(&event), Some("released" | "left" | "leave")) {
                    // 被控端/云端把这次会话收掉了；控制端不做重连，直接让调用方收工。
                    log::warn!("对端已释放连接");
                    break;
                }
                let payload = soac_payload(event);
                // 只记 type：SDP / 候选不进日志。
                let kind = payload
                    .get("data")
                    .and_then(|data| data.get("type"))
                    .or_else(|| payload.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("-");
                log::debug!("信令事件: {kind}");
                if let Err(e) = peer.receive(&payload).await {
                    log::warn!("处理信令事件失败: {e}");
                }
            }
            // 事件泵退出 = 信令任务结束（心跳超时 / 读端断开 / 对端释放）。
            let _ = closed.send(true);
        });
    }

    // offer 只发一次：官方 host 按 ice_id 一个 peer，重发的 offer 会让它重建连接，
    // 表现为 DTLS 已 Connected 但 data channel 一直不 Open。
    let offer = peer.offer().await?;
    signal.soac(offer).await?;
    if let Err(e) = peer.wait_channel(rtc::FILE_CHANNEL, Duration::from_secs(20)).await {
        log::warn!("通道状态: {:?}", peer.channel_states().await);
        return Err(e);
    }
    Ok(Session { signal, peer, closed: closed_rx })
}

/// Socket.IO 事件名（数组第 0 位）；用来区分 `soac` 与会话结束类事件。
fn event_name(event: &Value) -> Option<&str> {
    match event {
        Value::Array(items) => items.first().and_then(Value::as_str),
        _ => None,
    }
}

/// Socket.IO 事件 `["soac", {...}]`：事件名在 [0]，answer / 候选在 [1]；其它事件原样返回。
fn soac_payload(event: Value) -> Value {
    match event {
        Value::Array(items) if items.first().and_then(Value::as_str) == Some("soac") => {
            items.get(1).cloned().unwrap_or(Value::Null)
        }
        other => other,
    }
}

pub fn uuid() -> String {
    let mut bytes = [0u8; 16];
    random_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

pub fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    random_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_bytes(out: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = file.read_exact(out);
    }
}

#[cfg(test)]
mod tests {
    use super::soac_payload;
    use serde_json::json;

    #[test]
    fn soac_events_are_unwrapped_but_other_events_are_kept() {
        let soac = json!(["soac", {"data": {"type": "answer", "sdp": "v=0"}}]);
        assert_eq!(soac_payload(soac), json!({"data": {"type": "answer", "sdp": "v=0"}}));
        // 没有第二个元素时不 panic。
        assert_eq!(soac_payload(json!(["soac"])), serde_json::Value::Null);
        // released / left 这类事件原样交给上层。
        let released = json!(["released", {"reason": "bye"}]);
        assert_eq!(soac_payload(released.clone()), released);
    }
}
