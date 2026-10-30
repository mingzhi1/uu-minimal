//! 控制端 Socket.IO / Engine.IO 客户端：`control`（带二进制 ConnectOptions）→ ack，
//! `soac` 收发 candidate/offer/answer。
//!
//! 官方 host 可能用二进制事件（`451-` + 附件）回 answer，附件按 base64 替换进 JSON，
//! 这样 `rtc::answer_sdp` 里的 gzip_sdp 解码能照常工作。

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

/// capture_type：1 桌面、8 终端、9 端口映射。
pub const CAPTURE_TERMINAL: u32 = 8;
pub const CAPTURE_PORT_MAP: u32 = 9;
const CLIENT_VERSION: &str = "4.42.0.2770";

pub struct Signal {
    out: mpsc::Sender<Message>,
    ack: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    next: AtomicU64,
}

impl Signal {
    pub async fn connect(
        server: &str,
        room_token: &str,
        timeout: Duration,
        events: mpsc::Sender<Value>,
        closed: watch::Sender<bool>,
    ) -> Result<Arc<Self>, String> {
        let url = format!("{}/socket.io/?transport=websocket&EIO=4", server.trim_end_matches('/'));
        let mut request = url.into_client_request().map_err(|_| "信令 URL 无效")?;
        request
            .headers_mut()
            .insert("X-NRD-AUTH", room_token.parse().map_err(|_| "房间票据无法放进请求头")?);
        let (socket, _) = tokio::time::timeout(timeout, connect_async(request))
            .await
            .map_err(|_| "信令连接超时")?
            .map_err(|_| "信令连接失败")?;
        let (mut write, mut read) = socket.split();
        let (out, mut out_rx) = mpsc::channel::<Message>(64);
        let ack: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> = Arc::new(Mutex::new(HashMap::new()));

        let write_closed = closed.clone();
        tokio::spawn(async move {
            while let Some(message) = out_rx.recv().await {
                if write.send(message).await.is_err() {
                    break;
                }
            }
            // 写端退出就等于这条路已经不可用（对端关闭 / 网络断）。
            let _ = write_closed.send(true);
        });

        let writer = out.clone();
        let acks = ack.clone();
        // 服务端 `40{"sid":…}` 才是 Socket.IO 命名空间连上的标志；control 必须等它，否则会丢。
        let (ready_tx, ready_rx) = oneshot::channel::<()>();
        let ready = Arc::new(Mutex::new(Some(ready_tx)));
        let ready_reader = ready.clone();
        let read_closed = closed.clone();
        tokio::spawn(async move {
            let mut window = Duration::from_secs(45);
            let mut deadline = tokio::time::Instant::now() + window;
            loop {
                let message = tokio::select! {
                    _ = events.closed() => break,
                    _ = tokio::time::sleep_until(deadline) => {
                        log::warn!("信令心跳超时");
                        break;
                    }
                    message = read.next() => message,
                };
                let Some(Ok(message)) = message else { break };
                let Message::Text(text) = message else { continue };
                if log::log_enabled!(log::Level::Trace) {
                    log::trace!("<- {} ({}B)", frame_summary(&text), text.len());
                }

                if text.starts_with('0') {
                    if let Ok(open) = serde_json::from_str::<Value>(&text[1..]) {
                        if let (Some(interval), Some(pong)) = (
                            open.get("pingInterval").and_then(Value::as_u64),
                            open.get("pingTimeout").and_then(Value::as_u64),
                        ) {
                            window = Duration::from_millis(interval.saturating_add(pong).clamp(5_000, 300_000));
                            deadline = tokio::time::Instant::now() + window;
                        }
                    }
                    let _ = writer.try_send(Message::Text("40".to_owned()));
                } else if text.starts_with("40") {
                    if let Some(tx) = ready_reader.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                } else if text.starts_with('2') {
                    deadline = tokio::time::Instant::now() + window;
                    let _ = writer.try_send(Message::Text(format!("3{}", &text[1..])));
                } else if let Some(rest) = text.strip_prefix("43") {
                    let Some(begin) = rest.find('[') else { continue };
                    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&rest[begin..]) else { continue };
                    let id = rest[..begin].parse::<u64>().unwrap_or(0);
                    // `control` 的 ack 是 `["success", body]`；`room_info` 的 ack 直接给对象。
                    let body = match items.first().and_then(Value::as_str) {
                        Some("success") => items.get(1).cloned().unwrap_or(Value::Null),
                        Some("error") => {
                            log::warn!("信令返回 error（内容不打印）");
                            continue;
                        }
                        _ => items.first().cloned().unwrap_or(Value::Null),
                    };
                    if let Some(tx) = acks.lock().unwrap().remove(&id) {
                        let _ = tx.send(body);
                    }
                } else if text.starts_with("45") || text.starts_with("46") {
                    let binary_ack = text.starts_with("46");
                    let rest = &text[2..];
                    let attachments = match rest.find('-') {
                        Some(dash) => {
                            let count = rest[..dash].parse::<usize>().unwrap_or(0).min(16);
                            Some((count, &rest[dash + 1..]))
                        }
                        None => None,
                    };
                    let (count, tail) = attachments.unwrap_or((0, rest));
                    let Some(begin) = tail.find('[') else { continue };
                    let id = tail[..begin].parse::<u64>().unwrap_or(0);
                    let Ok(mut payload) = serde_json::from_str::<Value>(&tail[begin..]) else { continue };
                    if count > 0 {
                        let mut frames = Vec::new();
                        while frames.len() < count {
                            match read.next().await {
                                Some(Ok(Message::Binary(bytes))) => frames.push(bytes.to_vec()),
                                _ => break,
                            }
                        }
                        substitute(&mut payload, &frames);
                    }
                    if binary_ack {
                        if let Some(tx) = acks.lock().unwrap().remove(&id) {
                            let value = payload.get(1).cloned().unwrap_or(Value::Null);
                            let _ = tx.send(value);
                        }
                    } else if events.send(payload).await.is_err() {
                        break;
                    }
                } else if let Some(rest) = text.strip_prefix("42") {
                    if let Ok(payload) = serde_json::from_str::<Value>(rest) {
                        if events.send(payload).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // 读任务退出：心跳超时、连接关闭或事件无人接收，都说明会话已经不可用。
            let _ = read_closed.send(true);
        });

        // 命名空间没连上就发 control，云端不会回 ack（表现为“等待 control ack 超时”）。
        tokio::time::timeout(timeout, ready_rx)
            .await
            .map_err(|_| "信令握手超时：未收到 Socket.IO connect 确认")?
            .map_err(|_| "信令连接已关闭".to_string())?;
        Ok(Arc::new(Self { out, ack, next: AtomicU64::new(1) }))
    }

    /// `control` + 一帧二进制 ConnectOptions；返回 ack 体（含 iceServers / client_id / ice_id）。
    pub async fn control(&self, app_id: &str, device: &str, capture_type: u32) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let streamer = json!({
            "control_id": app_id,
            "device_capability": {"display_info": [], "ice_id": "", "video_codec_capability": []},
        });
        let header = json!({
            "app_control_id": app_id,
            "app_data": {"_placeholder": true, "num": 0},
            "streamer_data": streamer.to_string(),
        });
        let (tx, rx) = oneshot::channel();
        self.ack.lock().unwrap().insert(id, tx);
        self.out
            .send(Message::Text(format!("451-{id}{}", json!(["control", header]))))
            .await
            .map_err(|_| "信令已断开")?;
        // 附件必须以 0x04 开头（老版 Engine.IO 的分帧前缀，官方 viewer 就是这么发的）。
        // 少了这个字节，官方 host 解析出的 ConnectOptions 是废的，`be-controlled` 不落地，
        // 后续 offer 直接被丢弃——表现为 control ack 之后再也没有任何下行信令。
        let mut options = vec![4u8];
        options.extend_from_slice(&connect_options(capture_type, device));
        self.out
            .send(Message::Binary(options))
            .await
            .map_err(|_| "信令已断开")?;
        tokio::time::timeout(Duration::from_secs(15), rx)
            .await
            .map_err(|_| "等待 control ack 超时")?
            .map_err(|_| "信令已断开".to_string())
    }

    /// 房间成员自报家门。云端回 `{publisher, subscribers, you, iceServers}`，
    /// `you.client_id` 是本端路由 id。
    pub async fn room_info(&self) -> Result<Value, String> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.ack.lock().unwrap().insert(id, tx);
        self.out
            .send(Message::Text(format!("42{id}[\"room_info\"]")))
            .await
            .map_err(|_| "信令已断开")?;
        tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| "等待 room_info ack 超时")?
            .map_err(|_| "信令已断开".to_string())
    }

    pub async fn soac(&self, value: Value) -> Result<(), String> {
        let packet = format!("42[\"soac\",{value}]");
        self.out.send(Message::Text(packet)).await.map_err(|_| "信令已断开".to_string())
    }
}

/// ConnectOptions：字段 1 capture_type、8 platform、9 device、10 1、12 客户端版本；
/// 终端（8）额外带 2 = u64::MAX（官方 viewer 的形态）。platform 跟随配置（3 = Windows，4 = macOS）。
fn connect_options(capture_type: u32, device: &str) -> Vec<u8> {
    let mut out = Vec::new();
    int(1, u64::from(capture_type), &mut out);
    if capture_type == CAPTURE_TERMINAL {
        int(2, u64::MAX, &mut out);
    }
    int(8, crate::cloud::config::platform().connect_id(), &mut out);
    bytes(9, device.as_bytes(), &mut out);
    int(10, 1, &mut out);
    bytes(12, CLIENT_VERSION.as_bytes(), &mut out);
    out
}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn int(field: u32, value: u64, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3, out);
    varint(value, out);
}

fn bytes(field: u32, value: &[u8], out: &mut Vec<u8>) {
    varint((u64::from(field) << 3) | 2, out);
    varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

/// 入站帧摘要：engine.io / socket.io 前缀 + 事件名。不含业务内容（SDP、凭据不进日志）。
fn frame_summary(text: &str) -> String {
    let mut out: String = text.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').take(8).collect();
    if let Some(begin) = text.find('[') {
        if let Some(name) = text[begin..].strip_prefix("[\"").and_then(|rest| rest.split('"').next()) {
            out.push(' ');
            out.extend(name.chars().take(24));
        }
    }
    out
}

/// Socket.IO 二进制附件：把 `{"_placeholder":true,"num":n}` 换成附件 n 的 base64。
fn substitute(value: &mut Value, attachments: &[Vec<u8>]) {
    use base64::Engine;
    match value {
        Value::Array(items) => {
            for item in items {
                substitute(item, attachments);
            }
        }
        Value::Object(map) => {
            if map.get("_placeholder").and_then(Value::as_bool) == Some(true) {
                if let Some(bytes) = map.get("num").and_then(Value::as_u64).and_then(|n| attachments.get(n as usize)) {
                    *value = Value::String(base64::engine::general_purpose::STANDARD.encode(bytes));
                    return;
                }
            }
            for (_, item) in map.iter_mut() {
                substitute(item, attachments);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_options_use_observed_field_numbers() {
        use crate::proto::read_fields;
        // read_fields 借用入参，先绑定再解码。
        let port_map = connect_options(CAPTURE_PORT_MAP, "dev");
        let fields = read_fields(&port_map).unwrap();
        let numbers: Vec<u32> = fields.iter().map(|f| f.number).collect();
        assert_eq!(numbers, vec![1, 8, 9, 10, 12]);
        let terminal_options = connect_options(CAPTURE_TERMINAL, "dev");
        let terminal = read_fields(&terminal_options).unwrap();
        assert_eq!(terminal.iter().map(|f| f.number).collect::<Vec<_>>(), vec![1, 2, 8, 9, 10, 12]);
    }

    #[test]
    fn frame_summary_keeps_the_event_name_and_drops_the_payload() {
        assert_eq!(frame_summary("42[\"soac\",{\"sdp\":\"v=0\"}]"), "42 soac");
        assert_eq!(frame_summary("451-1[\"control\",{}]"), "451-1 control");
        assert_eq!(frame_summary("0{\"sid\":\"x\"}"), "0");
        assert_eq!(frame_summary("2"), "2");
    }

    #[test]
    fn binary_attachments_are_base64_encoded_in_place() {
        let mut value = serde_json::json!({"data": {"gzip_sdp": {"_placeholder": true, "num": 0}}});
        substitute(&mut value, &[b"abc".to_vec()]);
        assert_eq!(value["data"]["gzip_sdp"], "YWJj");
    }
}
