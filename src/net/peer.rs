//! 组网的数据面：收 offer → 回 answer，并把本地 ICE 候选逐个发回。
//! host 永远是 DTLS Server（a=setup:passive），和官方 host 一致。
//! 这里只建连接，不采集画面、不注入输入——那是主程序的事。

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use rtc::ice::mdns::MulticastDnsMode;
use rtc::peer_connection::transport::RTCDtlsRole;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCIceCandidateInit,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, SettingEngineBuilder,
};

use crate::host::portmap;
use crate::host::file_transfer;
use crate::host::terminal::{self, TerminalConn};
use crate::net::ice::SessionIce;
use crate::net::signaling::{Signaling, Soac};
use crate::proto::{self, Value as WireValue};

const FILE_DATA_CHANNEL: &str = "FILE_DATA_CHANNEL";
const BINARY_DATA_CHANNEL: &str = "BINARY_DATA_CHANNEL";
/// 无序快通道（块级 FEC + NACK），只在我们自己的 viewer 打开 `UU_FAST=1` 时出现。
const FAST_DATA_CHANNEL: &str = "FAST_DATA_CHANNEL";

/// viewer（libwebrtc）默认按 64 KB 处理 data channel 单条消息；webrtc-rs 不写
/// a=max-message-size，端口映射的大帧会被对端拒绝，所以只对发给对端的那份 SDP 补一行。
const MAX_MESSAGE_SIZE: usize = 262_144;

/// 连接级事件。0.21 把 `set_*_handler(闭包)` 换成了实现 `PeerConnectionEventHandler`，
/// 共享状态只能挂在 handler 上，通过 `with_handler` 交进去。
struct Events {
    signal: Arc<Signaling>,
    client: String,
    ice: String,
    control: Option<Value>,
    bundle: Arc<Mutex<Option<(String, u16)>>>,
    channels: Arc<StdMutex<HashMap<String, Arc<dyn DataChannel>>>>,
    file_channel: Arc<StdMutex<Option<Arc<dyn DataChannel>>>>,
    mapping: Arc<portmap::Session>,
    files: Arc<file_transfer::Session>,
    outbox: mpsc::UnboundedSender<(String, Vec<u8>)>,
    terminal: Arc<TerminalConn>,
    sequence: Arc<AtomicU64>,
    /// Wakes `drain_outbox` as soon as a channel opens instead of polling.
    ready: Arc<tokio::sync::Notify>,
    /// 房间循环持有的 peer 表。断线时由这里把死连接摘掉，
    /// 否则 viewers 换 ice_id 反复重连，表里会一直堆着死 peer。
    peers: Arc<StdMutex<HashMap<String, Arc<dyn PeerConnection>>>>,
}

impl Drop for Events {
    /// peer 被拆除时兜底收掉端口映射：`pc.close()` 不一定触发状态回调，
    /// 不兜底的话指向目标机的 TCP 连接会一直挂着（读任务持有 Session）。
    fn drop(&mut self) {
        self.mapping.shutdown();
    }
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Events {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let Ok(init) = event.candidate.to_json() else { return };
        let Some((mid, mline)) = self.bundle.lock().await.clone() else {
            log::warn!("候选早于 BUNDLE 协商，丢弃");
            return;
        };
        let soac = Soac {
            kind: "candidate".into(),
            candidate: Some(json!({
                "candidate": init.candidate,
                "sdpMid": mid,
                "sdpMLineIndex": mline,
            })),
            ice_id: Some(Value::String(self.ice.clone())),
            client_id: (!self.client.is_empty()).then_some(self.client.clone()),
            app_control_id: self.control.clone(),
            ..Default::default()
        };
        if let Err(e) = self.signal.emit_soac(&soac).await {
            log::error!("发送本地候选失败: {e}");
        }
    }

    async fn on_ice_connection_state_change(&self, state: rtc::peer_connection::state::RTCIceConnectionState) {
        log::info!("ICE 状态: {state:?}");
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        log::info!("PeerConnection 状态: {state:?}");
        if matches!(
            state,
            RTCPeerConnectionState::Closed | RTCPeerConnectionState::Failed | RTCPeerConnectionState::Disconnected
        ) {
            self.mapping.shutdown();
            // 只从表里摘掉、不在这里 close：这个回调是 driver 调的，在它里面 await
            // 关闭自己就有死锁风险。Failed/Disconnected 的连接由 driver 自己收尾。
            let _dead = { self.peers.lock().unwrap().remove(&self.ice) };
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let Ok(label) = channel.label().await else { return };
        log::info!("对端打开 data channel: {label}");
        self.channels.lock().unwrap().insert(label.clone(), channel.clone());
        self.ready.notify_waiters();
        if label == FILE_DATA_CHANNEL {
            *self.file_channel.lock().unwrap() = Some(channel.clone());
        }
        if label == FAST_DATA_CHANNEL {
            self.mapping.attach_fast(channel.clone());
        }
        // 0.21 没有 `on_message` 回调了：每条通道起一个任务不停 `poll()`。
        let (outbox, terminal, mapping, files, sequence) = (
            self.outbox.clone(),
            self.terminal.clone(),
            self.mapping.clone(),
            self.files.clone(),
            self.sequence.clone(),
        );
        tokio::spawn(async move {
            while let Some(event) = channel.poll().await {
                if let DataChannelEvent::OnMessage(message) = event {
                    dispatch(&label, message.data.to_vec(), &outbox, &terminal, &mapping, &files, &sequence).await;
                }
            }
        });
    }
}

/// 处理一条 offer：建 PeerConnection、回 answer，后续候选由 handler 自己发。
pub async fn answer(
    ice: &SessionIce,
    offer_sdp: &str,
    signaling: Arc<Signaling>,
    client_id: String,
    ice_id: String,
    app_control_id: Option<Value>,
    // 房间的 peer 表；这条连接断掉时由 handler 把死条目摘掉。
    peers: Arc<StdMutex<HashMap<String, Arc<dyn PeerConnection>>>>,
    _capture_type: u64,
) -> Result<Arc<dyn PeerConnection>, String> {
    if offer_sdp.is_empty() {
        return Err("offer SDP 为空".into());
    }

    let mut media = MediaEngine::default();
    // 不推画面：只用默认编解码，保证 answer 不会拒掉对端的媒体段。
    media.register_default_codecs().map_err(|e| format!("注册默认编解码失败: {e}"))?;

    // 0.21 的 SettingEngine 改成 builder 风格：原来的 set_*(..) -> Result 变成
    // with_*(..) -> Self，链式配置。
    let settings = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Server)
        // mDNS 关掉：直接给真实网卡候选，和官方 host 一样。
        .with_multicast_dns_mode(MulticastDnsMode::Disabled)
        // 网卡过滤在 0.21 里改由 with_udp_addrs 承担（见 ice::udp_bind_addrs）。
        .build();

    // 候选要带 sdpMid / sdpMLineIndex；webrtc-rs 的 to_json() 固定给空 mid，
    // 所以从 answer 的 BUNDLE 首段自己算，收集开始前先填好。
    let bundle: Arc<Mutex<Option<(String, u16)>>> = Arc::new(Mutex::new(None));

    // ---- data channel 分发：终端（裸 TERM 帧 + Message 21 RPC）与端口映射（Message 27）----
    // 每个 peer 一个出口队列；发送时按通道名找已打开的 data channel。
    let channels: Arc<StdMutex<HashMap<String, Arc<dyn DataChannel>>>> = Arc::new(StdMutex::new(HashMap::new()));
    let file_channel: Arc<StdMutex<Option<Arc<dyn DataChannel>>>> = Arc::new(StdMutex::new(None));
    let sequence = Arc::new(AtomicU64::new(1));

    let (outbox, outbox_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let ready = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(drain_outbox(outbox_rx, channels.clone(), ready.clone()));

    // 终端输出的是裸 TERM 帧，这里补上通道名并入同一个出口。
    let (binary_tx, mut binary_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let outbox = outbox.clone();
        tokio::spawn(async move {
            while let Some(frame) = binary_rx.recv().await {
                if outbox.send((BINARY_DATA_CHANNEL.to_owned(), frame)).is_err() {
                    return;
                }
            }
        });
    }
    let terminal = Arc::new(TerminalConn::new(binary_tx));
    // 端口映射的帧固定走 FILE_DATA_CHANNEL，Session 自己持有那个槽位。
    let mapping = portmap::Session::new(file_channel.clone(), sequence.clone());
    // 文件传输与端口映射共用 FILE_DATA_CHANNEL，靠消息字段号区分。
    let files = file_transfer::Session::new(outbox.clone(), sequence.clone());

    let events = Arc::new(Events {
        signal: signaling.clone(),
        client: client_id.clone(),
        ice: ice_id.clone(),
        control: app_control_id.clone(),
        bundle: bundle.clone(),
        channels: channels.clone(),
        file_channel: file_channel.clone(),
        mapping: mapping.clone(),
        files: files.clone(),
        outbox: outbox.clone(),
        terminal: terminal.clone(),
        sequence: sequence.clone(),
        ready,
        peers,
    });

    let pc: Arc<dyn PeerConnection> = Arc::new(
        PeerConnectionBuilder::<std::net::SocketAddr>::new()
            .with_configuration(ice.configuration()?)
            .with_media_engine(media)
            .with_setting_engine(settings)
            .with_udp_addrs(crate::net::ice::udp_bind_addrs())
            .with_handler(events)
            .build()
            .await
            .map_err(|e| format!("创建 PeerConnection 失败: {e}"))?,
    );

    log::debug!("offer SDP:\n{offer_sdp}");
    pc.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_owned()).map_err(|e| format!("offer 无效: {e}"))?)
        .await
        .map_err(|e| format!("设置远端 SDP 失败: {e}"))?;

    let answer = pc.create_answer(None).await.map_err(|e| format!("生成 answer 失败: {e}"))?;
    log::debug!("answer SDP:\n{}", answer.sdp);
    // 一眼看出哪一段被拒（m=audio 0 会让官方客户端直接放弃连接）。
    for line in answer.sdp.lines().filter(|line| {
        line.starts_with("m=") || line.starts_with("a=mid:") || line.starts_with("a=send") || line.starts_with("a=recv") || line.starts_with("a=inactive")
    }) {
        log::info!("answer 媒体段: {line}");
    }
    let media_section = negotiated_bundle_media(&answer.sdp).ok_or("answer 里没有可用的 BUNDLE 段")?;
    *bundle.lock().await = Some(media_section);
    pc.set_local_description(answer.clone())
        .await
        .map_err(|e| format!("设置本地 SDP 失败: {e}"))?;

    signaling
        .emit_soac(&Soac {
            kind: "answer".into(),
            sdp: Some(with_max_message_size(&answer.sdp)),
            ice_id: Some(Value::String(ice_id)),
            // 空 client_id 不能发出去：云端按它路由，空串会让对端收不到。
            client_id: (!client_id.is_empty()).then_some(client_id),
            app_control_id,
            ..Default::default()
        })
        .await?;

    Ok(pc)
}

/// 注入对端候选。`candidate` 既可能是字符串，也可能是 {candidate, sdpMid, sdpMLineIndex}。
pub async fn add_candidate(pc: &Arc<dyn PeerConnection>, soac: &Soac) -> Result<(), String> {
    let Some(value) = &soac.candidate else { return Ok(()) };
    let (candidate, mid, mline) = if let Some(text) = value.as_str() {
        (text.to_owned(), soac.sdp_mid.clone(), soac.sdp_mline_index)
    } else {
        (
            value.get("candidate").and_then(Value::as_str).unwrap_or_default().to_owned(),
            value
                .get("sdpMid")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| soac.sdp_mid.clone()),
            value
                .get("sdpMLineIndex")
                .and_then(Value::as_u64)
                .map(|i| i as i32)
                .or(soac.sdp_mline_index),
        )
    };
    if candidate.is_empty() {
        return Ok(());
    }
    pc.add_ice_candidate(RTCIceCandidateInit {
        candidate,
        sdp_mid: mid.or_else(|| Some("0".into())),
        sdp_mline_index: Some(mline.unwrap_or(0).max(0) as u16),
        ..Default::default()
    })
    .await
    .map_err(|e| format!("添加远端候选失败: {e}"))
}

pub(crate) fn with_max_message_size(sdp: &str) -> String {
    if sdp.contains("a=max-message-size:") {
        return sdp.to_owned();
    }
    let eol = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(sdp.len() + 32);
    for line in sdp.split_inclusive('\n') {
        out.push_str(line);
        if line.trim_end().starts_with("a=sctp-port:") {
            out.push_str(&format!("a=max-message-size:{MAX_MESSAGE_SIZE}{eol}"));
        }
    }
    out
}

/// 一个 peer 的所有出向报文：按通道名找到 data channel 再发。
/// 通道可能还没 Open（viewer 先发请求后开通道的时序），短暂等待而不丢。
async fn drain_outbox(
    mut rx: mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    channels: Arc<StdMutex<HashMap<String, Arc<dyn DataChannel>>>>,
    ready: Arc<tokio::sync::Notify>,
) {
    // 通道一旦发送失败就是关了（SCTP 流不会再回来）。记住它只为两条：
    // 不再逐帧打日志（断线期间终端每秒都在输出，会把日志刷满），以及不必白跑 send。
    let mut broken: HashSet<String> = HashSet::new();
    while let Some((label, message)) = rx.recv().await {
        if broken.contains(&label) {
            continue;
        }
        let mut target = channels.lock().unwrap().get(&label).cloned();
        if target.is_none() {
            // Register before the second check so a channel that opens between
            // the check and the wait cannot be missed.
            let notified = ready.notified();
            tokio::pin!(notified);
            target = channels.lock().unwrap().get(&label).cloned();
            if target.is_none() {
                let _ = tokio::time::timeout(Duration::from_secs(5), &mut notified).await;
                target = channels.lock().unwrap().get(&label).cloned();
            }
        }
        let Some(channel) = target else {
            log::warn!("输出被丢弃：{label} 未打开");
            continue;
        };
        if let Err(e) = channel.send(bytes::BytesMut::from(&message[..])).await {
            log::warn!("{label} 发送失败，该通道后续消息丢弃: {e}");
            broken.insert(label);
        }
    }
}

/// 只打印字段号 / 类型 / 长度（小 varint 顺带打数值），不打印载荷内容。
/// 用来对照官方客户端在 CONTROL 等通道上发的未知消息。
fn describe_fields(fields: &[proto::Field], depth: usize, out: &mut String) {
    for field in fields {
        if !out.is_empty() {
            out.push(' ');
        }
        match &field.value {
            WireValue::Varint(value) => out.push_str(&format!("{}:varint={value}", field.number)),
            WireValue::Fixed32(_) => out.push_str(&format!("{}:fixed32", field.number)),
            WireValue::Fixed64(_) => out.push_str(&format!("{}:fixed64", field.number)),
            WireValue::Bytes(bytes) => {
                out.push_str(&format!("{}:bytes[{}]", field.number, bytes.len()));
                if depth > 0 && !bytes.is_empty() && bytes.len() <= 512 {
                    if let Ok(inner) = proto::read_fields(bytes) {
                        if !inner.is_empty() {
                            out.push('{');
                            describe_fields(&inner, depth - 1, out);
                            out.push('}');
                        }
                    }
                }
            }
        }
    }
}

/// 一条入向报文的去向：终端帧/终端 RPC → 终端；Message 27 → 端口映射。
async fn dispatch(
    label: &str,
    data: Vec<u8>,
    outbox: &mpsc::UnboundedSender<(String, Vec<u8>)>,
    terminal: &TerminalConn,
    mapping: &Arc<portmap::Session>,
    files: &Arc<file_transfer::Session>,
    sequence: &AtomicU64,
) {
    // 快通道是自定义二进制包（无 protobuf 信封），交给 FEC 层排序后写目标。
    if label == FAST_DATA_CHANNEL {
        mapping.feed_fast(&data).await;
        return;
    }
    // 终端是裸 "TERM" 帧，不是 protobuf。
    if label == BINARY_DATA_CHANNEL && terminal::is_frame(&data) {
        terminal.handle(&data);
        return;
    }
    let Ok(fields) = proto::read_fields(&data) else { return };
    // 文件传输（Message 21 字段 8 / Message 22 字段 4）自己认领，认不出就往下走。
    if files.handle(&fields).await {
        return;
    }
    // 终端 RPC（28 check_env / 29 rename_session）：Message 21 请求 → Message 22 应答。
    let response = fields
        .iter()
        .find_map(|f| match (f.number, &f.value) {
            (21, WireValue::Bytes(request)) => Some(*request),
            _ => None,
        })
        .and_then(|request| proto::read_fields(request).ok())
        .and_then(|request| terminal::rpc_response(&request));
    if let Some(body) = response {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let message = proto::envelope(sequence.fetch_add(1, Ordering::Relaxed), timestamp, 22, &body);
        let _ = outbox.send((label.to_owned(), message));
        return;
    }
    // 不认识的 RPC 也要回一条只带 header 的 RpcResponse：客户端按 header 里的请求号配对，
    // 不回的话客户端会一直等（文件列表之类的请求就卡住）。
    if let Some(request) = fields.iter().find_map(|field| match (field.number, &field.value) {
        (21, WireValue::Bytes(request)) => Some(*request),
        _ => None,
    }) {
        if let Ok(inner) = proto::read_fields(request) {
            if let Some(header) = inner.iter().find(|field| field.number == 1).and_then(|field| field.blob()) {
                let methods: Vec<u32> = inner.iter().map(|field| field.number).collect();
                log::info!("未知 RPC（fields={methods:?}）回空 RpcResponse");
                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let message =
                    proto::envelope(sequence.fetch_add(1, Ordering::Relaxed), timestamp, 22, &rpc_header_only(header));
                let _ = outbox.send((label.to_owned(), message));
            }
        }
    }
    // 端口映射：Message 27，只接受 FILE_DATA_CHANNEL（Session 自己拒绝其他通道）。
    if !mapping.handle(&fields, label).await {
        // 官方客户端在桌面 / 文件模式下还会发别的东西（握手、心跳、文件列表…）。
        // 只记结构和长度，不碰载荷内容，方便对照协议补实现。
        let mut detail = String::new();
        describe_fields(&fields, 2, &mut detail);
        log::debug!("未处理的消息: channel={label} fields={detail}");
    }
}

/// RpcResponse 的 body 只带 header（字段 1）：客户端靠它把应答对上请求。
fn rpc_header_only(header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + 3);
    out.push(0x0a); // 字段 1，wire type 2
    let mut len = header.len() as u64;
    while len >= 0x80 {
        out.push((len as u8) | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(header);
    out
}

/// BUNDLE 组里第一个还在用的段的 (mid, mLineIndex)。
fn negotiated_bundle_media(sdp: &str) -> Option<(String, u16)> {
    let preferred: Vec<&str> = sdp
        .lines()
        .find_map(|l| l.strip_prefix("a=group:BUNDLE "))?
        .split_whitespace()
        .collect();
    let mut sections: Vec<(bool, Option<String>)> = Vec::new();
    for line in sdp.lines() {
        if let Some(media) = line.strip_prefix("m=") {
            let port = media.split_whitespace().nth(1)?;
            sections.push((port != "0", None));
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            if let Some(section) = sections.last_mut() {
                section.1 = Some(mid.to_owned());
            }
        }
    }
    for mid in preferred {
        for (index, (active, section_mid)) in sections.iter().enumerate() {
            if *active && section_mid.as_deref() == Some(mid) {
                return Some((mid.to_owned(), index.try_into().ok()?));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{negotiated_bundle_media, with_max_message_size};

    #[test]
    fn advertises_max_message_size_once() {
        let sdp = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=sctp-port:5000\r\n";
        let out = with_max_message_size(sdp);
        assert!(out.contains("a=sctp-port:5000\r\na=max-message-size:262144\r\n"));
        assert_eq!(with_max_message_size(&out), out);
    }

    #[test]
    fn picks_first_active_bundle_section() {        let sdp = "a=group:BUNDLE 0 1\r\nm=audio 0 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:1\r\n";
        assert_eq!(negotiated_bundle_media(sdp), Some(("1".to_owned(), 1)));
        assert_eq!(negotiated_bundle_media("v=0\r\n"), None);
    }
}
