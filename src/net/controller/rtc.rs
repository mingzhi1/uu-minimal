//! 控制端 PeerConnection：发 offer、收 answer/candidate、开五条通道，
//! 并在 FILE 通道上跑 `Message 27` 的多路流。

use bytes::BytesMut;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit, RTCDataChannelState};
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfiguration, RTCConfigurationBuilder,
    RTCIceCandidateInit, RTCIceServer, RTCIceTransportPolicy, RTCPeerConnectionIceEvent, RTCPeerConnectionState,
    RTCSessionDescription,
};

use super::signal::Signal;
use crate::proto::{read_fields, Value as WireValue};

pub const CHANNELS: [&str; 6] = [
    "CONTROL_DATA_CHANNEL",
    "TEXT_DATA_CHANNEL",
    "STREAMER_DATA_CHANNEL",
    "FILE_DATA_CHANNEL",
    "BINARY_DATA_CHANNEL",
    "FAST_DATA_CHANNEL",
];
pub const FILE_CHANNEL: usize = 3;
pub const FAST_CHANNEL: usize = 5;
const MESSAGE_FIELD: u32 = 27;
const SYN: u64 = 0;
const FIN: u64 = 1;
const DATA: u64 = 2;
const SYN_ACK: u64 = 3;
const SESSION_ID: u64 = 1;
/// 等 SYN_ACK 的上限。官方 host 建连超时是 10s，但对我们没意义：
/// 控制端本地 listener 已经和内核握完手，等太久只会表现为“连上了但没画面”。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// ack 里的 iceServers / force_relay → RTCConfiguration。
/// 云端没给就用 host 候选，**不自造公共 STUN**。
pub fn configuration(ack: &Value) -> Result<RTCConfiguration, String> {
    let list = ack.get("iceServers").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut servers = Vec::new();
    for server in &list {
        let urls: Vec<String> = match server.get("urls") {
            Some(Value::String(url)) => vec![url.clone()],
            Some(Value::Array(urls)) => urls.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            _ => Vec::new(),
        };
        let urls: Vec<String> = urls
            .into_iter()
            .filter(|url| url.len() <= 2048 && ["stun:", "stuns:", "turn:", "turns:"].iter().any(|p| url.starts_with(p)))
            .collect();
        if urls.is_empty() {
            continue;
        }
        let string = |key: &str| server.get(key).and_then(Value::as_str).unwrap_or_default().to_owned();
        // 0.14 起没有 credential_type：TURN 固定按 long-term credential 处理。
        servers.push(RTCIceServer {
            urls,
            username: string("username"),
            credential: string("credential"),
        });
    }
    let relay = ack.get("force_relay").and_then(Value::as_bool).unwrap_or(false);
    if relay && !servers.iter().any(|s| s.urls.iter().any(|u| u.starts_with("turn:") || u.starts_with("turns:"))) {
        return Err("云端要求 relay-only，但没有 TURN".into());
    }
    Ok(RTCConfigurationBuilder::new()
        .with_ice_servers(servers)
        .with_ice_transport_policy(if relay { RTCIceTransportPolicy::Relay } else { RTCIceTransportPolicy::All })
        .build())
}

struct Flow {
    data: mpsc::Sender<Vec<u8>>,
    ack: Mutex<Option<oneshot::Sender<Result<(), String>>>>,
}

/// 快通道默认关闭：官方 host 不认这条通道，打开只在我们自己的 host 上有意义。
fn fast_enabled() -> bool {
    std::env::var("UU_FAST").map(|value| value == "1").unwrap_or(false)
}

/// 连接级事件（候选、状态、对端建的通道）。0.21 把 `set_*_handler(闭包)` 换成了实现
/// `PeerConnectionEventHandler`，共享状态只能挂在 handler 上，通过 `with_handler` 交进去。
struct Events {
    signal: Arc<Signal>,
    app_id: String,
    ice_id: String,
    remote: String,
    flows: Arc<Mutex<HashMap<(u64, u64), Arc<Flow>>>>,
    /// 连接进 Failed/Disconnected/Closed 时置 true，让 CLI 立刻收工。
    closed: watch::Sender<bool>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Events {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let Ok(mut value) = event.candidate.to_json() else { return };
        log::debug!("本地候选: {}", value.candidate);
        // to_json() 不给 mid：我们的 offer 只有一条 bundled m-line（mid "0"）。
        value.sdp_mid = Some("0".to_owned());
        value.sdp_mline_index = Some(0);
        let payload = json!({"client_id": self.remote, "data": {
            "type": "candidate", "candidate": value, "ice_id": self.ice_id, "app_control_id": self.app_id}});
        if let Err(e) = self.signal.soac(payload).await {
            log::warn!("发送候选失败: {e}");
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        // 排查“通道没打开”时用来区分 ICE/DTLS 没通，还是对端不收这次连接。
        log::info!("连接状态: {state:?}");
        if matches!(
            state,
            RTCPeerConnectionState::Closed | RTCPeerConnectionState::Failed | RTCPeerConnectionState::Disconnected
        ) {
            // 控制端不做 ICE 重启：链路没了就让调用方报错退出，比干等超时好。
            let _ = self.closed.send(true);
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        // 只有对端主动建的通道走这里；我们自建的通道在 new() 里自己挂泵。
        let Ok(label) = channel.label().await else { return };
        if label == CHANNELS[FILE_CHANNEL] {
            let flows = self.flows.clone();
            tokio::spawn(pump_file(channel, flows));
        }
    }
}

pub struct Peer {
    pub pc: Arc<dyn PeerConnection>,
    pub channels: Vec<Arc<dyn DataChannel>>,
    fast: Arc<crate::net::fast::FastLink>,
    app_id: String,
    ice_id: String,
    remote: String,
    answered: AtomicBool,
    early: Mutex<Vec<RTCIceCandidateInit>>,
    flows: Arc<Mutex<HashMap<(u64, u64), Arc<Flow>>>>,
    next_rule: AtomicU64,
}

impl Peer {
    pub async fn new(
        config: RTCConfiguration,
        app_id: String,
        ice_id: String,
        remote: String,
        signal: Arc<Signal>,
        closed: watch::Sender<bool>,
    ) -> Result<Self, String> {
        let flows: Arc<Mutex<HashMap<(u64, u64), Arc<Flow>>>> = Arc::new(Mutex::new(HashMap::new()));

        // 快通道：无序 + 只重传一次。丢包不再阻塞后续消息，配合 `net::fast` 的
        // 块级 FEC 和 NACK，避免有序 SCTP 上“一丢就整条流停住”。
        let (fast_inbox, mut fast_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
        let fast = crate::net::fast::FastLink::new(fast_inbox);
        {
            let flows = flows.clone();
            tokio::spawn(async move {
                while let Some((stream, payload)) = fast_rx.recv().await {
                    let key = (u64::from(stream), 1u64);
                    let flow = flows.lock().unwrap().get(&key).cloned();
                    let Some(flow) = flow else { continue };
                    // 空载荷 = 对端 FIN：丢登记，FlowReader 随通道关闭返回 None。
                    if payload.is_empty() {
                        flows.lock().unwrap().remove(&key);
                        continue;
                    }
                    if flow.data.send(payload).await.is_err() {
                        flows.lock().unwrap().remove(&key);
                    }
                }
            });
        }

        let events = Arc::new(Events {
            signal,
            app_id: app_id.clone(),
            ice_id: ice_id.clone(),
            remote: remote.clone(),
            flows: flows.clone(),
            closed,
        });
        let pc: Arc<dyn PeerConnection> = Arc::new(
            PeerConnectionBuilder::<std::net::SocketAddr>::new()
                .with_configuration(config)
                .with_media_engine(MediaEngine::default())
                .with_udp_addrs(crate::net::ice::udp_bind_addrs())
                .with_handler(events)
                .build()
                .await
                .map_err(|e| format!("创建 PeerConnection 失败: {e}"))?,
        );

        let mut channels: Vec<Arc<dyn DataChannel>> = Vec::with_capacity(CHANNELS.len());
        for (index, label) in CHANNELS.iter().enumerate() {
            // 快通道默认关闭（`UU_FAST=1` 打开）。不开时 host 侧 `FastLink` 永远未就绪，
            // 端口映射自动回退到 FILE 通道，官方 host 的行为不受影响。
            if index == FAST_CHANNEL && !fast_enabled() {
                continue;
            }
            // 0.21 的 `ordered` 是 bool（不再是 Option）。
            let init = if index == FAST_CHANNEL {
                RTCDataChannelInit { ordered: false, max_retransmits: Some(1), ..Default::default() }
            } else {
                RTCDataChannelInit { ordered: true, ..Default::default() }
            };
            let channel = pc.create_data_channel(label, Some(init)).await.map_err(|e| format!("创建 data channel {label} 失败: {e}"))?;
            if index == FAST_CHANNEL {
                fast.attach(channel.clone());
                tokio::spawn(pump_fast(channel.clone(), fast.clone()));
            }
            channels.push(channel);
        }

        {
            // `on_data_channel` 只在远端建通道时触发；自己 create 的通道要自己起事件泵，
            // 否则 FILE 通道上的 Message 27（SYN_ACK/DATA）全部收不到。
            let flows = flows.clone();
            tokio::spawn(pump_file(channels[FILE_CHANNEL].clone(), flows));
        }

        Ok(Self {
            pc,
            channels,
            fast,
            app_id,
            ice_id,
            remote,
            answered: AtomicBool::new(false),
            early: Mutex::new(Vec::new()),
            flows,
            next_rule: AtomicU64::new(1),
        })
    }

    /// offer 必须在 host 处理完 `be-controlled` 之后才发（官方 host 会丢弃未知 ice_id 的 offer）。
    pub async fn offer(&self) -> Result<Value, String> {
        let offer = self.pc.create_offer(None).await.map_err(|e| format!("生成 offer 失败: {e}"))?;
        // 官方 viewer 的 offer 都带 `a=x-uuremote-quic`。实测缺了它官方 host 照样回 answer，
        // 但 data channel 一直不 Open（SYN 收不到 SYN_ACK），所以这行是必须的。
        let sdp = with_quic_flag(&offer.sdp);
        log::debug!("offer SDP:\n{sdp}");
        // 必须先交出原始 SDP 再改字符串：webrtc-rs 不接受被改过的 local description。
        self.pc.set_local_description(offer).await.map_err(|e| format!("设置本地 SDP 失败: {e}"))?;
        Ok(json!({"client_id": self.remote, "data": {
            "type": "offer",
            "sdp": crate::net::peer::with_max_message_size(&sdp),
            "ice_id": self.ice_id,
            "app_control_id": self.app_id,
            "ice_network_type": 3,
        }}))
    }

    pub async fn receive(&self, event: &Value) -> Result<(), String> {
        let body = event.get("data").unwrap_or(event);
        if let Some(ice_id) = body.get("ice_id").and_then(Value::as_str) {
            if ice_id != self.ice_id {
                return Ok(());
            }
        }
        if let Some(app) = body.get("app_control_id").and_then(Value::as_str) {
            if app != self.app_id {
                return Ok(());
            }
        }
        match body.get("type").and_then(Value::as_str) {
            Some("answer") => {
                if self.answered.swap(true, Ordering::AcqRel) {
                    return Ok(());
                }
                let sdp = answer_sdp(body)?;
                log::debug!("answer SDP:\n{sdp}");
                let answer = RTCSessionDescription::answer(sdp).map_err(|e| format!("answer 无效: {e}"))?;
                self.pc.set_remote_description(answer).await.map_err(|e| format!("设置远端 SDP 失败: {e}"))?;
                // 先把队列取空再 await：MutexGuard 跨 await 会让 future 不是 Send。
                let early: Vec<RTCIceCandidateInit> = self.early.lock().unwrap().drain(..).collect();
                for candidate in early {
                    self.pc.add_ice_candidate(candidate).await.map_err(|e| format!("回放候选失败: {e}"))?;
                }
            }
            Some("candidate") => {
                let Some(value) = body.get("candidate") else { return Ok(()) };
                let candidate: RTCIceCandidateInit = if let Some(text) = value.as_str() {
                    RTCIceCandidateInit {
                        candidate: text.to_owned(),
                        sdp_mid: body.get("sdp_mid").and_then(Value::as_str).map(str::to_owned),
                        sdp_mline_index: body.get("sdp_mline_index").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok()),
                        ..Default::default()
                    }
                } else {
                    serde_json::from_value(value.clone()).map_err(|e| format!("候选无效: {e}"))?
                };
                if self.answered.load(Ordering::Acquire) {
                    self.pc.add_ice_candidate(candidate).await.map_err(|e| format!("添加候选失败: {e}"))?;
                } else {
                    let mut early = self.early.lock().unwrap();
                    if early.len() >= 256 {
                        return Err("过早的候选过多".into());
                    }
                    early.push(candidate);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// 各通道当前状态（标签, Connecting/Open/…）。通道打不开时用来区分是对端没开，
    /// 还是只开了其中几条。0.21 起 `ready_state()` 是异步的。
    pub async fn channel_states(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::with_capacity(self.channels.len());
        for (channel, label) in self.channels.iter().zip(CHANNELS.iter()) {
            let state = match channel.ready_state().await {
                Ok(state) => format!("{state:?}"),
                Err(e) => format!("<{e}>"),
            };
            out.push((*label, state));
        }
        out
    }

    pub async fn wait_channel(&self, index: usize, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if matches!(self.channels[index].ready_state().await, Ok(RTCDataChannelState::Open)) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{} 未在 {:?} 内打开（对端可能没接受这次连接）", CHANNELS[index], timeout));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn send_file(&self, message: Vec<u8>) -> Result<(), String> {
        // 0.21 的 `send` 收 `BytesMut`（不再是 `&Bytes`）。
        self.channels[FILE_CHANNEL]
            .send(BytesMut::from(&message[..]))
            .await
            .map_err(|e| format!("FILE 通道发送失败: {e}"))
    }

    /// 打开一条流：SYN → 等 SYN_ACK，之后双向 DATA。
    pub async fn open_flow(self: &Arc<Self>, host: &str, port: u16) -> Result<FlowHandle, String> {
        let rule = self.next_rule.fetch_add(1, Ordering::Relaxed);
        let stream = 1u64;
        let (data, data_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ack, ack_rx) = oneshot::channel();
        let flow = Arc::new(Flow { data, ack: Mutex::new(Some(ack)) });
        self.flows.lock().unwrap().insert((rule, stream), flow);

        let syn = json!({"version": 1, "target_host": host, "target_port": port}).to_string();
        self.send_file(frame(rule, stream, SYN, syn.as_bytes())).await?;

        match tokio::time::timeout(CONNECT_TIMEOUT, ack_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                self.flows.lock().unwrap().remove(&(rule, stream));
                return Err(e);
            }
            _ => {
                self.flows.lock().unwrap().remove(&(rule, stream));
                return Err("等待 SYN_ACK 超时".into());
            }
        }
        Ok(FlowHandle { peer: self.clone(), rule, stream, rx: data_rx })
    }
}

pub struct FlowHandle {
    peer: Arc<Peer>,
    rule: u64,
    stream: u64,
    rx: mpsc::Receiver<Vec<u8>>,
}

/// 读写两半：双向泵可以同时持有。
pub struct FlowWriter {
    peer: Arc<Peer>,
    rule: u64,
    stream: u64,
}

pub struct FlowReader {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl FlowHandle {
    pub fn into_parts(self) -> (FlowWriter, FlowReader) {
        (
            FlowWriter { peer: self.peer, rule: self.rule, stream: self.stream },
            FlowReader { rx: self.rx },
        )
    }
}

impl FlowWriter {
    pub async fn send(&self, data: &[u8]) -> Result<(), String> {
        for chunk in data.chunks(crate::net::fast::MAX_PAYLOAD) {
            // 快通道可用就走无序 + FEC；否则回退到 FILE（官方 host / 未开启 UU_FAST）。
            if self.peer.fast.send(self.rule as u32, chunk).await {
                continue;
            }
            self.peer.send_file(frame(self.rule, self.stream, DATA, chunk)).await?;
        }
        Ok(())
    }

    pub async fn fin(&self) -> Result<(), String> {
        // 走快通道的流，FIN 也要跟着快通道走：否则有序通道上的 FIN 会插到还在途的
        // 无序数据前面，接收端提前关流就把尾部数据丢了。
        if self.peer.fast.send_fin(self.rule as u32).await {
            return Ok(());
        }
        self.peer.send_file(frame(self.rule, self.stream, FIN, &[])).await
    }
}

impl FlowReader {
    /// None = 对端 FIN 或连接断开。
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

/// FILE 通道的事件泵：0.21 没有 `on_message` 回调了，改成一个任务不停 `poll()`。
/// 一条通道只能有一个消费者，所以自建的通道在 `new()` 里起，对端建的在 handler 里起。
async fn pump_file(channel: Arc<dyn DataChannel>, flows: Arc<Mutex<HashMap<(u64, u64), Arc<Flow>>>>) {
    while let Some(event) = channel.poll().await {
        if let DataChannelEvent::OnMessage(message) = event {
            dispatch_flow(&flows, &message.data).await;
        }
    }
}

/// 快通道的事件泵：吃掉无序块，交给 `net::fast` 去重排/校验。
async fn pump_fast(channel: Arc<dyn DataChannel>, fast: Arc<crate::net::fast::FastLink>) {
    while let Some(event) = channel.poll().await {
        if let DataChannelEvent::OnMessage(message) = event {
            fast.feed(&message.data).await;
        }
    }
}

/// 收帧回调。DATA 必须**阻塞发送**：`try_send` 在 256 帧（4 MiB）用满时会静默丢字节，
/// 而这层下面是一条 TCP 字节流，丢一个字节就等于把协议啃出空洞（花屏、握手失败）。
/// 阻塞会把背压交给 SCTP 窗口，代价只是本通道回调变慢。
async fn dispatch_flow(flows: &Arc<Mutex<HashMap<(u64, u64), Arc<Flow>>>>, data: &[u8]) {
    let Ok(fields) = read_fields(data) else { return };
    let Some(WireValue::Bytes(raw)) = fields.iter().find(|f| f.number == MESSAGE_FIELD).map(|f| &f.value) else { return };
    let Ok(frame) = read_fields(raw) else { return };
    let number = |n: u32| frame.iter().find(|f| f.number == n).and_then(|f| match f.value { WireValue::Varint(v) => Some(v), _ => None });
    let (rule, stream) = (number(2).unwrap_or(0), number(3).unwrap_or(0));
    let kind = number(4).unwrap_or(0);
    let payload = frame
        .iter()
        .find(|f| f.number == 5)
        .and_then(|f| match f.value { WireValue::Bytes(b) => Some(b.to_vec()), _ => None })
        .unwrap_or_default();
    let flow = flows.lock().unwrap().get(&(rule, stream)).cloned();
    let Some(flow) = flow else {
        log::warn!("端口映射帧没有对应的流，忽略");
        return;
    };
    match kind {
        DATA => {
            if flow.data.send(payload).await.is_err() {
                // 本地读端已经退出（对端 FIN 或 socket 关闭），把登记一起清掉。
                flows.lock().unwrap().remove(&(rule, stream));
            }
        }
        FIN => {
            flows.lock().unwrap().remove(&(rule, stream));
        }
        SYN_ACK => {
            if let Some(tx) = flow.ack.lock().unwrap().take() {
                let reply = serde_json::from_slice::<Value>(&payload).ok();
                let ok = reply.as_ref().and_then(|v| v.get("ok").and_then(Value::as_bool)).unwrap_or(false);
                // 对端的 error 是 host 侧连不上的原因（refused / timeout），不是凭据。
                let error = reply
                    .as_ref()
                    .and_then(|v| v.get("error").and_then(Value::as_str))
                    .unwrap_or("目标不可达")
                    .to_owned();
                let _ = tx.send(if ok { Ok(()) } else { Err(format!("目标不可达: {error}")) });
            }
        }
        _ => {}
    }
}

fn frame(rule: u64, stream: u64, kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    int(1, SESSION_ID, &mut body);
    int(2, rule, &mut body);
    int(3, stream, &mut body);
    if kind != SYN {
        int(4, kind, &mut body);
    }
    if !payload.is_empty() {
        bytes(5, payload, &mut body);
    }
    crate::proto::envelope(0, 0, MESSAGE_FIELD, &body)
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

/// 在 `a=group:BUNDLE` 之前插入 `a=x-uuremote-quic`（官方 viewer 的 offer 形态）。
fn with_quic_flag(sdp: &str) -> String {
    let eol = if sdp.contains("\r\n") { "\r\n" } else { "\n" };
    let marker = "a=group:BUNDLE";
    if sdp.contains("a=x-uuremote-quic") {
        return sdp.to_owned();
    }
    match sdp.find(marker) {
        Some(at) => {
            let mut out = String::with_capacity(sdp.len() + marker.len());
            out.push_str(&sdp[..at]);
            out.push_str("a=x-uuremote-quic");
            out.push_str(eol);
            out.push_str(&sdp[at..]);
            out
        }
        None => sdp.to_owned(),
    }
}

/// 官方 host 可能回 gzip_sdp（base64 + gzip）。
fn answer_sdp(body: &Value) -> Result<String, String> {
    if let Some(sdp) = body.get("sdp").and_then(Value::as_str) {
        if sdp.len() <= 1024 * 1024 {
            return Ok(sdp.to_owned());
        }
    }
    if let Some(encoded) = body.get("gzip_sdp").and_then(Value::as_str) {
        use base64::Engine;
        use std::io::Read;
        if encoded.len() > 2 * 1024 * 1024 {
            return Err("压缩 answer 过大".into());
        }
        let raw = base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| "压缩 answer 无效")?;
        let mut sdp = String::new();
        flate2::read::GzDecoder::new(raw.as_slice())
            .take(1024 * 1024 + 1)
            .read_to_string(&mut sdp)
            .map_err(|_| "压缩 answer 解压失败")?;
        if sdp.len() <= 1024 * 1024 {
            return Ok(sdp);
        }
    }
    Err("answer 缺少 sdp".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_mapping_frames_round_trip() {
        let message = frame(7, 1, DATA, b"hello");
        let fields = read_fields(&message).unwrap();
        assert!(fields.iter().any(|f| f.number == MESSAGE_FIELD));
        let WireValue::Bytes(body) = fields.iter().find(|f| f.number == MESSAGE_FIELD).unwrap().value else { panic!() };
        let inner = read_fields(body).unwrap();
        let number = |n: u32| inner.iter().find(|f| f.number == n).and_then(|f| match f.value { WireValue::Varint(v) => Some(v), _ => None });
        assert_eq!((number(1), number(2), number(3), number(4)), (Some(1), Some(7), Some(1), Some(DATA)));
    }

    #[test]
    fn quic_flag_goes_before_the_bundle_group_and_is_idempotent() {
        let sdp = "v=0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        let out = with_quic_flag(sdp);
        assert!(out.contains("a=x-uuremote-quic\r\na=group:BUNDLE 0\r\n"));
        // 没有 BUNDLE 段时原样返回，免得插到非法位置。
        assert_eq!(with_quic_flag("v=0\r\n"), "v=0\r\n");
        assert_eq!(with_quic_flag(&out), out);
    }

    #[test]
    fn ice_configuration_rejects_relay_without_turn() {
        assert!(configuration(&json!({"force_relay": true})).is_err());
        let ok = configuration(&json!({"iceServers": [{"urls": "stun:127.0.0.1:3478"}]})).unwrap();
        assert_eq!(ok.ice_servers().len(), 1);
        assert_eq!(configuration(&json!({})).unwrap().ice_servers().len(), 0);
    }
}
