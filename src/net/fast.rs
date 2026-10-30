//! 快通道：无序 SCTP 上的块级 FEC + NACK 重传（KCP 思路的最小实现）。
//!
//! 背景：`FILE_DATA_CHANNEL` 是有序可靠通道，丢一个 SCTP 包会阻塞其后所有消息，
//! 应用层补发的冗余包也排在空洞后面，所以 FEC 在有序通道上无效。
//! 这里另开一条 `FAST_DATA_CHANNEL`（`ordered: false` + `max_retransmits: 1`），
//! 无序投递让冗余包立刻可用，丢包不用等 SCTP 的 RTO；可靠性由本模块的 NACK 重传兜底。
//!
//! 包格式（小端，16 字节头）：
//! ```text
//! 0      kind     0=data 1=parity 2=nack
//! 1      count    parity 覆盖的帧数；其他为 0
//! 2      flags    仅 data 有意义：bit0 = FIN（空载荷 + FIN = 流结束）
//! 3      reserved
//! 4..8   stream   流号（端口映射里等于 rule_id）
//! 8..12  seq      data 的序号；nack 的起始序号
//! 12..16 range    parity 组起始序号；nack 的结束序号
//! 16..   payload  data 的裸字节；parity 为 [u16 len; count] 后接异或后的字节
//! ```

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use webrtc::data_channel::DataChannel;

/// 一帧的载荷上限，和 `FILE_DATA_CHANNEL` 的读块大小保持一致。
pub const MAX_PAYLOAD: usize = 16 * 1024;
/// 每多少帧出一个校验帧。8 帧 1 冗余 = 12.5% 额外带宽，能救块内单丢包。
pub const BLOCK: usize = 8;
const HEADER: usize = 16;
/// 每个流保留多少帧用于 NACK 重传。
const HISTORY: usize = 128;
/// 缺口持续这么久才发 NACK，给 FEC 留出恢复时间。
pub const NACK_AFTER: Duration = Duration::from_millis(60);

const DATA: u8 = 0;
const PARITY: u8 = 1;
const NACK: u8 = 2;
const FIN_FLAG: u8 = 0x01;

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn get_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

pub fn data_packet(stream: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
    data_packet_with(stream, seq, payload, false)
}

fn data_packet_with(stream: u32, seq: u32, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.push(DATA);
    out.push(0);
    out.push(if fin { FIN_FLAG } else { 0 });
    out.push(0);
    put_u32(&mut out, stream);
    put_u32(&mut out, seq);
    put_u32(&mut out, 0);
    out.extend_from_slice(payload);
    out
}

fn parity_packet(stream: u32, start: u32, lens: &[u16], xor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + lens.len() * 2 + xor.len());
    out.push(PARITY);
    out.push(lens.len() as u8);
    out.push(0);
    out.push(0);
    put_u32(&mut out, stream);
    put_u32(&mut out, start);
    put_u32(&mut out, start.wrapping_add(lens.len() as u32));
    for len in lens {
        out.extend_from_slice(&len.to_le_bytes());
    }
    out.extend_from_slice(xor);
    out
}

fn nack_packet(stream: u32, from: u32, to: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    out.push(NACK);
    out.push(0);
    out.push(0);
    out.push(0);
    put_u32(&mut out, stream);
    put_u32(&mut out, from);
    put_u32(&mut out, to);
    out
}

/// 解析后的包。`lens` 在块级校验帧上只有一份，直接拷出来（每 8 帧才一次）。
pub enum Packet<'a> {
    Data { stream: u32, seq: u32, fin: bool, payload: &'a [u8] },
    Parity { stream: u32, start: u32, lens: Vec<u16>, xor: &'a [u8] },
    Nack { stream: u32, from: u32, to: u32 },
}

impl Packet<'_> {
    pub fn stream(&self) -> u32 {
        match self {
            Self::Data { stream, .. } | Self::Parity { stream, .. } | Self::Nack { stream, .. } => *stream,
        }
    }
}

pub fn parse(buf: &[u8]) -> Option<Packet<'_>> {
    if buf.len() < HEADER {
        return None;
    }
    let kind = buf[0];
    let count = buf[1];
    let stream = get_u32(buf, 4);
    let seq = get_u32(buf, 8);
    let range = get_u32(buf, 12);
    match kind {
        DATA => Some(Packet::Data { stream, seq, fin: buf[2] & FIN_FLAG != 0, payload: &buf[HEADER..] }),
        PARITY => {
            let count = usize::from(count);
            if count == 0 || count > BLOCK {
                return None;
            }
            let lens_len = count * 2;
            if buf.len() < HEADER + lens_len {
                return None;
            }
            let lens = buf[HEADER..HEADER + lens_len]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<u16>>();
            Some(Packet::Parity { stream, start: seq, lens, xor: &buf[HEADER + lens_len..] })
        }
        NACK => Some(Packet::Nack { stream, from: seq, to: range }),
        _ => None,
    }
}

/// 发送侧：编号、保留重传窗口、凑够 `BLOCK` 帧就异或出一个校验帧。
#[derive(Default)]
pub struct Sender {
    next: HashMap<u32, u32>,
    history: HashMap<u32, VecDeque<(u32, Vec<u8>)>>,
    block: HashMap<u32, Vec<(u32, Vec<u8>)>>,
}

impl Sender {
    /// 把一段字节编号并发包；返回需要按顺序发出去的报文（数据帧 + 可能的校验帧）。
    pub fn push(&mut self, stream: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Vec::new();
        }
        let seq = *self.next.entry(stream).or_insert(0);
        self.next.insert(stream, seq.wrapping_add(1));

        let mut out = vec![data_packet(stream, seq, payload)];

        let history = self.history.entry(stream).or_default();
        history.push_back((seq, payload.to_vec()));
        while history.len() > HISTORY {
            history.pop_front();
        }

        let block = self.block.entry(stream).or_default();
        block.push((seq, payload.to_vec()));
        if block.len() == BLOCK {
            let start = block[0].0;
            let lens: Vec<u16> = block.iter().map(|(_, data)| data.len() as u16).collect();
            let widest = block.iter().map(|(_, data)| data.len()).max().unwrap_or(0);
            let mut xor = vec![0u8; widest];
            for (_, data) in block.iter() {
                for (index, byte) in data.iter().enumerate() {
                    xor[index] ^= byte;
                }
            }
            out.push(parity_packet(stream, start, &lens, &xor));
            block.clear();
        }
        out
    }

    /// 流结束：占用一个新序号发空载荷 FIN 帧。
    /// 不进 FEC 块（FIN 丢了还有 FILE 通道的 FIN 兜底），但要进重传窗口。
    pub fn push_fin(&mut self, stream: u32) -> Vec<Vec<u8>> {
        let seq = *self.next.entry(stream).or_insert(0);
        self.next.insert(stream, seq.wrapping_add(1));
        let history = self.history.entry(stream).or_default();
        history.push_back((seq, Vec::new()));
        while history.len() > HISTORY {
            history.pop_front();
        }
        vec![data_packet_with(stream, seq, &[], true)]
    }

    /// 对端 NACK 之后的重传；超出窗口就放弃（上层 TCP 会自己重试）。
    pub fn retransmit(&self, stream: u32, seq: u32) -> Option<Vec<u8>> {
        self.history
            .get(&stream)?
            .iter()
            .find(|(number, _)| *number == seq)
            .map(|(_, payload)| if payload.is_empty() { data_packet_with(stream, seq, &[], true) } else { data_packet(stream, seq, payload) })
    }
}

/// 接收侧：乱序缓存、按序交付、块内单丢包用校验帧补齐。
///
/// `pending` 的值是 `Option<Vec<u8>>`：`None` 表示 FIN（交付时换成空 Vec 作为 EOF 标记）。
#[derive(Default)]
pub struct Receiver {
    expected: HashMap<u32, u32>,
    pending: HashMap<u32, BTreeMap<u32, Option<Vec<u8>>>>,
    /// 最近收到的帧（含已交付的），校验帧恢复时要拿它们做异或。
    recent: HashMap<u32, BTreeMap<u32, Vec<u8>>>,
    gap_since: HashMap<u32, Instant>,
}

impl Receiver {
    /// 返回按序可交付的载荷；**空 Vec** 表示这条流结束。
    pub fn on_data(&mut self, stream: u32, seq: u32, fin: bool, payload: &[u8]) -> Vec<Vec<u8>> {
        self.insert(stream, seq, if fin { None } else { Some(payload.to_vec()) })
    }

    fn insert(&mut self, stream: u32, seq: u32, item: Option<Vec<u8>>) -> Vec<Vec<u8>> {
        // 发送端每个流的序号都从 0 开始，所以这里不能用“首包序号”当期望值：
        // 无序通道里首包可能是 5，那会把 0..4 全当成过期数据丢掉。
        let expected = *self.expected.entry(stream).or_insert(0);
        if seq < expected {
            return Vec::new(); // 已交付过（多半是重传副本）
        }
        if let Some(payload) = &item {
            self.recent.entry(stream).or_default().insert(seq, payload.clone());
        }
        if seq != expected {
            self.pending.entry(stream).or_default().insert(seq, item);
            self.gap_since.entry(stream).or_insert_with(Instant::now);
            return Vec::new();
        }

        let mut out = Vec::new();
        match item {
            Some(payload) => out.push(payload),
            None => out.push(Vec::new()), // FIN → EOF 标记
        }
        let mut next = expected.wrapping_add(1);
        if let Some(queue) = self.pending.get_mut(&stream) {
            while let Some(item) = queue.remove(&next) {
                match item {
                    Some(payload) => out.push(payload),
                    None => out.push(Vec::new()),
                }
                next = next.wrapping_add(1);
            }
        }
        self.expected.insert(stream, next);
        // recent 只留最近 2 个块的量，长连接下不会无限增长。
        if let Some(recent) = self.recent.get_mut(&stream) {
            while recent.len() > BLOCK * 2 {
                let Some(first) = recent.keys().next().copied() else { break };
                recent.remove(&first);
            }
        }
        if self.pending.get(&stream).map(|queue| queue.is_empty()).unwrap_or(true) {
            self.gap_since.remove(&stream);
        }
        out
    }

    /// 收到校验帧：块内恰好缺一个且其余都在，就把它算出来并交付。
    pub fn on_parity(&mut self, stream: u32, start: u32, lens: &[u16], xor: &[u8]) -> Vec<Vec<u8>> {
        let expected = *self.expected.entry(stream).or_insert(0);
        if start.wrapping_add(lens.len() as u32) <= expected {
            return Vec::new(); // 整块都已经交付
        }
        let missing: Vec<(u32, u16)> = lens
            .iter()
            .enumerate()
            .map(|(index, len)| (start.wrapping_add(index as u32), *len))
            .filter(|(seq, _)| {
                *seq >= expected && !self.recent.get(&stream).map(|recent| recent.contains_key(seq)).unwrap_or(false)
            })
            .collect();
        if missing.len() != 1 {
            return Vec::new(); // 0 个不用管；多个只能等 NACK 重传
        }
        let (seq, len) = missing[0];
        let mut data = xor.to_vec();
        for (index, _) in lens.iter().enumerate() {
            let other = start.wrapping_add(index as u32);
            if other == seq {
                continue;
            }
            let Some(payload) = self.recent.get(&stream).and_then(|recent| recent.get(&other)) else {
                return Vec::new();
            };
            for (at, byte) in payload.iter().enumerate() {
                if at < data.len() {
                    data[at] ^= byte;
                }
            }
        }
        data.truncate(usize::from(len));
        self.insert(stream, seq, Some(data))
    }

    /// 缺口持续超过 `NACK_AFTER` 还没被 FEC 救回来，就请求重传。
    pub fn poll_nack(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let streams: Vec<u32> = self
            .gap_since
            .iter()
            .filter(|(_, since)| now.duration_since(**since) >= NACK_AFTER)
            .map(|(stream, _)| *stream)
            .collect();
        let mut out = Vec::new();
        for stream in streams {
            let expected = self.expected.get(&stream).copied().unwrap_or(0);
            let highest = self
                .pending
                .get(&stream)
                .and_then(|queue| queue.keys().next_back().copied())
                .unwrap_or(expected);
            if highest > expected {
                out.push(nack_packet(stream, expected, highest));
                self.gap_since.insert(stream, now);
            } else {
                self.gap_since.remove(&stream);
            }
        }
        out
    }
}

/// 快通道的收发门面：通道可能还没打开，发送失败时返回 false，调用方回退到 FILE 通道。
pub struct FastLink {
    channel: Mutex<Option<std::sync::Arc<dyn DataChannel>>>,
    sender: Mutex<Sender>,
    receiver: Mutex<Receiver>,
    inbox: UnboundedSender<(u32, Vec<u8>)>,
}

impl FastLink {
    pub fn new(inbox: UnboundedSender<(u32, Vec<u8>)>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            channel: Mutex::new(None),
            sender: Mutex::new(Sender::default()),
            receiver: Mutex::new(Receiver::default()),
            inbox,
        })
    }

    pub fn attach(&self, channel: std::sync::Arc<dyn DataChannel>) {
        *self.channel.lock().unwrap() = Some(channel);
    }

    fn channel(&self) -> Option<std::sync::Arc<dyn DataChannel>> {
        self.channel.lock().unwrap().clone()
    }

    /// 发一段字节；返回 false 表示通道还没开或发送失败，调用方应回退到 FILE 通道。
    pub async fn send(&self, stream: u32, payload: &[u8]) -> bool {
        let Some(channel) = self.channel() else { return false };
        let packets = self.sender.lock().unwrap().push(stream, payload);
        if packets.is_empty() {
            return false;
        }
        for packet in packets {
            if channel.send(bytes::BytesMut::from(&packet[..])).await.is_err() {
                return false;
            }
        }
        true
    }

    /// 结束一条流：走快通道发 FIN（序号有序，接收端等前面数据到齐再交 EOF）。
    pub async fn send_fin(&self, stream: u32) -> bool {
        let Some(channel) = self.channel() else { return false };
        // 先把锁里的结果取出来，MutexGuard 不能跨 await（否则 future 不是 Send）。
        let packets = self.sender.lock().unwrap().push_fin(stream);
        for packet in packets {
            if channel.send(bytes::BytesMut::from(&packet[..])).await.is_err() {
                return false;
            }
        }
        true
    }

    /// 处理一条入向快通道报文：交付已排序的数据，必要时回 NACK / 重传。
    pub async fn feed(&self, data: &[u8]) {
        let Some(packet) = parse(data) else { return };
        let stream = packet.stream();
        let mut replies: Vec<Vec<u8>> = Vec::new();
        let delivered: Vec<Vec<u8>> = {
            let mut receiver = self.receiver.lock().unwrap();
            let out = match packet {
                Packet::Data { stream, seq, fin, payload } => receiver.on_data(stream, seq, fin, payload),
                Packet::Parity { stream, start, lens, xor } => receiver.on_parity(stream, start, &lens, xor),
                Packet::Nack { stream, from, to } => {
                    let sender = self.sender.lock().unwrap();
                    for seq in from..=to {
                        if let Some(packet) = sender.retransmit(stream, seq) {
                            replies.push(packet);
                        }
                    }
                    Vec::new()
                }
            };
            replies.extend(receiver.poll_nack(Instant::now()));
            out
        };
        for payload in delivered {
            let _ = self.inbox.send((stream, payload));
        }
        if let Some(channel) = self.channel() {
            for reply in replies {
                let _ = channel.send(bytes::BytesMut::from(&reply[..])).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_round_trips() {
        let packet = data_packet(7, 42, b"hello");
        match parse(&packet).unwrap() {
            Packet::Data { stream, seq, fin, payload } => {
                assert_eq!((stream, seq, fin, payload), (7, 42, false, &b"hello"[..]));
            }
            _ => panic!("kind mismatch"),
        }
        assert!(parse(&packet[..HEADER - 1]).is_none());
        let mut bad = packet.clone();
        bad[0] = 9;
        assert!(parse(&bad).is_none());
    }

    #[test]
    fn receiver_delivers_in_order_and_drops_duplicates() {
        let mut receiver = Receiver::default();
        assert_eq!(receiver.on_data(1, 0, false, b"a"), vec![b"a".to_vec()]);
        assert!(receiver.on_data(1, 0, false, b"a").is_empty());
        assert!(receiver.on_data(1, 2, false, b"c").is_empty());
        assert_eq!(receiver.on_data(1, 1, false, b"b"), vec![b"b".to_vec(), b"c".to_vec()]);
    }

    #[test]
    fn parity_recovers_a_single_missing_packet() {
        let mut sender = Sender::default();
        let mut packets = Vec::new();
        for index in 0..BLOCK {
            packets.extend(sender.push(3, format!("payload-{index}").as_bytes()));
        }
        assert_eq!(packets.len(), BLOCK + 1, "每块应多出一个校验帧");

        let mut receiver = Receiver::default();
        let mut delivered = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            if index == 4 {
                continue; // 故意丢掉第 4 帧
            }
            match parse(packet).unwrap() {
                Packet::Data { stream, seq, fin, payload } => delivered.extend(receiver.on_data(stream, seq, fin, payload)),
                Packet::Parity { stream, start, lens, xor } => delivered.extend(receiver.on_parity(stream, start, &lens, xor)),
                Packet::Nack { .. } => {}
            }
        }
        assert_eq!(delivered.len(), BLOCK);
        assert_eq!(delivered[4], b"payload-4".to_vec());
    }

    #[test]
    fn nack_fires_only_after_the_gap_persists() {
        let mut receiver = Receiver::default();
        let now = Instant::now();
        assert_eq!(receiver.on_data(1, 0, false, b"a").len(), 1);
        assert!(receiver.on_data(1, 3, false, b"d").is_empty());
        assert!(receiver.poll_nack(now).is_empty(), "缺口刚出现不应立刻 NACK");
        let later = now + NACK_AFTER + Duration::from_millis(1);
        let nacks = receiver.poll_nack(later);
        assert_eq!(nacks.len(), 1);
        match parse(&nacks[0]).unwrap() {
            Packet::Nack { stream, from, to } => assert_eq!((stream, from, to), (1, 1, 3)),
            _ => panic!("kind mismatch"),
        }
    }

    #[test]
    fn eof_waits_for_earlier_data() {
        let mut receiver = Receiver::default();
        // 无序通道里 FIN 可能先到：此时不能立刻交出 EOF，否则会截断还在路上的数据。
        assert!(receiver.on_data(9, 2, true, b"").is_empty());
        assert_eq!(receiver.on_data(9, 0, false, b"a"), vec![b"a".to_vec()]);
        assert_eq!(receiver.on_data(9, 1, false, b"b"), vec![b"b".to_vec(), Vec::new()]);
    }

    #[test]
    fn sender_retransmits_from_history() {
        let mut sender = Sender::default();
        sender.push(1, b"first");
        sender.push(1, b"second");
        let packet = sender.retransmit(1, 0).expect("窗口内应能重传");
        match parse(&packet).unwrap() {
            Packet::Data { seq, payload, .. } => {
                assert_eq!(seq, 0);
                assert_eq!(payload, b"first");
            }
            _ => panic!("kind mismatch"),
        }
        assert!(sender.retransmit(1, 9999).is_none());
    }
}
