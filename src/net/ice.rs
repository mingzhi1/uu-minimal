//! 每连接的 ICE 配置。STUN/TURN 由云端在 `be-controlled` 头的 `iceServers` 里下发，
//! 代码里不内置任何 UU 中继地址；云端不给时才退回公共 STUN。
//! 故意不实现 Debug：凭据不能进日志。

use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use webrtc::peer_connection::{RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy};

/// 跳过 overlay / 容器网卡：否则同一 LAN 也会选到 ZeroTier 之类的候选（实测 36-81ms）。
pub fn interface_allowed(name: &str) -> bool {
    !["zt", "docker", "br-", "veth", "virbr", "lo"].iter().any(|prefix| name.starts_with(prefix))
}

/// 给 `PeerConnectionBuilder::with_udp_addrs` 用的监听地址。
///
/// 0.21 必须显式指定本地 socket（不给就是 `no udp_sockets or tcp_listeners available`），
/// 而老版本的 `with_interface_filter` 被上游注释掉了，所以「只从允许的网卡收候选」这件事
/// 改在这里做：枚举网卡地址，把 zt / docker / veth 这些跳过。端口 0 = 每个 socket 随机端口。
/// 枚举不到（权限、平台差异）就退回通配地址，宁可多收候选也别连不上。
pub fn udp_bind_addrs() -> Vec<SocketAddr> {
    let wildcard = || vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)];
    let mut addrs = Vec::new();
    // SAFETY: getifaddrs 分配的链表由 freeifaddrs 释放；循环里只读，指针在释放前有效。
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return wildcard();
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            cursor = entry.ifa_next;
            if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
            if !interface_allowed(&name) {
                continue;
            }
            match i32::from((*entry.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        addrs.push(SocketAddr::new(IpAddr::V4(ip), 0));
                    }
                }
                libc::AF_INET6 => {
                    let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                    let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        addrs.push(SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, sin6.sin6_scope_id)));
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(head);
    }
    addrs.sort();
    addrs.dedup();
    if addrs.is_empty() {
        wildcard()
    } else {
        addrs
    }
}

#[derive(Clone, Default)]
pub struct SessionIce {
    servers: Vec<RTCIceServer>,
    relay_only: bool,
}

impl SessionIce {
    /// 从 `be-controlled` 的 header（或 header.data）里取 `iceServers` / `force_relay`。
    pub fn from_header(header: &Value) -> Self {
        let data = header.get("data").unwrap_or(header);
        let field = |name: &str| header.get(name).or_else(|| data.get(name));
        let mut result = Self {
            relay_only: field("force_relay").and_then(Value::as_bool).unwrap_or(false),
            ..Default::default()
        };
        if let Some(servers) = field("iceServers").and_then(Value::as_array) {
            for server in servers.iter().take(16) {
                let urls: Vec<String> = match server.get("urls").or_else(|| server.get("url")) {
                    Some(Value::String(url)) => vec![url.clone()],
                    Some(Value::Array(urls)) => urls.iter().filter_map(Value::as_str).take(16).map(str::to_owned).collect(),
                    _ => Vec::new(),
                }
                .into_iter()
                .filter(|url| url.len() <= 2048 && ["stun:", "stuns:", "turn:", "turns:"].iter().any(|p| url.starts_with(p)))
                .collect();
                if urls.is_empty() {
                    continue;
                }
                let string = |name: &str| server.get(name).and_then(Value::as_str).filter(|s| s.len() <= 4096).unwrap_or("").to_owned();
                // webrtc 0.14 起 `RTCIceServer` 不再带 credential_type：TURN 一律按
                // long-term credential（用户名 + 密码）处理，和云端下发的形态一致。
                result.servers.push(RTCIceServer {
                    urls,
                    username: string("username"),
                    credential: string("credential"),
                });
            }
        }
        result
    }

    pub fn configuration(&self) -> Result<RTCConfiguration, String> {
        let has_turn = self
            .servers
            .iter()
            .any(|s| s.urls.iter().any(|u| u.starts_with("turn:") || u.starts_with("turns:")));
        // 要求中继却没有 TURN 时明确失败，不静默降级成直连。
        if self.relay_only && !has_turn {
            return Err("云端要求 relay-only，但没有可用的 TURN 配置".into());
        }
        let supplied = !self.servers.is_empty();
        let servers = if supplied {
            self.servers.clone()
        } else {
            vec![RTCIceServer {
                urls: vec![
                    "stun:stun.l.google.com:19302".into(),
                    "stun:stun1.l.google.com:19302".into(),
                    "stun:stun.miwifi.com:3478".into(),
                ],
                ..Default::default()
            }]
        };
        log::info!(
            "ICE 配置: cloud_supplied={supplied} server_count={} turn_available={has_turn} relay_only={}",
            servers.len(),
            self.relay_only
        );
        // 0.21 起配置改成 builder（sans-IO 重写后结构体字段不再公开构造）。
        Ok(RTCConfigurationBuilder::new()
            .with_ice_servers(servers)
            .with_ice_transport_policy(if self.relay_only { RTCIceTransportPolicy::Relay } else { RTCIceTransportPolicy::All })
            .build())
    }
}
