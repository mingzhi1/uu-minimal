//! 网易 NRD REST 客户端：请求签名、建房、设备列表。
//! 凭据来自 [`crate::cloud::creds`]，任何结构体都不实现会打印内容的 Debug。

use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cloud::creds::Credentials;

type HmacSha256 = Hmac<Sha256>;

pub const BASE_URL: &str = "https://api.nrd.nie.163.com";
/// 登录失效（"Token无效或已过期"，HTTP 422）。
pub const TOKEN_INVALID: i64 = 1120;

#[derive(Debug)]
pub enum RoomError {
    LoginExpired,
    Other(String),
}

impl std::fmt::Display for RoomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoomError::LoginExpired => f.write_str("login token invalid or expired"),
            RoomError::Other(e) => f.write_str(e),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct RoomData {
    #[serde(default)]
    pub signaling_server: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub signaling_list: Vec<String>,
}

impl RoomData {
    /// 云端有时只填 `signaling_list`，两者任一可用即可。
    pub fn server(&self) -> &str {
        if !self.signaling_server.is_empty() {
            &self.signaling_server
        } else {
            self.signaling_list.first().map(String::as_str).unwrap_or("")
        }
    }
}

impl std::fmt::Debug for RoomData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoomData { .. }")
    }
}

pub struct Api {
    pub creds: Credentials,
    http: reqwest::Client,
}

impl Api {
    pub fn new(creds: Credentials) -> Self {
        // 默认不走系统代理：本地代理拦截 TLS 会让登录和信令直接失败。
        let mut builder = reqwest::Client::builder();
        if !matches!(std::env::var("UU_USE_PROXY").ok().as_deref(), Some("1" | "true" | "yes" | "on")) {
            builder = builder.no_proxy();
        }
        let http = builder
            .timeout(Duration::from_secs(12))
            .build()
            .expect("HTTP client");
        Self { creds, http }
    }

    /// HMAC-SHA256(method + path + 排序后的 x-param-* + body)
    fn sign_request(&self, method: &str, path: &str, headers: &BTreeMap<String, String>, body: &str) -> String {
        let params = headers
            .iter()
            .filter(|(k, _)| k.starts_with("x-param-") && k.as_str() != "x-param-sign")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("{}{}{}{}", method.to_uppercase(), path, params, body);
        let mut mac = HmacSha256::new_from_slice(self.creds.sign_key.as_bytes()).expect("HMAC key");
        mac.update(string_to_sign.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn build_headers(&self, method: &str, path: &str, body: &str) -> HeaderMap {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_string();
        let mut params = BTreeMap::new();
        // 平台来自配置（默认 mac），官方客户端才会把它当 PC 接受。
        params.insert("x-param-plat".into(), crate::cloud::config::platform().x_param_plat().into());
        params.insert("x-param-vn".into(), "4.42.0.2770".into());
        params.insert("x-param-vc".into(), "2770".into());
        params.insert("x-param-pkgn".into(), "com.netease.gameviewer".into());
        params.insert("x-param-chn".into(), "gwqd".into());
        params.insert("x-param-lang".into(), "zh-CN".into());
        params.insert("x-param-cnt".into(), "CN".into());
        // 登录前这些 id 还不存在：为空就不发、不参与签名。
        for (key, value) in [
            ("x-param-client-id", &self.creds.client_id),
            ("x-param-device-id", &self.creds.device_id),
            ("x-param-system-id", &self.creds.system_id),
            ("x-param-user-id", &self.creds.user_id),
        ] {
            if !value.is_empty() {
                params.insert(key.into(), value.clone());
            }
        }
        params.insert("x-param-ts".into(), ts);

        let sign = self.sign_request(method, path, &params, body);

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", HeaderValue::from_static("application/json"));
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert("User-Agent", HeaderValue::from_static(match crate::cloud::config::platform() {
            crate::cloud::config::Platform::Mac => "UURemote/4.42.0 (Macintosh; Intel Mac OS X 10_15_7)",
            crate::cloud::config::Platform::Windows => "UURemote/4.42.0 (Windows NT 10.0; Win64; x64)",
        }));
        if !self.creds.token.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", self.creds.token)) {
                headers.insert("Authorization", v);
            }
            if let Ok(v) = HeaderValue::from_str(&format!(
                "nrd_access_token={}; nrd_csrf_access_token={}",
                self.creds.token, self.creds.csrf
            )) {
                headers.insert("Cookie", v);
            }
            if let Ok(v) = HeaderValue::from_str(&self.creds.csrf) {
                headers.insert("X-CSRF-TOKEN", v);
            }
        }
        for (k, v) in params {
            if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&v)) {
                headers.insert(name, value);
            }
        }
        headers.insert("X-Param-SIGN", HeaderValue::from_str(&sign).expect("sign header"));
        headers
    }

    /// 签名 POST。`body = None` 表示空 body（官方部分接口如此，签名也按空串算）。
    pub async fn post_with_timeout(&self, path: &str, body: Option<&Value>, timeout: Duration) -> Result<(u16, Value), String> {
        let body_str = body.map(serde_json::to_string).transpose().map_err(|e| e.to_string())?.unwrap_or_default();
        let resp = self
            .http
            .post(format!("{BASE_URL}{path}"))
            .timeout(timeout)
            .headers(self.build_headers("POST", path, &body_str))
            .body(body_str)
            .send()
            .await
            .map_err(|_| format!("HTTP post {path} 失败（细节省略）"))?;
        let status = resp.status().as_u16();
        let value = resp.json().await.unwrap_or(Value::Null);
        Ok((status, value))
    }

    pub async fn post(&self, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        self.post_with_timeout(path, body, Duration::from_secs(12)).await
    }

    /// 签名 GET（无 body）。
    pub async fn get(&self, path: &str) -> Result<(u16, Value), String> {
        let resp = self
            .http
            .get(format!("{BASE_URL}{path}"))
            .headers(self.build_headers("GET", path, ""))
            .send()
            .await
            .map_err(|_| format!("HTTP get {path} 失败（细节省略）"))?;
        let status = resp.status().as_u16();
        let value = resp.json().await.unwrap_or(Value::Null);
        Ok((status, value))
    }

    /// GET /api/v1/device/list → data {current_device, my_binded_devices[], others_shared_devices[]}
    pub async fn devices(&self) -> Result<Value, String> {
        let (status, body) = self.get("/api/v1/device/list").await?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        if code == TOKEN_INVALID {
            return Err("登录已失效，执行 `uu-minimal auth --login` 重新扫码".into());
        }
        if status != 200 || code != 0 {
            return Err(format!("设备列表失败: http {status} code {code}"));
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }

    /// GET /api/v1/device/groups/of/my → data {current_device_id, desktop_devices[], mobile_devices[], tv_devices[]}
    /// 手机/电视只在这里出现，`/device/list` 只有桌面。
    pub async fn device_groups(&self) -> Result<Value, String> {
        let (status, body) = self.get("/api/v1/device/groups/of/my").await?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        if code == TOKEN_INVALID {
            return Err("登录已失效，执行 `uu-minimal auth --login` 重新扫码".into());
        }
        if status != 200 || code != 0 {
            return Err(format!("设备分组失败: http {status} code {code}"));
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }

    /// POST /api/v1/room/join/by_device/{device}：以 viewer 身份加入。
    /// `force_join` 抢占已有会话——CLI 隧道被一条陈旧会话挡住比被踢更糟。
    pub async fn join_room(&self, device: &str) -> Result<RoomData, RoomError> {
        let segment = device_segment(device).map_err(RoomError::Other)?;
        let path = format!("/api/v1/room/join/by_device/{segment}");
        let (status, body) = self
            .post_with_timeout(&path, Some(&serde_json::json!({"force_join": true})), Duration::from_secs(15))
            .await
            .map_err(RoomError::Other)?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        if code == TOKEN_INVALID {
            return Err(RoomError::LoginExpired);
        }
        if status == 200 && code == 0 {
            if let Some(data) = body.get("data") {
                let room: RoomData =
                    serde_json::from_value(data.clone()).map_err(|e| RoomError::Other(format!("房间数据解析失败: {e}")))?;
                if room.server().is_empty() || room.token.is_empty() {
                    return Err(RoomError::Other("房间缺少信令地址或票据".into()));
                }
                return Ok(room);
            }
        }
        Err(RoomError::Other(format!("join http {status} code {code}")))
    }

    /// 建房间：拿到信令服务器地址和房间票据（每次重连都要重新申请）。
    pub async fn create_room(&self) -> Result<RoomData, RoomError> {
        let (status, body) = self
            .post("/api/v1/room/create", Some(&serde_json::json!({})))
            .await
            .map_err(RoomError::Other)?;
        let code = body.get("code").and_then(Value::as_i64).unwrap_or(-1);
        if code == TOKEN_INVALID {
            return Err(RoomError::LoginExpired);
        }
        if status == 200 && code == 0 {
            if let Some(data) = body.get("data") {
                let room: RoomData = serde_json::from_value(data.clone())
                    .map_err(|e| RoomError::Other(format!("room data 解析失败: {e}")))?;
                if room.server().is_empty() || room.token.is_empty() {
                    return Err(RoomError::Other("room data 缺少信令地址或票据".into()));
                }
                return Ok(room);
            }
        }
        Err(RoomError::Other(format!("create_room http {status} code {code}")))
    }
}

/// 设备 id 进 URL 路径：只放行 unreserved 字符，其余百分号编码。
fn device_segment(device: &str) -> Result<String, String> {
    let trimmed = device.trim();
    if trimmed.is_empty() || matches!(trimmed, "." | "..") {
        return Err("设备 id 无效".into());
    }
    let mut out = String::with_capacity(trimmed.len());
    for byte in trimmed.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    Ok(out)
}
