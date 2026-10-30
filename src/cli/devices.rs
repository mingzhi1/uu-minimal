//! `auth` 与 `list` 命令：本地凭据、本机身份、自有/共享设备与设备菜单。

use serde_json::Value;

use crate::cli::access::{exec_sftp, exec_ssh, loaded_api, portmap_run};
use crate::cli::args::Args;
use crate::cli::current_user;
use crate::cli::ui;
use crate::cloud::api::Api;
use crate::cloud::config;
use crate::cloud::login;
use crate::cloud::creds::Credentials;

pub async fn auth_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    if args.flag("--login") {
        return login::run().await;
    }
    let file = config::read()?;
    let creds = Credentials::load(file.as_ref())?;
    ui::banner("账号");
    println!("{} {}", ui::pad("platform", 10), config::platform().slug());
    println!("{} {}", ui::pad("user_id", 10), mask(&creds.user_id));
    println!("{} {}", ui::pad("device_id", 10), mask(&creds.device_id));
    println!("{} {}", ui::pad("client_id", 10), mask(&creds.client_id));
    let api = Api::new(creds);
    let data = api.devices().await?;
    let count = |key: &str| data.get(key).and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    ui::section("云端");
    println!(
        "凭据有效 · 自有设备 {} 台 · 共享给你 {} 台",
        count("my_binded_devices"),
        count("others_shared_devices")
    );
    Ok(())
}

#[derive(Clone)]

struct Device {
    id: String,
    name: String,
    shared: bool,
    platform: i64,
    status: String,
    online: Option<bool>,
}

/// 本机在云端的身份：`/api/v1/device/list` 的 `current_device`（名字字段是 `alias`），
/// 不在自有/共享数组里，所以单独列一段。

impl Device {
    /// 菜单里的一行：名字 · id · 平台 · 归属。
    fn menu_label(&self) -> String {
        format!(
            "{}  {}  {}  {}",
            ui::pad(&self.name, 22),
            self.id,
            ui::pad(&platform_label(self.platform), 8),
            if self.shared { "共享" } else { "自有" }
        )
    }

    /// 状态：云端给了 online 就用它，否则退回 status 字段（CONNECTED / DISCONNECTED）。
    fn state_label(&self) -> String {
        state_text(self.online, &self.status)
    }
}

/// 状态的一行文字：`online` 优先，其次 `status`（小写、变暗）。

struct LocalDevice {
    id: String,
    name: String,
    platform: i64,
    status: String,
    controllable: Option<bool>,
}

/// 云端 platform 取值 → 名字（1 = Windows，4 = macOS）；未知值保留原始编号，方便排查。

fn platform_label(platform: i64) -> String {
    match platform {
        1 => "windows".to_owned(),
        2 => "android".to_owned(),
        4 => "macos".to_owned(),
        other => format!("p{other}"),
    }
}

pub async fn list_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let api = loaded_api()?;
    // `/device/groups/of/my` 才带 mobile_devices / tv_devices；`/device/list` 只有桌面。
    // 分组接口失败（老账号/接口变动）再退回设备列表。
    let data = match api.device_groups().await {
        Ok(groups) => groups,
        Err(_) => api.devices().await?,
    };
    // `--json`：原样打印云端 data，用来看清到底返回了哪些分组与字段。
    if args.flag("--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).map_err(|e| format!("序列化失败: {e}"))?
        );
        return Ok(());
    }
    let devices = collect_devices(&data);
    ui::banner("设备");
    print_local(&data);
    print_devices(&devices);
    if devices.is_empty() {
        ui::hint("\n  没有设备：手机需登录同一账号，并在手机 App 里开启被控（允许远程控制）。");
        ui::hint("  用 `uu-minimal list --json` 看云端原始返回。");
    }
    // 非交互（管道/脚本）时只打印，不进菜单。
    if devices.is_empty() || !ui::is_tty() {
        return Ok(());
    }
    let Some(index) = ui::pick("选择设备（回车退出）", &devices, Device::menu_label) else {
        return Ok(());
    };
    menu_device(&devices[index]).await
}

fn state_text(online: Option<bool>, status: &str) -> String {
    match online {
        Some(true) => "online".to_owned(),
        Some(false) => ui::dim("offline"),
        None if status.is_empty() => ui::dim("unknown"),
        None => ui::dim(&status.to_ascii_lowercase()),
    }
}

fn collect_devices(data: &Value) -> Vec<Device> {
    let current = data.get("current_device_id").and_then(Value::as_str).unwrap_or_default().to_owned();
    let mut devices = Vec::new();
    // 分组接口：desktop / mobile / tv；设备列表接口：自有 / 共享。
    for (shared, key) in [
        (false, "desktop_devices"),
        (false, "mobile_devices"),
        (false, "tv_devices"),
        (false, "my_binded_devices"),
        (true, "others_shared_devices"),
    ] {
        for device in data.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
            devices.push(Device {
                id: text_field(device, &["device_id", "id"]),
                name: text_field(device, &["device_name", "name", "alias"]),
                shared,
                platform: device.get("platform").and_then(Value::as_i64).unwrap_or(0),
                status: device.get("status").and_then(Value::as_str).unwrap_or("").to_owned(),
                online: device.get("online").and_then(Value::as_bool),
            });
        }
    }
    // 本机在分组接口里混在 desktop_devices 里，单独一段展示，不进选择列表。
    if !current.is_empty() {
        devices.retain(|device| device.id != current);
    }
    devices
}

/// `current_device` 缺失或没有 device_id 时返回 `None`（此时只列云端设备列表）。

fn local_device(data: &Value) -> Option<LocalDevice> {
    // 分组接口只给 current_device_id，本机详情混在 desktop_devices 里。
    if let Some(current) = data.get("current_device_id").and_then(Value::as_str).filter(|id| !id.is_empty()) {
        let entry = data
            .get("desktop_devices")
            .and_then(Value::as_array)
            .and_then(|list| list.iter().find(|device| device.get("device_id").and_then(Value::as_str) == Some(current)));
        return Some(LocalDevice {
            id: current.to_owned(),
            name: entry.map(|value| text_field(value, &["alias", "device_name", "name"])).unwrap_or_else(|| "-".into()),
            platform: entry.and_then(|value| value.get("platform")).and_then(Value::as_i64).unwrap_or(0),
            status: entry
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            controllable: entry
                .and_then(|value| value.get("controllable"))
                .and_then(Value::as_bool),
        });
    }
    let local = data.get("current_device").filter(|value| value.is_object())?;
    let id = local.get("device_id").and_then(Value::as_str).filter(|id| !id.is_empty())?;
    Some(LocalDevice {
        id: id.to_owned(),
        name: text_field(local, &["alias", "device_name", "name"]),
        platform: local.get("platform").and_then(Value::as_i64).unwrap_or(0),
        status: ["status", "publisher_availability_status"]
            .iter()
            .find_map(|key| local.get(*key).and_then(Value::as_str))
            .unwrap_or("")
            .to_owned(),
        controllable: local.get("controllable").and_then(Value::as_bool),
    })
}

fn print_local(data: &Value) {
    let Some(local) = local_device(data) else { return };
    ui::section("本机");
    let control = match local.controllable {
        Some(true) => "  可被控".to_owned(),
        Some(false) => format!("  {}", ui::dim("不可被控")),
        None => String::new(),
    };
    println!(
        "  {} {}  {}  {}{control}",
        ui::pad(&local.name, 22),
        local.id,
        ui::pad(&platform_label(local.platform), 8),
        state_text(None, &local.status)
    );
}

fn print_devices(devices: &[Device]) {
    for (title, shared) in [("自有设备", false), ("共享设备", true)] {
        ui::section(title);
        let mut any = false;
        for (index, device) in devices.iter().enumerate().filter(|(_, device)| device.shared == shared) {
            println!(
                "  {} {}  {}  {}  {}",
                ui::dim(&format!("{})", index + 1)),
                ui::pad(&device.name, 22),
                device.id,
                ui::pad(&platform_label(device.platform), 8),
                device.state_label()
            );
            any = true;
        }
        if !any {
            ui::hint("  （无）");
        }
    }
}

/// 调试用：直接打一个签名请求，看云端原始返回（排查设备/能力字段时用）。
/// 用法：`uu-minimal api GET /api/v1/device/list`、`uu-minimal api POST /api/v1/xxx '{"a":1}'`
pub async fn api_command(args: &[String]) -> Result<(), String> {
    let args = Args::new(args);
    let positional = args.positionals();
    let method = positional.first().map(|m| m.to_ascii_uppercase()).unwrap_or_default();
    let path = positional.get(1).ok_or("用法: uu-minimal api <GET|POST> <路径> [json]")?;
    let api = loaded_api()?;
    let (status, body) = match method.as_str() {
        "GET" => api.get(path).await?,
        "POST" => {
            let value: Value = match positional.get(2) {
                Some(raw) => serde_json::from_str(raw).map_err(|e| format!("body 不是合法 JSON: {e}"))?,
                None => Value::Null,
            };
            let body = value.is_null().then_some(None).unwrap_or(Some(&value));
            api.post(path, body).await?
        }
        other => return Err(format!("只支持 GET / POST，收到 {other}")),
    };
    println!("http {status}");
    println!(
        "{}",
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())
    );
    Ok(())
}

/// 设备二级菜单：ssh / sftp / portmap。

async fn menu_device(device: &Device) -> Result<(), String> {
    loop {
        ui::section(&format!("设备 · {}", device.name));
        println!(
            "{}  {}  {}",
            device.id,
            ui::pad(&platform_label(device.platform), 8),
            device.state_label()
        );
        let actions = ["ssh", "sftp", "portmap", "返回"];
        let Some(choice) = ui::pick("操作（回车返回）", &actions, |action| (*action).to_string()) else {
            return Ok(());
        };
        let result = match choice {
            0 => {
                let (default_host, default_port) = config::ssh_target();
                let host = ui::prompt("目标主机（设备可达）", &default_host);
                let Ok(port) = ui::port("端口", default_port) else { continue };
                let user = ui::prompt("用户名（留空用当前用户）", &current_user());
                exec_ssh(&device.id, &host, port, &user).await
            }
            1 => {
                let host = ui::prompt("目标主机（设备可达）", "127.0.0.1");
                let user = ui::prompt("用户名（留空用当前用户）", &current_user());
                let path = ui::prompt("远端路径（留空进入家目录）", "");
                exec_sftp(&device.id, &host, &user, &path).await
            }
            2 => {
                let Ok(local) = ui::port("本地端口", 2222) else { continue };
                let host = ui::prompt("目标主机（设备可达）", "127.0.0.1");
                let Ok(port) = ui::port("目标端口", 22) else { continue };
                portmap_run(&device.id, local, &host, port).await
            }
            _ => return Ok(()),
        };
        if let Err(error) = result {
            ui::error(&error);
        }
    }
}

/// 菜单里的 ssh：进程内直接跑 russh，不再起子进程。

fn mask(id: &str) -> String {
    let head: String = id.chars().take(6).collect();
    if id.chars().count() <= 6 {
        "***".into()
    } else {
        format!("{head}…")
    }
}

fn text_field(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .unwrap_or("-")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{local_device, state_text};
    use serde_json::json;

    #[test]
    fn local_device_reads_the_current_device_object() {
        // 线上的 current_device 只有 `alias`，没有 `device_name`。
        let data = json!({
            "current_device": {
                "device_id": "demo1234demo5678", "alias": "example-box", "platform": 4,
                "status": "DISCONNECTED", "controllable": false,
                "publisher_availability_status": "offline"
            },
            "my_binded_devices": []
        });
        let local = local_device(&data).expect("current_device 是对象且有 device_id");
        assert_eq!(local.id, "demo1234demo5678");
        assert_eq!(local.name, "example-box");
        assert_eq!(local.platform, 4);
        assert_eq!(local.status, "DISCONNECTED");
        assert_eq!(local.controllable, Some(false));
    }

    #[test]
    fn local_device_falls_back_and_skips_missing_identity() {
        let data = json!({"current_device": {"device_id": "x", "publisher_availability_status": "offline"}});
        let local = local_device(&data).unwrap();
        assert_eq!(local.status, "offline");
        assert_eq!(local.controllable, None);

        // 没有 current_device / 没有 device_id：不打印本机段，也不影响设备列表。
        assert!(local_device(&json!({"my_binded_devices": []})).is_none());
        assert!(local_device(&json!({"current_device": {"alias": "box"}})).is_none());
    }

    #[test]
    fn state_text_prefers_online_then_status() {
        assert_eq!(state_text(Some(true), "DISCONNECTED"), "online");
        assert!(state_text(Some(false), "CONNECTED").contains("offline"));
        assert!(state_text(None, "CONNECTED").contains("connected"));
        assert!(state_text(None, "").contains("unknown"));
    }
}
