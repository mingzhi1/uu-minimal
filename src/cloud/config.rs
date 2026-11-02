//! 配置读写：`$UU_CONFIG`，否则 `$XDG_CONFIG_HOME/uuremote/config.json`，否则
//! `~/.config/uuremote/config.json`。与主程序共用同一个文件与权限约定（0600）。

use std::path::PathBuf;
use std::sync::OnceLock;

pub fn path() -> PathBuf {
    if let Some(p) = std::env::var_os("UU_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("uuremote/config.json")
}

/// 文件不存在返回 `Ok(None)`；格式错误是错误，不静默忽略。
pub fn read() -> Result<Option<serde_json::Value>, String> {
    let p = path();
    match std::fs::read(&p) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("invalid config {}: {e}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read config {}: {e}", p.display())),
    }
}

/// 0600 + 临时文件 + rename：中途崩溃不会留下半截凭据。
pub fn write(cfg: &serde_json::Value) -> Result<PathBuf, String> {
    use std::io::Write;
    let path = path();
    let dir = path.parent().ok_or("config path has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = open_private(&tmp).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    f.write_all(serde_json::to_string_pretty(cfg).unwrap_or_default().as_bytes())
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| format!("replace {}: {e}", path.display()))?;
    Ok(path)
}

/// Unix 上以 0600 建文件；Windows 没有等价位，交给目录 ACL（用户配置目录默认就是私有的）。
#[cfg(unix)]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)
}

/// 冒充的平台：决定设备注册路径、`x-param-plat` 与 ConnectOptions 的 platform 字段。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Platform {
    /// 伪装成 Mac 客户端，也是默认值。
    #[default]
    Mac,
    /// 伪装成 Windows 客户端。
    Windows,
}

impl Platform {
    /// 配置里接受的写法，大小写不敏感。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "mac" | "macos" | "osx" | "darwin" => Some(Self::Mac),
            "windows" | "win" | "win32" => Some(Self::Windows),
            _ => None,
        }
    }

    /// `POST /api/v1/device/{slug}/init` 的路径段。云端只有 `macos`，`mac` 会 404。
    pub fn slug(self) -> &'static str {
        match self {
            Self::Mac => "macos",
            Self::Windows => "windows",
        }
    }

    /// 请求头 `x-param-plat`：官方 Windows 客户端为 1，Mac 客户端按 2 发（未逐项验证）。
    pub fn x_param_plat(self) -> &'static str {
        match self {
            Self::Mac => "2",
            Self::Windows => "1",
        }
    }

    /// ConnectOptions 字段 8 的取值（3 = Windows，4 = macOS）。
    pub fn connect_id(self) -> u64 {
        match self {
            Self::Mac => 4,
            Self::Windows => 3,
        }
    }
}

/// SSH 的缺省目标：`UU_SSH_HOST` / `UU_SSH_PORT` → `config.json` 的 `ssh_host` / `ssh_port`
/// → `127.0.0.1:22`。命令行给了位置主机或 `--port` 时以命令行为准。
pub fn ssh_target() -> (String, u16) {
    let env = |key: &str| std::env::var(key).ok().filter(|value| !value.trim().is_empty());
    let file = read().ok().flatten();
    let field = |key: &str| file.as_ref().and_then(|cfg| cfg.get(key));
    let host = env("UU_SSH_HOST")
        .or_else(|| field("ssh_host").and_then(|v| v.as_str()).map(str::to_owned))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_owned());
    let port = env("UU_SSH_PORT")
        .and_then(|value| value.parse::<u16>().ok())
        .or_else(|| field("ssh_port").and_then(|v| v.as_u64()).and_then(|port| u16::try_from(port).ok()))
        .unwrap_or(22);
    (host, port)
}

/// 平台来源：`UU_PLATFORM` 环境变量 → `config.json` 的 `platform` → 默认 `mac`。
/// 进程内只读一次（登录后设备身份已固定，中途改配置不会重新注册）。
pub fn platform() -> Platform {
    static CACHE: OnceLock<Platform> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let from_file = || {
            read()
                .ok()
                .flatten()
                .and_then(|cfg| cfg.get("platform").and_then(|v| v.as_str()).map(str::to_owned))
        };
        let raw = std::env::var("UU_PLATFORM")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(from_file);
        match raw.as_deref().and_then(Platform::parse) {
            Some(platform) => platform,
            None => {
                if let Some(raw) = &raw {
                    log::warn!("platform={raw:?} 无法识别，回退 {}", Platform::default().slug());
                }
                Platform::default()
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::Platform;

    #[test]
    fn platform_names_accept_common_spellings() {
        for raw in ["mac", "Mac", "macOS", "darwin", " osx "] {
            assert_eq!(Platform::parse(raw), Some(Platform::Mac), "{raw}");
        }
        for raw in ["windows", "WIN", "win32"] {
            assert_eq!(Platform::parse(raw), Some(Platform::Windows), "{raw}");
        }
        assert_eq!(Platform::parse("linux"), None);
        assert_eq!(Platform::parse(""), None);
    }

    #[test]
    fn mac_is_the_default_and_drives_every_platform_field() {
        assert_eq!(Platform::default(), Platform::Mac);
        assert_eq!(Platform::Mac.slug(), "macos");
        assert_eq!(Platform::Mac.x_param_plat(), "2");
        assert_eq!(Platform::Mac.connect_id(), 4);
        assert_eq!(Platform::Windows.slug(), "windows");
        assert_eq!(Platform::Windows.x_param_plat(), "1");
        assert_eq!(Platform::Windows.connect_id(), 3);
    }
}
