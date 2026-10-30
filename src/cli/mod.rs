//! 命令行：用法文本、日志默认值、子命令分发。

pub mod access;
pub mod args;
pub mod devices;
pub mod ui;

use crate::cloud::login;
use crate::host;

const USAGE: &str = "\
uu-minimal — UU 远程的最小可用骨架（登录 · 组网 · 终端 · 端口映射）

用法:
  uu-minimal <命令> [选项]

账号:
  login                          扫码登录，凭据写入 config.json（0600）
  auth                           查看本地凭据并校验是否仍有效
  auth --login                   登录失效时重新扫码

设备与工具（控制别人的设备）:
  list [--json]                  列出本机身份与云端设备；--json 打印云端原始返回；
                                 stdin 是终端时直接进操作菜单
  api GET|POST <路径> [json]     调试：打一个签名请求，打印云端原始返回
  ssh    --device <id> [--user 用户] [--port 22] [--key 私钥] [--command 命令] [主机]
                                 内嵌 SSH（russh），不读 ~/.ssh/config；密码交互输入
                                 （--password 仍可用，但会出现在进程列表里）
                                 主机/端口缺省 127.0.0.1:22，可用 config.json 的
                                 ssh_host / ssh_port 或 UU_SSH_HOST / UU_SSH_PORT 改
  sftp   --device <id> [用户@]<主机> [路径]
                                 系统 sftp，ProxyCommand 指回本程序
  tunnel --device <id> <主机> <端口>
                                 stdio 桥，给系统 ssh 的 ProxyCommand 用
  portmap --device <id> <本地端口> <目标主机> <目标端口>
                                 本地端口 → 目标设备可达的地址

本机被控（仅桌面 Linux）:
  run                            host 端：建房、回 answer、服务终端与端口映射

全局:
  help, -h, --help               显示本帮助
  version, -V, --version         显示版本
";

const DEFAULT_FILTER: &str = "uu_minimal=info,webrtc=warn,webrtc_ice=warn,webrtc_mdns=warn,\
webrtc_dtls=warn,webrtc_srtp=warn,webrtc_media=warn,webrtc_sctp=warn,russh=warn";

/// 独占终端的命令（交互 SSH、系统 sftp、stdio 桥）默认完全静音：
/// 日志会和远端画面 / ProxyCommand 的 stderr 混在一起。`RUST_LOG` 仍然优先。
pub fn log_filter(command: &str) -> &'static str {
    match command {
        "ssh" | "sftp" | "tunnel" => "off",
        _ => DEFAULT_FILTER,
    }
}

pub fn init_logger(default_filter: &'static str) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter)).init();
}

pub async fn dispatch(command: &str, rest: &[String]) -> Result<(), String> {
    match command {
        "run" => host::run().await,
        "login" => login::run().await,
        "auth" => devices::auth_command(rest).await,
        "list" => devices::list_command(rest).await,
        "api" => devices::api_command(rest).await,
        "portmap" => access::portmap_command(rest).await,
        "tunnel" => access::tunnel_command(rest).await,
        "ssh" => access::ssh_command(rest).await,
        "sftp" => access::sftp_command(rest).await,
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            Ok(())
        }
        "version" | "-V" | "--version" => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => {
            eprintln!("未识别的命令: {other}\n");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

pub fn current_user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default()
}
