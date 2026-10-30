# uu-minimal — 登录 + 组网最小骨架

独立实现（与主程序同一套协议、行为对齐）、能独立编译运行的三条链路：

1. **登录**：设备注册 → 二维码 → 长轮询 → 换 token（`~/.config/uuremote/config.json`，0600）
2. **组网**：建房 → Socket.IO → `be-controlled` → `soac` offer / answer / 候选
3. **工具**：终端（BINARY 上的 `TERM` 帧）、端口映射（FILE 上的 Message 27）与文件传输（FILE 上的 RPC 21/22 字段 8/4）

不含画面、输入、剪贴板、多显示器、重连退避、协助码和 GTK 窗口。连上后桌面是黑的，**终端、端口映射和文件传输可用**。

同一二进制也可当控制端（`list` / `ssh` / `sftp` / `tunnel` / `portmap`，只走 TCP 和 WebRTC）。手机只能做控制端：被控需要 `openpty`、fork shell 和 `/proc`，iOS 都不允许。Android 可在 Termux 里编；iOS 只能嵌成静态库，菜单用 SwiftUI，`sftp` 换 russh。桌面 Linux 上的 `run` 是部分被控端。

## 构建与运行

```sh
cargo build --release
./target/release/uu-minimal help      # 命令与选项
./target/release/uu-minimal login     # 二维码只打到当前终端
./target/release/uu-minimal run
```

依赖全部来自 crates.io：WebRTC 用上游 `webrtc 0.21.x`（sans-IO 重写后的形态），没有 `[patch.crates-io]`，也不依赖任何本地 `vendor` 目录，拷走整个目录即可独立编译。

日志默认本程序 `info`，`webrtc*` / `russh` 压到 `warn`。`ssh` / `sftp` / `tunnel` 默认静音（独占终端）。`RUST_LOG` 优先，例如 `RUST_LOG=info,webrtc_ice=debug`；`NO_COLOR=1` 关颜色。

凭据与主程序共用。`UU_CONFIG` 指向别处的 `config.json`（相对路径按当前目录解析）：

```sh
UU_CONFIG=./config.json ./target/release/uu-minimal auth
UU_CONFIG=./config.json ./target/release/uu-minimal list
UU_CONFIG=./config.json ./target/release/uu-minimal ssh --device <id> --user me
```

`config.json` 里的 `token` / `csrf` 只在本机使用，不要提交（本目录 `.gitignore` 只忽略 `target/` 和日志）。

| 项 | 说明 |
|---|---|
| `platform` / `UU_PLATFORM` | 默认 `mac`。注册走 `/api/v1/device/{macos\|windows}/init`（云端没有 `mac`，会 404）；`x-param-plat` macos=2 / windows=1；ConnectOptions 的 platform mac=4 / windows=3。已有 `device_id` 不会重注册，换平台先删掉再 `login` |
| `machine_guid`、`host_name` | 以配置为准，`UU_MACHINE_GUID` / `UU_HOST_NAME` 可临时覆盖。缺字段时首次 `login` 用 `/etc/machine-id` 和 hostname 补上并写回 |
| macOS 注册附加项 | `system_version` / `model` / `model_identifier` / `system_name` / `resolution` / `dpi`，且 `memory` 必须是字符串（缺了服务端 422/1001）。默认为 `14.5` / `MacBook Pro` / `MacBookPro18,3` / `macOS` / `1920x1080` / `96`，同名字段可覆盖 |
| `ssh_host` / `ssh_port` | `ssh` 和设备菜单的缺省目标；`UU_SSH_HOST` / `UU_SSH_PORT` 可覆盖，否则 `127.0.0.1:22`。命令行主机或 `--port` 优先 |
| `UU_PORT_MAPPING=0` | 关闭被控端端口映射 |

## 控制别人

```sh
uu-minimal auth                 # 本地凭据 + /api/v1/device/list
uu-minimal auth --login         # 失效则重新扫码
uu-minimal list                 # TTY 进菜单；管道只打印

uu-minimal portmap --device <id> 2222 127.0.0.1 22
ssh -p 2222 me@127.0.0.1

uu-minimal ssh --device <id> --user me
uu-minimal ssh --device <id> --user me --command "uname -a"

# 系统 ssh 的 -L/-R/-D、scp、rsync 才需要 stdio 桥
uu-minimal tunnel --device <id> 127.0.0.1 22
ssh -o ProxyCommand="uu-minimal tunnel --device <id> %h %p" -p 22 me@127.0.0.1

uu-minimal sftp --device <id> me@127.0.0.1   # exec 系统 sftp，ProxyCommand 指回 tunnel
```

内嵌 SSH（russh）不读 `~/.ssh/config`，也不调用系统 ssh。认证顺序：`--password` → `--key` 或 `~/.ssh/id_{ed25519,ecdsa,rsa}` → 终端输入。主机密钥存在 `~/.config/uuremote/known_hosts`（TOFU，`<host>:<port> <sha256>`），指纹变了就拒绝，不碰 `~/.ssh/known_hosts`。

`list` 顶部「本机」来自 `current_device`（名字字段是 `alias`），不在自有/共享列表里，也不进选择菜单；`controllable` 为假表示官方客户端连不进来。菜单项是 ssh、sftp、portmap（占到 Ctrl-C）。ssh / portmap 在本进程 `force_join` 同一设备，**不要同时开两条**（后开的会顶掉先开的）；ssh 退出后菜单会重新 join。

`join` 带 `force_join: true`；`ice_id` 以云端 ack 为准；offer 补 `a=x-uuremote-quic`。`control` 的 `ConnectOptions` 附件必须带 `0x04` 前缀（老版 Engine.IO 分帧），少了这个字节官方 host 解析不出 capture_type，`be-controlled` 不落地，ack 之后收不到任何下行信令。offer 只发一次：官方 host 按 `ice_id` 一个 peer，重发的 offer 会让它重建连接（DTLS 已 Connected 但 data channel 一直不 Open）。官方 host 可能用二进制事件加 gzip_sdp 回 answer。一条 Message 27 流就是一条 TCP。

## 被控与安全

- 终端起 `$SHELL -l`（默认 `/bin/bash`）。会话跨控制端存活，重连最多回放 256 KiB scrollback；`DETACH` 只解绑、不杀进程。
- 端口映射按对端给的 `target_host:target_port` 主动去连（10s 超时），等于把 **host 所在内网** 暴露给对端，只在可信账号下开。
- 文件传输可浏览、上传、下载、改名、新建目录、删除。路径按客户端给的 PC 风格解析（`~` = `$HOME`，盘符映射到 `/`），不做沙箱：对端能读写运行用户能读写的任何位置，只在可信账号下开。日志只记任务号、文件数、字节数与错误码，不记文件名和内容。
- 不监听入向端口，只有一条出向 WSS 加 WebRTC 的 UDP。STUN/TURN 全由云端下发，没有内置中继；云端不给才退回公共 STUN。`force_relay=true` 但没有 TURN 直接报错，不静默降级。候选只留物理网卡（丢掉 `zt*` / `docker` / `br-` / `veth` / `virbr` / `lo`），关闭 mDNS。host 固定 DTLS Server；answer 补 `a=max-message-size:262144`，否则对端按 64 KB 拒绝大帧。
- 二维码等同登录票据，只打在当前终端，不进日志、不落盘、不要截图外发。日志只记字段号、计数和布尔，不记 SDP、候选、token、TURN 凭据、终端字节和映射载荷。

## 代码结构

```text
src/
  main.rs          入口：取命令、初始化日志、交给 cli
  cli/             args 解析、ui、devices（auth/list/菜单）、access（portmap/ssh/sftp/tunnel）
  cloud/           config、creds、签名 REST（api）、扫码登录（login）
  net/             signaling、ice、peer（被控端建连）
  net/controller/  控制端：rtc（Message 27 客户端）、signal、ssh（russh）
  host/            run 的房间循环、terminal（TERM 帧 + PTY）、portmap（Message 27）、
                   file_transfer（RPC 21/22 的浏览/上传/下载/删除）
  proto/           wire（protobuf 读取）、envelope（外层信封）
```

协议行为对齐官方 host 与主程序，代码独立重写：字段号、帧布局、常量这类事实一致，实现与命名不复用。
字段号以 `proto/`、`host/`、`net/controller/` 的代码为准，这里不再列一遍。

## 许可证

MIT，见 [LICENSE](LICENSE)。


## 致谢
- [VallierDev/uu-remote-linux](https://github.com/VallierDev/uu-remote-linux)
- 网易 UU 远程团队：做了一个好用的远程工具。
- [webrtc-rs](https://github.com/webrtc-rs/webrtc) 等开源项目。
