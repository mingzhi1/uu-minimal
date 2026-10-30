//! `--no-default-features` 时的终端占位实现。
//!
//! 目的是让 `net/peer.rs` 完全不用 `cfg` 判断：终端相关的帧一律视为“不归我管”，
//! 由端口映射继续处理。这样 Android / 无 PTY 环境可以去掉 `nix` 依赖而不改动数据面代码。

use tokio::sync::mpsc::UnboundedSender;

/// 占位连接：有 `out` 只是为了签名一致，实际永不发送。
pub struct TerminalConn {
    #[allow(dead_code)]
    out: UnboundedSender<Vec<u8>>,
}

impl TerminalConn {
    pub fn new(out: UnboundedSender<Vec<u8>>) -> Self {
        Self { out }
    }

    /// 没有终端能力：直接忽略。
    pub fn handle(&self, _data: &[u8]) {}
}

/// 永远不是 TERM 帧。
pub fn is_frame(_data: &[u8]) -> bool {
    false
}

/// 没有终端 RPC 可回（`check_env` 会被当作不支持）。
pub fn rpc_response(_request: &[crate::proto::Field<'_>]) -> Option<Vec<u8>> {
    None
}

/// 无会话可收。
pub fn shutdown_all() {}
