//! 协议常量与 AAD 上下文构造。
//!
//! 所有跨语言（Rust / Kotlin / TypeScript）共享的魔数和布局都集中在这里，
//! 各语言侧只允许从本文档对应的常量表里取字面量，不得就地硬编码。

/// 协议版本。
///
/// 一旦改动帧布局或握手消息格式就必须递增，并且服务端要在同一发布窗口内
/// 同时支持新旧两版（见 `docs/design.md` 的上线策略章节）。改这个数字不会报错，
/// 只会让老客户端全线失联。
///
/// v2：握手密钥派生绑定设备号（device_id 折进握手 info），见 [`crate::kdf::derive_handshake_key`]。
/// 报文二进制布局与 v1 相同，但派生方式变了，两版握手密钥互不通用，故必须升版。
pub const PROTOCOL_VERSION: u8 = 2;

/// 会话 ID 长度。
pub const SESSION_ID_LEN: usize = 16;
/// 握手 nonce 长度。
pub const HELLO_NONCE_LEN: usize = 16;
/// X25519 公钥 / 私钥长度。
pub const X25519_KEY_LEN: usize = 32;

/// 数据帧头部长度：version(1) + seq(8) + ts_ms(8)。
pub const FRAME_HEADER_LEN: usize = 17;
/// version 字段在帧内的偏移。
pub const FRAME_VERSION_OFFSET: usize = 0;
/// AEAD nonce 在帧内的偏移。
pub const FRAME_NONCE_OFFSET: usize = FRAME_HEADER_LEN;
/// AEAD nonce 长度（与 [`crate::aead::NONCE_LEN`] 同值，这里再导出一次方便绑定层引用）。
pub const AEAD_NONCE_LEN: usize = 12;
/// 帧最小长度：头部 + nonce + 空明文 + 标签。
pub const FRAME_MIN_LEN: usize = FRAME_HEADER_LEN + AEAD_NONCE_LEN + crate::aead::TAG_LEN;

/// 时间戳允许的偏差窗口（毫秒）。
///
/// 取 5 分钟是「设备时钟漂移」和「重放窗口大小」之间的折中：
/// - 太短：手机时钟没同步的设备会大面积握手失败，而且这是静默的 ——
///   用户看到的是「网络异常」。
/// - 太长：攻击者拿到一个截获帧后可以重放的窗口变长。
///
/// 注意这个窗口只是**第一道**防线，真正的防重放靠序号滑窗（帧）和
/// nonce 缓存（握手），时间戳只是把无限期的重放压成 5 分钟。
pub const TIMESTAMP_SKEW_MS: u64 = 5 * 60 * 1000;

/// 会话默认有效期（秒）。服务端可以在 ServerHello 里下发更短的值。
pub const DEFAULT_SESSION_TTL_SECS: u32 = 30 * 60;

/// 单会话建议的最大帧数，超过就要求重新握手。
///
/// ChaCha20-Poly1305 使用 96 位**随机** nonce 时，碰撞概率按生日界计算：
/// 约 2^32 个消息后有不可忽略的碰撞风险。这里留两个数量级的余量取 2^24。
/// 达到上限时主动要求 rekey，而不是继续用到出问题 —— nonce 复用会直接
/// 摧毁 AEAD 的机密性（异或出明文），而且完全没有报错。
pub const MAX_FRAMES_PER_SESSION: u64 = 1 << 24;

/// PSK 标识的最大长度。放 u8 长度前缀，所以不能超过 255。
pub const MAX_PSK_ID_LEN: usize = 64;

// ---------------------------------------------------------------------------
// 握手消息布局
// ---------------------------------------------------------------------------

/// ClientHello 固定前缀长度：version(1) + psk_id_len(1)。
pub const CLIENT_HELLO_PREFIX_LEN: usize = 2;
/// ClientHello 固定后缀长度：client_nonce(16) + eph_pub(32) + ts_ms(8) + mac(32)。
pub const CLIENT_HELLO_SUFFIX_LEN: usize = HELLO_NONCE_LEN + X25519_KEY_LEN + 8 + 32;
/// ClientHello 最小长度（psk_id 为空时）。
pub const CLIENT_HELLO_MIN_LEN: usize = CLIENT_HELLO_PREFIX_LEN + CLIENT_HELLO_SUFFIX_LEN;

/// ServerHello 固定长度：version(1) + session_id(16) + client_nonce(16)
/// + server_eph_pub(32) + ts_ms(8) + ttl_secs(4) + mac(32)。
pub const SERVER_HELLO_LEN: usize =
    1 + SESSION_ID_LEN + HELLO_NONCE_LEN + X25519_KEY_LEN + 8 + 4 + 32;

/// HTTP 头名称：承载协议版本、会话 ID 和序号。
pub const HEADER_NAME: &str = "X-Taotao-Crypto";

/// 构造帧的 AAD 上下文。
///
/// 约定格式：`{METHOD} {PATH}?{QUERY}`，例如 `POST /api/v1/favorites`。
/// 之所以把方法也放进去：只绑路径的话，`GET /api/v1/playlists/{id}` 和
/// `DELETE /api/v1/playlists/{id}` 会共享同一个 AAD，攻击者可以把读请求的
/// 密文改发成删除请求。
///
/// **必须包含查询串**：分页、搜索关键字都在 query 里，不绑的话攻击者可以
/// 保留密文只改 `page` 参数来遍历数据。
///
/// 响应方向的上下文由调用方按同样规则构造，通常是 `{STATUS} {PATH}`。
pub fn aad_context(method: &str, path_and_query: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(method.len() + 1 + path_and_query.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path_and_query.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_constants_are_consistent() {
        assert_eq!(FRAME_HEADER_LEN, 17);
        assert_eq!(FRAME_NONCE_OFFSET, 17);
        assert_eq!(FRAME_MIN_LEN, 17 + 12 + 16);
        assert_eq!(CLIENT_HELLO_MIN_LEN, 2 + 16 + 32 + 8 + 32);
        assert_eq!(SERVER_HELLO_LEN, 1 + 16 + 16 + 32 + 8 + 4 + 32);
    }

    #[test]
    fn aad_includes_method_and_query() {
        assert_eq!(
            aad_context("GET", "/api/v1/favorites"),
            b"GET /api/v1/favorites"
        );
        assert_ne!(
            aad_context("GET", "/api/v1/playlists/1"),
            aad_context("DELETE", "/api/v1/playlists/1"),
            "方法不同的同路径必须产生不同 AAD"
        );
        assert_ne!(
            aad_context("GET", "/api/v1/search?q=a"),
            aad_context("GET", "/api/v1/search?q=b"),
            "查询串不同的同路径必须产生不同 AAD"
        );
    }
}
