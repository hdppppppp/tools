//! 加密层的错误类型。
//!
//! 每个变体都对应一个**必须能区分**的失败原因：客户端要靠它决定「重新握手」
//! 还是「报错给用户」，服务端要靠它决定「回 401 让客户端重试」还是「回 400
//! 直接拒绝」。所以这里不做错误合并，也不把内部细节（比如期望的 MAC 值）
//! 放进消息里 —— 那会把错误响应变成一条侧信道。
//!
//! ## 为什么不用 `thiserror`
//!
//! 原先是 `#[derive(thiserror::Error)]` + `#[error("...")]`。那个写法把消息
//! 放在**属性位置**，而属性里塞不进宏调用 —— 结果是这 12 条消息以明文留在
//! 二进制里，而它们恰恰是泄露最多的一类：`时间戳超出允许窗口：偏差 {} ms`
//! 等于直接告诉逆向者「这里做了防重放时间窗校验」。
//!
//! 现在手写 [`Display`](core::fmt::Display)，消息模板经 [`crate::obf::obf!`]
//! 混淆。代价是模板里的参数要用**顺序** `{}` 而不是命名参数 —— `thiserror`
//! 的 `{got}` 这种命名写法依赖 `format_args!` 的编译期模板，而混淆后的模板是
//! 运行期解出来的 `String`，`format_args!` 接不了。

use core::fmt;

/// 加密层统一错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 协议版本不支持。`got` 是收到的版本号，`supported` 是本端支持的版本号。
    UnsupportedVersion { got: u8, supported: u8 },

    /// 消息被截断：至少需要 `need` 字节，实际只有 `got` 字节。
    Truncated { need: usize, got: usize },

    /// 握手 MAC 校验失败。刻意不区分「PSK 不对」和「消息被改过」——
    /// 两者对攻击者来说是同一个信息，区分开只会帮他把爆破变成二分。
    HandshakeAuthFailed,

    /// 时间戳超出允许窗口，可能被重放。
    TimestampOutOfWindow { skew_ms: u64, limit_ms: u64 },

    /// 检测到重放：该序号已经处理过。
    ReplayDetected { seq: u64 },

    /// 会话尚未建立。
    SessionNotReady,

    /// 会话已过期，需要重新握手。
    SessionExpired,

    /// 会话序号空间耗尽。
    SequenceExhausted,

    // 这里**刻意没有** `UnknownPskId` 这个变体。
    //
    // 它曾经存在，并且被 `accept_client_hello` 在「psk_id 查不到」时返回。
    // 那是个信息泄露：psk_id 只是版本标签（`prod-v1` 这种），不是秘密，攻击者
    // 可以用不同的 id 反复握手，靠「返回的是 UnknownPskId 还是
    // HandshakeAuthFailed」把服务端配置的 id 枚举出来 —— 一旦确认 id，他就省掉
    // 了猜 id 这一步，只需要专心对付密钥。而且这条路径还少算一次 HKDF + HMAC，
    // 就算统一了错误码，响应时间仍然能被用来问同一个问题。
    //
    // 现在「id 不认识」和「MAC 不对」统一返回 [`CryptoError::HandshakeAuthFailed`]，
    // 且两者计算量相同。运维需要的「客户端发的是哪个 id」由
    // `handshake::peek_psk_id` 单独提供 —— 那条路径只写日志，不回客户端。
    //
    // 不要为了「错误信息更友好」把它加回来。
    /// 密钥材料长度非法。
    InvalidKeyLength { expected: usize, got: usize },

    /// 数据帧解密失败。同样不区分「密钥不对」「AAD 不匹配」「密文被改」。
    FrameAuthFailed,

    /// 操作系统随机数源不可用。
    RandomFailure(String),

    /// 构建期没有注入 PSK，且没有可用的回退。
    PskNotConfigured(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::obf::{obf, obf_fmt};

        match self {
            Self::UnsupportedVersion { got, supported } => {
                obf_fmt!(f, "协议版本不支持：收到 {}，当前支持 {}", got, supported)
            }
            Self::Truncated { need, got } => {
                obf_fmt!(f, "消息长度非法：至少需要 {} 字节，实际 {} 字节", need, got)
            }
            Self::HandshakeAuthFailed => f.write_str(&obf!("握手认证失败")),
            Self::TimestampOutOfWindow { skew_ms, limit_ms } => obf_fmt!(
                f,
                "时间戳超出允许窗口：偏差 {} ms，上限 {} ms",
                skew_ms,
                limit_ms
            ),
            Self::ReplayDetected { seq } => {
                obf_fmt!(f, "检测到重放：序号 {} 已处理过", seq)
            }
            Self::SessionNotReady => f.write_str(&obf!("会话尚未建立，请先完成握手")),
            Self::SessionExpired => f.write_str(&obf!("会话已过期")),
            Self::SequenceExhausted => f.write_str(&obf!("会话序号空间耗尽，必须重新握手")),
            Self::InvalidKeyLength { expected, got } => obf_fmt!(
                f,
                "密钥材料长度非法：期望 {} 字节，实际 {} 字节",
                expected,
                got
            ),
            Self::FrameAuthFailed => f.write_str(&obf!("帧认证失败")),
            Self::RandomFailure(err) => {
                obf_fmt!(f, "随机数源不可用：{}", err)
            }
            Self::PskNotConfigured(detail) => {
                obf_fmt!(f, "PSK 尚未配置：{}", detail)
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// 加密层的统一返回类型。
pub type Result<T> = core::result::Result<T, CryptoError>;
