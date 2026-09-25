//! 加密层的错误类型。
//!
//! 每个变体都对应一个**必须能区分**的失败原因：客户端要靠它决定「重新握手」
//! 还是「报错给用户」，服务端要靠它决定「回 401 让客户端重试」还是「回 400
//! 直接拒绝」。所以这里不做错误合并，也不把内部细节（比如期望的 MAC 值）
//! 放进消息里 —— 那会把错误响应变成一条侧信道。

/// 加密层统一错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("协议版本不支持：收到 {got}，当前支持 {supported}")]
    UnsupportedVersion { got: u8, supported: u8 },

    #[error("消息长度非法：至少需要 {need} 字节，实际 {got} 字节")]
    Truncated { need: usize, got: usize },

    /// 握手 MAC 校验失败。刻意不区分「PSK 不对」和「消息被改过」——
    /// 两者对攻击者来说是同一个信息，区分开只会帮他把爆破变成二分。
    #[error("握手认证失败")]
    HandshakeAuthFailed,

    #[error("时间戳超出允许窗口：偏差 {skew_ms} ms，上限 {limit_ms} ms")]
    TimestampOutOfWindow { skew_ms: u64, limit_ms: u64 },

    #[error("检测到重放：序号 {seq} 已处理过")]
    ReplayDetected { seq: u64 },

    #[error("会话尚未建立，请先完成握手")]
    SessionNotReady,

    #[error("会话已过期")]
    SessionExpired,

    #[error("会话序号空间耗尽，必须重新握手")]
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
    #[error("密钥材料长度非法：期望 {expected} 字节，实际 {got} 字节")]
    InvalidKeyLength { expected: usize, got: usize },

    /// 数据帧解密失败。同样不区分「密钥不对」「AAD 不匹配」「密文被改」。
    #[error("帧认证失败")]
    FrameAuthFailed,

    #[error("随机数源不可用：{0}")]
    RandomFailure(String),

    #[error("PSK 尚未配置：{0}")]
    PskNotConfigured(String),
}

/// 加密层的统一返回类型。
pub type Result<T> = core::result::Result<T, CryptoError>;
