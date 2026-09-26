//! 会话状态机：帧的封装与解封。
//!
//! 一个 [`Session`] 同时管两个方向 —— 因为 [`crate::kdf::derive_session_keys`]
//! 对客户端和服务端返回的是**互为镜像**的密钥对，两侧的
//! 「用 seal_key 加密、用 open_key 解密」逻辑完全一致，不需要按角色分支。
//!
//! 会话必须由调用方持有并复用：每次请求重新握手会把整个握手的开销（一次完整
//! 握手 = 4 次 X25519 标量乘，本机实测约 207 微秒）叠在每个请求上，在低端
//! 安卓机上足以造成可感知的卡顿。
//!
//! ⚠️ 这个数字**强依赖 release profile 的 `opt-level`**。`Cargo.toml` 里曾用
//! `"z"`（优先体积），实测会把同一段握手放大到 **6029 微秒（29 倍）**。改那个
//! 配置之前先跑 `cargo bench -p taotao-crypto-core`，别让注释和现实脱节 ——
//! 这里原来写的「大约 50 微秒」就是这么失效的。

use crate::error::{CryptoError, Result};
use crate::frame::{open_frame, seal_frame, OpenedFrame, ReplayWindow, SealedFrame};
use crate::kdf::SessionKeys;
use crate::protocol::{
    FRAME_VERSION_OFFSET, MAX_FRAMES_PER_SESSION, PROTOCOL_VERSION, SESSION_ID_LEN,
};

/// 一条已建立的加密会话。
pub struct Session {
    id: [u8; SESSION_ID_LEN],
    keys: SessionKeys,
    created_at_ms: u64,
    expires_at_ms: u64,
    /// 下一个待使用的发送序号。从 1 开始，0 保留给「未初始化」。
    next_seq: u64,
    /// 对端序号的防重放滑窗。
    replay: ReplayWindow,
    /// 本会话已封装的帧数，用于触发 rekey。
    frames_sealed: u64,
}

impl Session {
    /// 建立会话。
    ///
    /// `ttl_secs` 来自 ServerHello；为 0 时按默认值处理，避免服务端漏填导致
    /// 会话一建立就过期（表现是「握手成功但所有请求都失败」，非常难查）。
    pub fn new(id: [u8; SESSION_ID_LEN], keys: SessionKeys, now_ms: u64, ttl_secs: u32) -> Self {
        let ttl = if ttl_secs == 0 {
            crate::protocol::DEFAULT_SESSION_TTL_SECS
        } else {
            ttl_secs
        };
        Self {
            id,
            keys,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl as u64 * 1000),
            next_seq: 1,
            replay: ReplayWindow::new(),
            frames_sealed: 0,
        }
    }

    pub fn id(&self) -> [u8; SESSION_ID_LEN] {
        self.id
    }

    /// 会话 ID 的十六进制表示，用于写进 HTTP 头。
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// 从 `now_ms` 起还能用多久（毫秒）。已过期返回 0。
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.expires_at_ms.saturating_sub(now_ms)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// 是否该主动重新握手。
    ///
    /// 除了帧数上限，还留出 10% 的有效期余量：等到会话真正过期才 rekey 的话，
    /// 过期瞬间的并发请求会全部失败并各自触发一次重试握手，形成惊群。
    pub fn needs_rekey(&self, now_ms: u64) -> bool {
        if self.frames_sealed >= MAX_FRAMES_PER_SESSION {
            return true;
        }
        let total = self.expires_at_ms.saturating_sub(self.created_at_ms);
        let elapsed = now_ms.saturating_sub(self.created_at_ms);
        // 用 `saturating_mul` 而不是 `*`：`now_ms` 由宿主传入，一个离谱的时间戳
        // （0、u64::MAX、或者误把秒当成毫秒）会让 `elapsed * 10` 溢出 ——
        // debug 下直接 panic，release 下（`overflow-checks = false`）静默回绕成
        // 一个小数字，于是「早就该 rekey」被判成「还早」。
        // 会话是否真的过期另有 `is_expired` 把关，这里只负责把判断算对。
        elapsed.saturating_mul(10) >= total.saturating_mul(9)
    }

    /// 加密一段明文，返回可直接作为请求/响应体发送的帧。
    ///
    /// `aad_context` 见 [`crate::protocol::aad_context`]。
    pub fn seal(
        &mut self,
        aad_context: &[u8],
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<SealedFrame> {
        if self.is_expired(now_ms) {
            return Err(CryptoError::SessionExpired);
        }
        if self.next_seq >= MAX_FRAMES_PER_SESSION {
            return Err(CryptoError::SequenceExhausted);
        }

        let seq = self.next_seq;
        let bytes = seal_frame(
            &self.keys.seal_key,
            &self.id,
            seq,
            now_ms,
            aad_context,
            plaintext,
        )?;

        self.next_seq += 1;
        self.frames_sealed += 1;

        Ok(SealedFrame {
            session_id: self.id,
            seq,
            ts_ms: now_ms,
            bytes,
        })
    }

    /// 解密一个帧。
    ///
    /// 实际顺序是 **解密 → 时间戳 → 防重放**。
    ///
    /// ⚠️ 时间戳**不可能**排在解密前面：它就在帧头里，而帧头是 AAD 的一部分，
    /// 在 AEAD 校验通过之前它是攻击者可以随意改的字节。想「先看时间戳再解密」，
    /// 看到的只是一个未经认证的、由攻击者提供的数字 —— 拿它做拒绝决策等于白送
    /// 对方一个丢弃开关。
    ///
    /// 所以这里的取舍是「付一次 AEAD 解密的代价，换一个可信的时间戳」。真要省这
    /// 一次解密，只能用 [`Session::peek_header`] 读**未认证**的时间戳做廉价预筛
    /// （明显超出窗口的直接丢），但那只是优化，最终判断必须落在这一次。
    ///
    /// 防重放放最后则是刻意的：只有解密成功才值得占用滑窗的一个位置，否则攻击者
    /// 可以拿伪造帧把滑窗填满，把真帧挤成「重放」。
    pub fn open(&mut self, aad_context: &[u8], frame: &[u8], now_ms: u64) -> Result<OpenedFrame> {
        let opened = open_frame(&self.keys.open_key, &self.id, aad_context, frame)?;

        let skew = opened.ts_ms.abs_diff(now_ms);
        if skew > crate::protocol::TIMESTAMP_SKEW_MS {
            return Err(CryptoError::TimestampOutOfWindow {
                skew_ms: skew,
                limit_ms: crate::protocol::TIMESTAMP_SKEW_MS,
            });
        }

        self.replay.check_and_update(opened.seq)?;
        Ok(opened)
    }

    /// 只解析帧头，不解密。用于在读取请求体之前做路由/限流决策。
    ///
    /// 返回 `(协议版本, 序号, 时间戳)`。注意帧头**尚未**通过认证 —— 调用方
    /// 只能用它做粗筛（比如「这个序号看起来已经处理过了，直接丢」），
    /// 任何安全决策都必须等 [`Session::open`] 成功之后。
    pub fn peek_header(frame: &[u8]) -> Result<(u8, u64, u64)> {
        if frame.len() < crate::protocol::FRAME_MIN_LEN {
            return Err(CryptoError::Truncated {
                need: crate::protocol::FRAME_MIN_LEN,
                got: frame.len(),
            });
        }
        let version = frame[FRAME_VERSION_OFFSET];
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&frame[1..9]);
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&frame[9..17]);
        Ok((
            version,
            u64::from_be_bytes(seq_bytes),
            u64::from_be_bytes(ts_bytes),
        ))
    }

    /// 从帧里取出会话 ID。
    ///
    /// 帧本身不含会话 ID —— 它在 HTTP 头里。这个函数是为了让调用方能从
    /// 头部字符串恢复出会话 ID 并查表。返回 `None` 表示头部格式非法。
    pub fn parse_header_value(value: &str) -> Option<([u8; SESSION_ID_LEN], u64)> {
        let mut parts = value.split('.');
        let tag = parts.next()?;
        // 版本标签跟随 PROTOCOL_VERSION，不能硬编码 —— 否则升版后握手能成、
        // 但头部一律被自己的解析器拒掉（v2 的头带 "v2."，硬编码 "v1" 会全拒）。
        let expected_tag = format!("v{}", PROTOCOL_VERSION);
        if tag != expected_tag.as_str() {
            return None;
        }
        let session_hex = parts.next()?;
        let seq: u64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let bytes = hex::decode(session_hex).ok()?;
        let id: [u8; SESSION_ID_LEN] = bytes.as_slice().try_into().ok()?;
        Some((id, seq))
    }

    /// 生成 HTTP 头值：`v<版本>.<session_id_hex>.<seq>`。
    pub fn header_value(&self, seq: u64) -> String {
        format!("v{}.{}.{}", PROTOCOL_VERSION, self.id_hex(), seq)
    }

    /// 下一个待使用的发送序号（尚未被任何帧占用）。
    pub fn next_seq_for_header(&self) -> u64 {
        self.next_seq
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id_hex())
            .field("expires_at_ms", &self.expires_at_ms)
            .field("next_seq", &self.next_seq)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_session_keys, KEY_LEN};

    const NOW: u64 = 1_700_000_000_000;

    fn session_pair(ttl_secs: u32) -> (Session, Session) {
        let shared = [0x5Au8; 32];
        let sid = [0x0Fu8; SESSION_ID_LEN];
        let (client_keys, server_keys) = derive_session_keys(&shared, b"nonce-16-bytes!!", &sid);
        (
            Session::new(sid, client_keys, NOW, ttl_secs),
            Session::new(sid, server_keys, NOW, ttl_secs),
        )
    }

    #[test]
    fn bidirectional_roundtrip() {
        let (mut c, mut s) = session_pair(600);
        let req = c
            .seal(b"POST /api/v1/favorites", br#"{"songId":"1"}"#, NOW)
            .unwrap();
        assert_eq!(req.seq, 1);
        assert_eq!(
            s.open(b"POST /api/v1/favorites", &req.bytes, NOW)
                .unwrap()
                .plaintext,
            br#"{"songId":"1"}"#
        );

        let resp = s.seal(b"200 /api/v1/favorites", b"{}", NOW).unwrap();
        assert_eq!(
            c.open(b"200 /api/v1/favorites", &resp.bytes, NOW)
                .unwrap()
                .plaintext,
            b"{}"
        );
    }

    #[test]
    fn sequence_increments_per_frame() {
        let (mut c, _s) = session_pair(600);
        for expected in 1..=5u64 {
            let frame = c.seal(b"ctx", b"x", NOW).unwrap();
            assert_eq!(frame.seq, expected);
        }
    }

    #[test]
    fn header_value_roundtrips() {
        let (c, _s) = session_pair(600);
        let value = c.header_value(42);
        assert_eq!(value, format!("v{}.{}.42", PROTOCOL_VERSION, c.id_hex()));
        let (id, seq) = Session::parse_header_value(&value).unwrap();
        assert_eq!(id, c.id());
        assert_eq!(seq, 42);
    }

    #[test]
    fn header_value_rejects_garbage() {
        let v = PROTOCOL_VERSION;
        assert!(Session::parse_header_value("").is_none());
        // 旧版本号必须拒绝（当前协议是 v2）。
        let old_version = "v1.00112233445566778899aabbccddeeff.1";
        assert!(Session::parse_header_value(old_version).is_none());
        // 会话 ID 长度不对。
        let bad_sid = format!("v{v}.abc.1");
        assert!(Session::parse_header_value(&bad_sid).is_none());
        // 序号不是数字。
        let bad_seq = format!("v{v}.00112233445566778899aabbccddeeff.abc");
        assert!(Session::parse_header_value(&bad_seq).is_none());
        // 多出一段。
        let extra = format!("v{v}.00112233445566778899aabbccddeeff.1.extra");
        assert!(Session::parse_header_value(&extra).is_none());
    }

    #[test]
    fn expired_session_refuses_to_seal() {
        let (mut c, _s) = session_pair(60);
        let later = NOW + 61_000;
        assert!(c.is_expired(later));
        assert_eq!(
            c.seal(b"ctx", b"x", later).unwrap_err(),
            CryptoError::SessionExpired
        );
        assert_eq!(c.remaining_ms(later), 0);
    }

    #[test]
    fn zero_ttl_falls_back_to_default() {
        let (c, _s) = session_pair(0);
        // 漏填 ttl 不能让会话立刻过期 —— 那会表现成「握手成功但请求全失败」。
        assert_eq!(
            c.expires_at_ms(),
            NOW + crate::protocol::DEFAULT_SESSION_TTL_SECS as u64 * 1000
        );
    }

    #[test]
    fn rekey_is_requested_before_expiry() {
        let (c, _s) = session_pair(1000);
        assert!(!c.needs_rekey(NOW), "刚建立不该要求 rekey");
        // 走到 90% 有效期时应提前要求 rekey，避免过期瞬间惊群。
        assert!(c.needs_rekey(NOW + 901_000));
    }

    #[test]
    fn needs_rekey_survives_absurd_clock() {
        // `now_ms` 由宿主传入，可能是一个离谱的值。测试跑在 debug profile 下
        // （`overflow-checks` 默认开），所以这里一旦回绕就会直接 panic ——
        // 这条用例就是那个 panic 的哨兵。
        let (c, _s) = session_pair(1000);
        assert!(
            c.needs_rekey(u64::MAX),
            "远超有效期必须要求 rekey，且不能溢出"
        );
        // 时间为 0 时 elapsed 被 saturating 成 0，等价于「刚建立」。
        assert!(!c.needs_rekey(0));
    }

    #[test]
    fn stale_frame_is_rejected_on_open() {
        let (mut c, mut s) = session_pair(600);
        let frame = c.seal(b"ctx", b"x", NOW).unwrap();
        let err = s
            .open(
                b"ctx",
                &frame.bytes,
                NOW + crate::protocol::TIMESTAMP_SKEW_MS + 1,
            )
            .unwrap_err();
        assert!(matches!(err, CryptoError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn replayed_frame_is_rejected_on_open() {
        let (mut c, mut s) = session_pair(600);
        let frame = c.seal(b"ctx", b"x", NOW).unwrap();
        s.open(b"ctx", &frame.bytes, NOW).unwrap();
        // 原样重放 —— 序号滑窗必须挡住。
        assert!(matches!(
            s.open(b"ctx", &frame.bytes, NOW).unwrap_err(),
            CryptoError::ReplayDetected { .. }
        ));
    }

    #[test]
    fn peek_header_works_without_decrypting() {
        let (mut c, _s) = session_pair(600);
        let frame = c.seal(b"ctx", b"payload", NOW).unwrap();
        let (version, seq, ts) = Session::peek_header(&frame.bytes).unwrap();
        assert_eq!(version, PROTOCOL_VERSION);
        assert_eq!(seq, 1);
        assert_eq!(ts, NOW);
    }

    #[test]
    fn peek_header_rejects_short_frame() {
        assert!(Session::peek_header(&[0u8; 5]).is_err());
    }

    #[test]
    fn aad_binds_request_to_endpoint() {
        let (mut c, mut s) = session_pair(600);
        let frame = c.seal(b"GET /api/v1/favorites", b"", NOW).unwrap();
        // 把收藏列表的密文改发到删除端点 —— 必须失败。
        assert!(s
            .open(b"DELETE /api/v1/playlists/1", &frame.bytes, NOW)
            .is_err());
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let (c, _s) = session_pair(600);
        let text = format!("{c:?}");
        assert!(text.contains(&c.id_hex()));
        assert!(!text.contains("5a"), "Debug 不能泄露密钥：{text}");
    }

    #[test]
    fn session_keys_debug_is_redacted() {
        let keys = crate::kdf::SessionKeys::pair_for_test([0xAB; KEY_LEN]);
        assert!(format!("{keys:?}").contains("已隐藏"));
    }
}
