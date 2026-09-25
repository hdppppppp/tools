//! 数据帧编解码与防重放滑窗。
//!
//! 帧布局（全部大端，与 `docs/design.md` 的协议章节一致）：
//!
//! ```text
//! 偏移  长度  字段
//! 0     1     version      协议版本
//! 1     8     seq          会话内单调递增的序号
//! 9     8     ts_ms        Unix 毫秒时间戳
//! 17    12    nonce       AEAD nonce（每次随机，不复用）
//! 29    N     ciphertext  密文
//! 29+N  16    tag         Poly1305 认证标签
//! ```
//!
//! 帧头（version/seq/ts_ms）进 AAD，所以它自己也受认证保护 —— 攻击者改不动
//! 序号或时间戳来绕过重放检测。

use zeroize::Zeroize;

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::kdf::{random_array, KEY_LEN};
use crate::protocol::{
    AEAD_NONCE_LEN, FRAME_HEADER_LEN, FRAME_MIN_LEN, FRAME_VERSION_OFFSET, PROTOCOL_VERSION,
};

/// 防重放滑窗宽度（位）。
///
/// 取 64 是因为正好放进一个 u64 位图，判断和更新都是 O(1) 且无分配。
/// 64 帧的乱序容忍度对 HTTP 来说绰绰有余：同一个会话上并发 64 个请求还没回来
/// 已经属于异常，真要更多就该开新会话了。
pub const REPLAY_WINDOW_BITS: u64 = 64;

/// 一个会话内对端序号的防重放滑窗。
///
/// 之所以需要滑窗而不是「只记最大序号」：HTTP 请求会并发，序号 5 的响应可能
/// 比序号 4 先到。只记最大值会把迟到的 4 误判成重放，表现为「偶发请求失败」，
/// 而且极难复现。
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// 已见过的最大序号。
    highest: u64,
    /// 位 i 表示 `highest - i` 这个序号是否已经出现过。
    bitmap: u64,
    /// 是否收到过第一个帧。首个帧不做窗口校验（否则初始 highest=0 会误判）。
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            initialized: false,
        }
    }

    /// 校验并记录一个序号。
    ///
    /// 返回 `Ok(())` 表示这个序号是新的、可以用；返回
    /// [`CryptoError::ReplayDetected`] 表示见过（或太旧，窗口外的旧序号一律
    /// 按重放处理 —— 宁可误拒也不能放过）。
    pub fn check_and_update(&mut self, seq: u64) -> Result<()> {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1;
            return Ok(());
        }

        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= REPLAY_WINDOW_BITS {
                // 跳得太远，窗口内所有旧序号都滑出去了，只保留新的这一个。
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = seq;
            return Ok(());
        }

        let diff = self.highest - seq;
        if diff >= REPLAY_WINDOW_BITS {
            return Err(CryptoError::ReplayDetected { seq });
        }
        let mask = 1u64 << diff;
        if self.bitmap & mask != 0 {
            return Err(CryptoError::ReplayDetected { seq });
        }
        self.bitmap |= mask;
        Ok(())
    }
}

/// 一个已封装的帧，拆成「头部值」和「帧体」两部分。
///
/// 拆开是为了直接对接 HTTP：头部值放 `X-Taotao-Crypto` 请求头，帧体放请求体。
/// 服务端不必先解析 body 就能拿到会话 ID 和序号，鉴权、限流、重放检测都能在
/// 读取请求体之前完成 —— 这对挡住「拿超大 body 打满内存」很重要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFrame {
    /// 会话 ID（16 字节）。
    pub session_id: [u8; 16],
    /// 本帧序号。
    pub seq: u64,
    /// 本帧时间戳（Unix 毫秒）。
    pub ts_ms: u64,
    /// 完整帧字节：头 + 密文 + 标签。直接作为请求/响应体。
    pub bytes: Vec<u8>,
}

/// 把会话密钥、AAD 上下文和明文封装成一个帧。
///
/// `aad_context` 由调用方提供，约定格式见 [`crate::protocol::aad_context`]。
pub fn seal_frame(
    key: &[u8; KEY_LEN],
    session_id: &[u8; 16],
    seq: u64,
    ts_ms: u64,
    aad_context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce: [u8; AEAD_NONCE_LEN] = random_array()?;

    let mut header = [0u8; FRAME_HEADER_LEN];
    header[FRAME_VERSION_OFFSET] = PROTOCOL_VERSION;
    header[1..9].copy_from_slice(&seq.to_be_bytes());
    header[9..17].copy_from_slice(&ts_ms.to_be_bytes());

    let aad = build_aad(session_id, aad_context, &header);
    let ciphertext = aead::seal(key, &nonce, &aad, plaintext)?;

    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + AEAD_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// 构造帧的 AAD。
///
/// 三段拼接：会话 ID + 调用方上下文 + 帧头。
/// - **会话 ID** 是纵深防御。密钥本来就已经按会话隔离了，理论上换个会话 ID
///   也解不开；但把它放进 AAD 之后，「帧被搬到另一个会话」会在认证层就失败，
///   而不是依赖密钥不同这个间接推论。
/// - **调用方上下文**把帧绑到具体端点（方法 + 路径 + 查询串）。
/// - **帧头**保护序号和时间戳本身，防止攻击者改序号绕过重放滑窗。
fn build_aad(
    session_id: &[u8; 16],
    aad_context: &[u8],
    header: &[u8; FRAME_HEADER_LEN],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + aad_context.len() + FRAME_HEADER_LEN);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(aad_context);
    aad.extend_from_slice(header);
    aad
}

/// 帧解析结果：序号、时间戳、明文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    pub seq: u64,
    pub ts_ms: u64,
    pub plaintext: Vec<u8>,
}

/// 解析一个帧并解密。
///
/// 注意本函数**不做**重放检测：重放窗口是会话级状态，调用方需要在通过
/// 时间戳校验之后、真正使用明文之前调 [`ReplayWindow::check_and_update`]。
/// 顺序很关键 —— 先解密再检重放会让攻击者能用重放帧消耗 CPU。
pub fn open_frame(
    key: &[u8; KEY_LEN],
    session_id: &[u8; 16],
    aad_context: &[u8],
    frame: &[u8],
) -> Result<OpenedFrame> {
    if frame.len() < FRAME_MIN_LEN {
        return Err(CryptoError::Truncated {
            need: FRAME_MIN_LEN,
            got: frame.len(),
        });
    }

    let version = frame[FRAME_VERSION_OFFSET];
    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion {
            got: version,
            supported: PROTOCOL_VERSION,
        });
    }

    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&frame[1..9]);
    let seq = u64::from_be_bytes(seq_bytes);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&frame[9..17]);
    let ts_ms = u64::from_be_bytes(ts_bytes);

    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + AEAD_NONCE_LEN]);

    let ciphertext = &frame[FRAME_HEADER_LEN + AEAD_NONCE_LEN..];

    let mut header = [0u8; FRAME_HEADER_LEN];
    header.copy_from_slice(&frame[..FRAME_HEADER_LEN]);
    let aad = build_aad(session_id, aad_context, &header);

    let mut plaintext = aead::open(key, &nonce, &aad, ciphertext)?;
    let result = OpenedFrame {
        seq,
        ts_ms,
        // 先把明文拷出来再返回，避免调用方持有内部缓冲区的引用。
        plaintext: plaintext.clone(),
    };
    plaintext.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const SID: [u8; 16] = [0x11; 16];

    #[test]
    fn frame_roundtrip() {
        let frame = seal_frame(&KEY, &SID, 1, 1_700_000_000_000, b"POST /a", b"payload").unwrap();
        assert!(frame.len() >= FRAME_MIN_LEN);
        assert_eq!(frame[FRAME_VERSION_OFFSET], PROTOCOL_VERSION);

        let opened = open_frame(&KEY, &SID, b"POST /a", &frame).unwrap();
        assert_eq!(opened.seq, 1);
        assert_eq!(opened.ts_ms, 1_700_000_000_000);
        assert_eq!(opened.plaintext, b"payload");
    }

    #[test]
    fn frame_header_is_authenticated() {
        let frame = seal_frame(&KEY, &SID, 7, 1_700_000_000_000, b"ctx", b"payload").unwrap();
        let mut tampered = frame.clone();
        // 改序号：如果帧头没进 AAD，这里就能骗过重放检测。
        tampered[1..9].copy_from_slice(&99u64.to_be_bytes());
        assert_eq!(
            open_frame(&KEY, &SID, b"ctx", &tampered).unwrap_err(),
            CryptoError::FrameAuthFailed
        );
    }

    #[test]
    fn frame_is_bound_to_aad_context() {
        let frame = seal_frame(&KEY, &SID, 1, 1, b"GET /api/v1/favorites", b"x").unwrap();
        assert_eq!(
            open_frame(&KEY, &SID, b"GET /api/v1/playlists", &frame).unwrap_err(),
            CryptoError::FrameAuthFailed
        );
    }

    #[test]
    fn short_frame_is_rejected() {
        assert!(matches!(
            open_frame(&KEY, &SID, b"ctx", &[0u8; 10]).unwrap_err(),
            CryptoError::Truncated { .. }
        ));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut frame = seal_frame(&KEY, &SID, 1, 1, b"ctx", b"x").unwrap();
        frame[FRAME_VERSION_OFFSET] = 99;
        assert!(matches!(
            open_frame(&KEY, &SID, b"ctx", &frame).unwrap_err(),
            CryptoError::UnsupportedVersion { got: 99, .. }
        ));
    }

    #[test]
    fn nonce_differs_between_frames() {
        let a = seal_frame(&KEY, &SID, 1, 1, b"ctx", b"same").unwrap();
        let b = seal_frame(&KEY, &SID, 2, 1, b"ctx", b"same").unwrap();
        assert_ne!(
            &a[17..29],
            &b[17..29],
            "nonce 必须每帧随机，重复 nonce 会直接击穿 ChaCha20-Poly1305"
        );
        assert_ne!(a, b);
    }

    // ---- 防重放滑窗 ----

    #[test]
    fn window_accepts_increasing_sequence() {
        let mut w = ReplayWindow::new();
        for seq in 1..=100 {
            w.check_and_update(seq).unwrap();
        }
    }

    #[test]
    fn window_rejects_exact_replay() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        w.check_and_update(2).unwrap();
        assert_eq!(
            w.check_and_update(1).unwrap_err(),
            CryptoError::ReplayDetected { seq: 1 }
        );
    }

    #[test]
    fn window_tolerates_reordering() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        w.check_and_update(3).unwrap();
        // 2 迟到，仍然要接受 —— 否则并发请求会随机失败。
        w.check_and_update(2).unwrap();
        // 但 2 再来一次就是重放。
        assert!(w.check_and_update(2).is_err());
    }

    #[test]
    fn window_rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        w.check_and_update(1000).unwrap();
        // 1 已经滑出 64 帧窗口，即使没记过也必须拒绝。
        assert_eq!(
            w.check_and_update(1).unwrap_err(),
            CryptoError::ReplayDetected { seq: 1 }
        );
    }

    #[test]
    fn window_handles_large_jump() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        w.check_and_update(u64::MAX / 2).unwrap();
        assert!(w.check_and_update(u64::MAX / 2).is_err());
    }

    #[test]
    fn window_first_frame_is_always_accepted() {
        let mut w = ReplayWindow::new();
        // 服务端不假设客户端从 1 开始，首个帧无条件接受。
        w.check_and_update(12345).unwrap();
        assert!(w.check_and_update(12345).is_err());
    }

    #[test]
    fn window_boundary_at_64() {
        let mut w = ReplayWindow::new();
        w.check_and_update(1).unwrap();
        w.check_and_update(65).unwrap();
        // diff = 64，正好滑出窗口边界，必须拒绝。
        assert!(w.check_and_update(1).is_err());
        // diff = 63，还在窗口内且没见过，必须接受。
        w.check_and_update(2).unwrap();
    }
}
