//! AEAD 封装：ChaCha20-Poly1305。
//!
//! 为什么不用 AES-256-GCM：
//! - **Web 端**。wasm 里没有 AES 硬件指令，纯软件 AES 比 ChaCha20 慢一大截，
//!   而 ChaCha20 是纯 ARX 运算，在 wasm 上几乎不损失性能。
//! - **Android 碎片化**。AES-GCM 的常数时间实现依赖 AES-NI / ARMv8 Crypto
//!   扩展，老机型上会退化到查表实现，存在缓存计时侧信道。
//! - **实现风险**。ChaCha20-Poly1305 没有 AES 那样的 S 盒查表，天然抗时序攻击。
//!
//! 代价是同等安全强度下密钥和标签更长，但对 HTTP 报文体这个量级完全无所谓。

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

use crate::error::{CryptoError, Result};
use crate::kdf::KEY_LEN;

/// AEAD nonce 长度。96 位是 RFC 8439 的规定值，不能改。
pub const NONCE_LEN: usize = 12;
/// Poly1305 认证标签长度。
pub const TAG_LEN: usize = 16;
/// 加密后的最小长度：只有标签、没有明文。
pub const MIN_CIPHERTEXT_LEN: usize = TAG_LEN;

/// 用给定的会话密钥加密一段明文，返回 `密文 ‖ 标签`。
///
/// 这是「图省事」的版本：自己分配输出。热路径上应该用 [`seal_in_place`]，
/// 把明文直接写进调用方已分配好的缓冲区，省掉一次全量拷贝。
///
/// `aad` 是不加密但参与认证的附加数据 —— 它才是这套协议的关键：把请求方法、
/// 路径、会话 ID 放进 AAD，攻击者即使截获了整个密文帧，也没法把它原样发到
/// 另一个端点上去（AAD 不匹配，解密直接失败）。
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = seal_in_place(key, nonce, aad, &mut out)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// 原地加密：`buffer` 进来是明文、出去是密文，返回认证标签。
///
/// 调用方负责把返回的标签接到密文后面（本协议的帧布局是 `密文 ‖ 标签`）。
/// 拆成「原地 + 分离标签」而不是直接返回 `Vec`，是为了让 `seal_frame` 能把
/// 明文一次性写进整帧缓冲区的最终位置，省掉一次「加密出一份密文再拷过去」。
pub fn seal_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_LEN]> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer)
        .map_err(|_| CryptoError::FrameAuthFailed)?;
    Ok(tag.into())
}

/// 解密并校验认证标签，返回明文。
///
/// 失败一律返回 [`CryptoError::FrameAuthFailed`]，不区分「密钥不对」「AAD 被改」
/// 「密文被篡改」—— 区分开等于告诉攻击者他改对了哪一部分。
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (body, tag) = split_tag(ciphertext)?;
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(body);
    open_in_place(key, nonce, aad, &mut out, tag)?;
    Ok(out)
}

/// 原地解密：`buffer` 进来是密文、出去是明文。
///
/// ⚠️ **失败时 `buffer` 保持原样，里面仍然是密文。** 这不是巧合而是必须依赖的
/// 性质：底层的 `decrypt_in_place_detached` 是**先验签、后解密** —— Poly1305
/// 校验不通过就直接返回错误，根本不会执行 `apply_keystream`。所以这里既不需要
/// 「失败后擦除缓冲区」那种操作，也不可能把未认证的明文交出去。
///
/// 反过来，如果哪天换成一个「先解密再验签」的实现，调用方就必须在错误分支里
/// 擦掉缓冲区 —— 那正是历史上无数 AEAD 误用的来源。这条依赖关系写在这里，
/// 是为了换实现时能被看见。
pub fn open_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .map_err(|_| CryptoError::FrameAuthFailed)
}

/// 把 `密文 ‖ 标签` 拆成两半。
fn split_tag(ciphertext: &[u8]) -> Result<(&[u8], &[u8; TAG_LEN])> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(CryptoError::Truncated {
            need: MIN_CIPHERTEXT_LEN,
            got: ciphertext.len(),
        });
    }
    let (body, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let tag = tag.try_into().map_err(|_| CryptoError::Truncated {
        need: MIN_CIPHERTEXT_LEN,
        got: ciphertext.len(),
    })?;
    Ok((body, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"aad", b"hello taotao").unwrap();
        assert_ne!(&ct[..9], b"hello tao", "密文不能等于明文");
        assert_eq!(ct.len(), 12 + TAG_LEN);
        let pt = open(&key, &nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello taotao");
    }

    #[test]
    fn aad_mismatch_is_rejected() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"POST /api/v1/favorites", b"body").unwrap();
        // 把密文搬到另一个端点重放 —— 必须失败，这正是 AAD 的作用。
        let err = open(&key, &nonce, b"POST /api/v1/draw", &ct).unwrap_err();
        assert_eq!(err, CryptoError::FrameAuthFailed);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let mut ct = seal(&key, &nonce, b"aad", b"body").unwrap();
        ct[0] ^= 0x01;
        assert_eq!(
            open(&key, &nonce, b"aad", &ct).unwrap_err(),
            CryptoError::FrameAuthFailed
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&[1u8; KEY_LEN], &nonce, b"aad", b"body").unwrap();
        assert_eq!(
            open(&[2u8; KEY_LEN], &nonce, b"aad", &ct).unwrap_err(),
            CryptoError::FrameAuthFailed
        );
    }

    #[test]
    fn truncated_ciphertext_is_rejected_before_decrypt() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let err = open(&key, &nonce, b"aad", &[0u8; 8]).unwrap_err();
        assert!(matches!(err, CryptoError::Truncated { .. }));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(open(&key, &nonce, b"", &ct).unwrap(), b"");
    }

    // ---- 原地 API ----
    //
    // 这两条是热路径真正走的分支，必须与「分配版」逐字节一致 —— 否则会出现
    // 「测试全绿但线上解不开」这种最难查的漂移。

    #[test]
    fn in_place_matches_allocating_version() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let aad = b"POST /api/v1/favorites";
        let plaintext = b"hello taotao";

        let allocating = seal(&key, &nonce, aad, plaintext).unwrap();

        let mut buf = plaintext.to_vec();
        let tag = seal_in_place(&key, &nonce, aad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);

        assert_eq!(allocating, buf, "两种封装必须产出完全相同的字节");
        assert_eq!(open(&key, &nonce, aad, &buf).unwrap(), plaintext);

        // 反方向：分配版产出的密文，原地版也必须解得开。
        let (body, tag) = split_tag(&allocating).unwrap();
        let mut in_place = body.to_vec();
        open_in_place(&key, &nonce, aad, &mut in_place, tag).unwrap();
        assert_eq!(in_place, plaintext);
    }

    #[test]
    fn open_in_place_leaves_buffer_untouched_on_failure() {
        let key = [9u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let ct = seal(&key, &nonce, b"ctx", b"secret payload").unwrap();
        let (body, tag) = split_tag(&ct).unwrap();

        // 用错误的 AAD 验签。这条锁住的是「先验签、后解密」这个性质：
        // 一旦换成「先解密再验签」的实现，缓冲区里会留下未认证的明文。
        let mut buf = body.to_vec();
        let err = open_in_place(&key, &nonce, b"other", &mut buf, tag).unwrap_err();
        assert_eq!(err, CryptoError::FrameAuthFailed);
        assert_eq!(
            buf.as_slice(),
            body,
            "验签失败时缓冲区必须保持原样，不能出现未认证的明文"
        );
    }

    #[test]
    fn split_tag_rejects_short_input() {
        assert!(split_tag(&[0u8; TAG_LEN - 1]).is_err());
        assert!(split_tag(&[]).is_err());
        assert!(split_tag(&[0u8; TAG_LEN]).is_ok());
    }
}
