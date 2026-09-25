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

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{CryptoError, Result};
use crate::kdf::KEY_LEN;

/// AEAD nonce 长度。96 位是 RFC 8439 的规定值，不能改。
pub const NONCE_LEN: usize = 12;
/// Poly1305 认证标签长度。
pub const TAG_LEN: usize = 16;
/// 加密后的最小长度：只有标签、没有明文。
pub const MIN_CIPHERTEXT_LEN: usize = TAG_LEN;

/// 用给定的会话密钥加密一段明文。
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::FrameAuthFailed)
}

/// 解密并校验认证标签。
///
/// 失败一律返回 [`CryptoError::FrameAuthFailed`]，不区分「密钥不对」「AAD 被改」
/// 「密文被篡改」—— 区分开等于告诉攻击者他改对了哪一部分。
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(CryptoError::Truncated {
            need: MIN_CIPHERTEXT_LEN,
            got: ciphertext.len(),
        });
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::FrameAuthFailed)
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
}
