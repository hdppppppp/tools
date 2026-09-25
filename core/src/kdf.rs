//! 密钥派生与随机数源。
//!
//! 所有密钥都从 PSK 或 X25519 共享秘密经 HKDF-SHA256 派生，不存在「直接
//! 把 PSK 当加密密钥用」的路径 —— 同一条 PSK 要同时喂握手认证和数据加密，
//! 不隔离的话握手 MAC 就成了数据密钥的已知明文对。

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::obf::obf;

/// PSK 固定 32 字节（256 位）。短于 32 字节的密钥在现代硬件上可以爆破。
pub const PSK_LEN: usize = 32;
/// 会话密钥长度，同时作为 ChaCha20-Poly1305 的密钥长度。
pub const KEY_LEN: usize = 32;
/// 握手与帧共用的随机数长度（握手 nonce 16B、AEAD nonce 12B 各自另定）。
pub const RANDOM_BLOCK_LEN: usize = 16;

/// 握手专用密钥的 HKDF info 标签。
///
/// 返回 `Vec<u8>` 而不是 `const &[u8]`：标签要经 [`crate::obf::obf!`] 混淆，
/// 而混淆是在**运行期**才把明文解出来的，`const` 里放不下。
///
/// 代价是每次调用多一次分配。这些函数只在握手路径上被调用（每个会话一次，
/// 而会话 TTL 是 30 分钟），不在逐帧热路径上 —— 帧加密走的是派生好的
/// [`SessionKeys`]，不会经过这里。
fn info_handshake() -> Vec<u8> {
    obf!("taotao-crypto-v1/handshake").into_bytes()
}

/// 客户端→服务端数据密钥的 HKDF info 标签。理由见 [`info_handshake`]。
fn info_key_c2s() -> Vec<u8> {
    obf!("taotao-crypto-v1/key/c2s").into_bytes()
}

/// 服务端→客户端数据密钥的 HKDF info 标签。理由见 [`info_handshake`]。
///
/// 双向必须用**不同**的 info 派生：如果两个方向共用一个密钥，服务端加密的
/// 响应就能被原样当作客户端请求发回来（反射攻击），而 MAC 是合法的。
fn info_key_s2c() -> Vec<u8> {
    obf!("taotao-crypto-v1/key/s2c").into_bytes()
}

/// 随机数来源抽象。
///
/// 单独抽出来不是为了「可插拔」，而是为了**测试能注入确定性随机**：
/// 握手和帧加密的向量测试必须可复现，直接调操作系统随机源就没法写断言了。
pub trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}

/// 操作系统随机源。Android 走 `getrandom` 的 `getrandom(2)`，
/// Windows 走 `BCryptGenRandom`，wasm32-unknown-unknown 走 `crypto.getRandomValues`。
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        getrandom::getrandom(out).map_err(|err| CryptoError::RandomFailure(err.to_string()))
    }
}

/// 用操作系统随机源生成一个定长数组。
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    OsRandom.fill(&mut out)?;
    Ok(out)
}

/// HKDF-Extract：把任意长度的输入密钥材料压成 32 字节伪随机密钥（PRK）。
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; KEY_LEN] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand：从 PRK 派生出 32 字节的子密钥。
pub fn hkdf_expand(prk: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hkdf =
        Hkdf::<Sha256>::from_prk(prk).expect(&obf!("32 字节 PRK 一定满足 HKDF 的最小长度要求"));
    let mut out = [0u8; KEY_LEN];
    hkdf.expand(info, &mut out)
        .expect(&obf!("请求 32 字节输出远小于 HKDF-SHA256 的 255×32 上限"));
    out
}

/// 从 PSK 派生握手专用密钥。
///
/// 握手消息里的 MAC 用这条密钥，和数据密钥完全隔离。
pub fn derive_handshake_key(psk: &[u8; PSK_LEN], psk_id: &[u8]) -> [u8; KEY_LEN] {
    let prk = hkdf_extract(psk_id, psk);
    hkdf_expand(&prk, &info_handshake())
}

/// 从 X25519 共享秘密派生双向会话密钥。
///
/// `salt` 用客户端 nonce：它双方都知道、每次握手都不同，能保证「同一条 PSK
/// 下的两次握手得到不同密钥」。`session_id` 进 info，把密钥绑死到这一次会话，
/// 防止会话 ID 被换掉后密钥仍然可用。
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    salt: &[u8],
    session_id: &[u8],
) -> (SessionKeys, SessionKeys) {
    let prk = hkdf_extract(salt, shared_secret);

    let label_c2s = info_key_c2s();
    let mut info_c2s = Vec::with_capacity(label_c2s.len() + session_id.len());
    info_c2s.extend_from_slice(&label_c2s);
    info_c2s.extend_from_slice(session_id);

    let label_s2c = info_key_s2c();
    let mut info_s2c = Vec::with_capacity(label_s2c.len() + session_id.len());
    info_s2c.extend_from_slice(&label_s2c);
    info_s2c.extend_from_slice(session_id);

    let c2s = SessionKeys {
        seal_key: hkdf_expand(&prk, &info_c2s),
        open_key: hkdf_expand(&prk, &info_s2c),
    };
    let s2c = SessionKeys {
        seal_key: hkdf_expand(&prk, &info_s2c),
        open_key: hkdf_expand(&prk, &info_c2s),
    };
    (c2s, s2c)
}

/// 一个方向上的会话密钥对。
///
/// `seal_key` 用来加密本端发出的帧，`open_key` 用来解密对端发来的帧。
/// 客户端拿到的 `c2s` 与 `s2c` 恰好互为镜像，所以两侧代码不用分支判断方向。
#[derive(Clone)]
pub struct SessionKeys {
    pub seal_key: [u8; KEY_LEN],
    pub open_key: [u8; KEY_LEN],
}

impl SessionKeys {
    /// 生成一对同密钥的会话密钥，仅用于测试。
    #[cfg(test)]
    pub fn pair_for_test(key: [u8; KEY_LEN]) -> Self {
        Self {
            seal_key: key,
            open_key: key,
        }
    }
}

impl core::fmt::Debug for SessionKeys {
    /// 手写 Debug：密钥绝不能出现在日志、panic 消息或崩溃上报里。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(<已隐藏>)")
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.seal_key.zeroize();
        self.open_key.zeroize();
    }
}

/// 计算 HMAC-SHA256。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect(&obf!("HMAC-SHA256 接受任意长度的密钥，不会失败"));
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

/// 常数时间比较。
///
/// 手写循环会被编译器优化成提前返回，从而泄露「前几个字节对上了」——
/// 攻击者据此可以逐字节爆破 MAC。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_is_deterministic_and_info_separated() {
        let prk = hkdf_extract(b"salt", b"ikm");
        let a = hkdf_expand(&prk, b"info-a");
        let b = hkdf_expand(&prk, b"info-a");
        let c = hkdf_expand(&prk, b"info-b");
        assert_eq!(a, b, "同 info 必须可复现");
        assert_ne!(a, c, "不同 info 必须派生不同密钥");
    }

    #[test]
    fn session_keys_are_mirrored() {
        let shared = [7u8; 32];
        let (client, server) = derive_session_keys(&shared, b"nonce", b"sid");
        assert_eq!(client.seal_key, server.open_key);
        assert_eq!(client.open_key, server.seal_key);
        assert_ne!(
            client.seal_key, client.open_key,
            "双向密钥必须不同，否则会退化成反射攻击"
        );
    }

    #[test]
    fn different_salt_yields_different_keys() {
        let shared = [7u8; 32];
        let (a, _) = derive_session_keys(&shared, b"nonce-1", b"sid");
        let (b, _) = derive_session_keys(&shared, b"nonce-2", b"sid");
        assert_ne!(a.seal_key, b.seal_key, "salt 变化必须导致密钥变化");
    }

    #[test]
    fn constant_time_eq_handles_length_mismatch() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn debug_never_leaks_key_bytes() {
        let keys = SessionKeys::pair_for_test([0xAB; 32]);
        let text = format!("{keys:?}");
        assert!(!text.contains("ab"), "Debug 输出不能包含密钥字节：{text}");
    }
}
