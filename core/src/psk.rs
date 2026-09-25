//! 预共享密钥（PSK）的装载、轮换与运行时拼装。
//!
//! ## 关于「把密钥藏在 native 里」
//!
//! 必须说清楚：**任何随客户端分发的密钥，理论上都能被提取**。有物理设备的人
//! 总能跑 Frida、抓内存、dump 代码段。本模块的目标不是「不可提取」，而是
//! **把提取成本从「grep 一下 hex 字符串」抬高到「需要写脚本逆向拼装逻辑」**。
//!
//! 具体手段：
//! 1. **不落明文常量**。构建期由 `build.rs` 把 PSK 拆成若干分片，每片带
//!    独立掩码、乱序存放，运行时才拼回完整密钥（见 [`Psk::from_build_blob`]）。
//! 2. **零化**。密钥用完即擦，降低内存 dump 的命中率（`zeroize`）。
//! 3. **派生隔离**。PSK 本身从不直接参与加密，只用于派生握手密钥。
//!
//! 反过来，**服务端侧必须把 PSK 当普通配置**（环境变量 / 密钥管理服务），
//! 因为服务端没有「提取」问题，过度混淆只会让轮换变难。

use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::kdf::PSK_LEN;
use crate::obf::{obf, obf_string};
use crate::protocol::MAX_PSK_ID_LEN;

/// 一条带标识的预共享密钥。
///
/// `id` 用于密钥轮换：服务端可以同时持有多条（当前 + 上一个），客户端在
/// 握手里带上自己用的 `id`，服务端按 id 查表。这样轮换期间新旧客户端
/// 都能握手成功，不需要「先停服再换密钥」。
#[derive(Clone)]
pub struct Psk {
    id: String,
    key: [u8; PSK_LEN],
}

impl Psk {
    /// 从 32 字节原始密钥构造。
    pub fn new(id: impl Into<String>, key: [u8; PSK_LEN]) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(CryptoError::PskNotConfigured(obf!("psk_id 不能为空")));
        }
        if id.len() > MAX_PSK_ID_LEN {
            return Err(CryptoError::PskNotConfigured(obf_string!(
                "psk_id 长度 {} 超过上限 {}",
                id.len(),
                MAX_PSK_ID_LEN
            )));
        }
        if !id.is_ascii() {
            // 非 ASCII 的 id 在不同语言侧的编码处理不一致，会在握手 MAC 上
            // 表现出「只有某些环境失败」这种极难查的问题。
            return Err(CryptoError::PskNotConfigured(obf!("psk_id 必须是 ASCII")));
        }
        Ok(Self { id, key })
    }

    /// 从十六进制字符串构造（64 个 hex 字符）。
    pub fn from_hex(id: impl Into<String>, hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|_| CryptoError::PskNotConfigured(obf!("PSK 不是合法的十六进制")))?;
        let key: [u8; PSK_LEN] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength {
                    expected: PSK_LEN,
                    got: bytes.len(),
                })?;
        Self::new(id, key)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// 取出原始密钥字节。调用方应尽快用完并擦除。
    pub fn key(&self) -> &[u8; PSK_LEN] {
        &self.key
    }

    /// 从构建期注入的混淆分片还原密钥。
    ///
    /// `blob` 的布局由 `build.rs` 决定：`[分片数 u8]` 后面跟「分片长度 + 掩码
    /// 字节 + 打乱顺序的分片数据」。运行时的还原逻辑与分片布局强耦合，
    /// 逆向者必须同时看懂 `build.rs` 和这里才能把密钥还原出来 —— 这就是
    /// 抬高成本的全部意义所在。
    ///
    /// 注意：这个函数**不**做「构建期是否配置了真实密钥」的判断，那是
    /// 调用方的责任（见 [`crate::psk::build_psk_or_placeholder`]）。
    pub fn from_build_blob(id: impl Into<String>, blob: &[u8]) -> Result<Self> {
        let key = crate::psk_blob::unmask_blob(blob).map_err(CryptoError::PskNotConfigured)?;
        Self::new(id, key)
    }
}

impl Drop for Psk {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl core::fmt::Debug for Psk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 只打印 id，绝不打印密钥。
        f.debug_struct("Psk")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// 从主种子派生某条 PSK。
///
/// 用途：一套主密钥管理多套环境（dev / staging / prod），只要换 `psk_id`
/// 就能得到互不相通的密钥。避免「测试环境的密钥泄漏导致生产可被解密」。
pub fn derive_psk_from_seed(seed: &[u8; PSK_LEN], psk_id: &str) -> Result<Psk> {
    let mut info = obf!("taotao-crypto-v1/psk/").into_bytes();
    info.extend_from_slice(psk_id.as_bytes());
    let prk = crate::kdf::hkdf_extract(&obf!("taotao-psk-seed").into_bytes(), seed);
    let key = crate::kdf::hkdf_expand(&prk, &info);
    Psk::new(psk_id, key)
}

/// 服务端侧的 PSK 表，支持轮换期同时持有多条。
///
/// 轮换流程（无需停服、无需同时升级两端）：
/// 1. 服务端先加上新 PSK（此时表里有新旧两条）。
/// 2. 客户端陆续切到新 PSK（按 id 握手，服务端都能认）。
/// 3. 确认没有客户端再用旧 id 后，服务端移除旧 PSK。
#[derive(Default, Clone)]
pub struct PskStore {
    entries: Vec<Psk>,
}

impl PskStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 插入一条 PSK。同 id 会覆盖（这正是轮换时更新密钥的路径）。
    pub fn insert(&mut self, psk: Psk) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.id() == psk.id()) {
            *slot = psk;
        } else {
            self.entries.push(psk);
        }
    }

    /// 按 id 查密钥。
    pub fn get(&self, id: &str) -> Option<&Psk> {
        self.entries.iter().find(|e| e.id() == id)
    }

    /// 移除一条 PSK，返回是否真的移除了。
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id() != id);
        before != self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl core::fmt::Debug for PskStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskStore")
            .field("ids", &self.entries.iter().map(Psk::id).collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_psk_id() {
        assert!(Psk::new("", [0u8; PSK_LEN]).is_err());
        assert!(Psk::new("x".repeat(MAX_PSK_ID_LEN + 1), [0u8; PSK_LEN]).is_err());
        assert!(
            Psk::new("生产密钥", [0u8; PSK_LEN]).is_err(),
            "非 ASCII id 必须拒绝"
        );
        assert!(Psk::new("prod-2026-09", [0u8; PSK_LEN]).is_ok());
    }

    #[test]
    fn hex_roundtrip_and_length_check() {
        let hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let psk = Psk::from_hex("prod", hex_key).unwrap();
        assert_eq!(hex::encode(psk.key()), hex_key);

        assert!(Psk::from_hex("prod", "0011").is_err(), "短密钥必须拒绝");
        assert!(
            Psk::from_hex("prod", "zz".repeat(32).as_str()).is_err(),
            "非法 hex 必须拒绝"
        );
    }

    #[test]
    fn seed_derivation_is_id_separated() {
        let seed = [7u8; PSK_LEN];
        let a = derive_psk_from_seed(&seed, "prod").unwrap();
        let b = derive_psk_from_seed(&seed, "staging").unwrap();
        assert_ne!(a.key(), b.key(), "不同 psk_id 必须派生不同密钥");
    }

    #[test]
    fn store_supports_rotation() {
        let mut store = PskStore::new();
        store.insert(Psk::new("v1", [1u8; PSK_LEN]).unwrap());
        assert_eq!(store.len(), 1);

        // 轮换：加新密钥，旧密钥仍在（灰度期两条并存）。
        store.insert(Psk::new("v2", [2u8; PSK_LEN]).unwrap());
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("v1").unwrap().key(), &[1u8; PSK_LEN]);
        assert_eq!(store.get("v2").unwrap().key(), &[2u8; PSK_LEN]);

        // 同 id 覆盖即更新密钥。
        store.insert(Psk::new("v2", [3u8; PSK_LEN]).unwrap());
        assert_eq!(store.len(), 2);
        assert_eq!(store.get("v2").unwrap().key(), &[3u8; PSK_LEN]);

        assert!(store.remove("v1"));
        assert!(!store.remove("v1"));
        assert_eq!(store.len(), 1);
        assert!(store.get("v1").is_none());
    }

    #[test]
    fn debug_never_leaks_psk() {
        let psk = Psk::new("prod", [0xAB; PSK_LEN]).unwrap();
        let text = format!("{psk:?}");
        assert!(text.contains("prod"));
        assert!(!text.contains("ab"), "Debug 不能泄露密钥：{text}");
    }
}
