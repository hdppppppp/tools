//! PSK 分片 blob 的编解码。
//!
//! ## 为什么单独抽一个模块
//!
//! 编码发生在 `build.rs`（构建脚本），解码发生在 `psk.rs`（运行时）。
//! 构建脚本是一个**独立编译的 crate**，没法直接 `use` 本 crate 的函数，
//! 所以最初的写法是两边各写一份逻辑、靠注释约定格式。
//!
//! 结果就是这份代码第一次跑测试时暴露的问题：`build.rs` 的注释写着
//! 「逆序存放」，代码却是顺序存放，而解码器按逆序读 —— **生产密钥会还原错**，
//! 表现是「所有客户端握不上手」，而且构建、启动、日志全都正常，没有任何线索。
//!
//! 修法不是把两边改一致就完事，而是让它们**共用同一份源码**：
//! `build.rs` 用 `include!("src/psk_blob.rs")` 把本文件编进构建脚本，
//! 运行时则通过 `crate::psk_blob` 使用。同一份代码，不可能再漂移。
//!
//! ## blob 格式
//!
//! ```text
//! [0]        shard_count u8     分片数量（必须整除 32）
//! [1..1+n]   masks[n]           每片的异或掩码
//! [1+n..]    分片数据           每片 32/n 字节，按 shard → (n-1-shard) 逆序存放
//! ```
//!
//! 注意本文件里的函数**不使用 crate 内的任何其它模块**，也不依赖 `thiserror`
//! 或任何非 `hex` 的 crate —— 否则 `include!` 到构建脚本里会因为缺少依赖而
//! 编译失败。错误类型统一用 `String`，同样是为了这个约束。
//!
//! ## 这里的错误文案为什么不混淆
//!
//! `error.rs` / `kdf.rs` / `psk.rs` 的文案都经 `crate::obf::obf!` 混淆过，
//! 本文件**没有**，而且不能照做：本文件被 `build.rs` 用 `#[path]` 编进构建
//! 脚本，而构建脚本里根本不存在 `crate::obf` 这个模块，`obf!` 会直接编译
//! 不过。上面那条「不使用 crate 内任何其它模块」的约束就是这个意思 ——
//! 它是为了保证「编解码只有一份实现」这个更重要的性质（见文件开头），
//! 不能用混淆去换。
//!
//! 另外，即便把文案混淆了收益也接近零：本文件里的 `SHARD_COUNT` 与 `MASKS`
//! 是**编译期常量**，它们本身就把分片方案完整地写在二进制里，藏住错误文案
//! 并不改变攻击者已知的信息量。真要抬高这一处的成本，得改分片方案本身
//! （例如让掩码由构建期密钥派生），那是另一个话题。

/// PSK 长度（字节）。
pub const PSK_LEN: usize = 32;

/// 分片数量。必须能整除 [`PSK_LEN`]。
pub const SHARD_COUNT: usize = 4;

/// 每片的异或掩码。
///
/// 用**编译期固定值**而不是随机值：随机会让每次构建产物不同，破坏可复现构建，
/// 而发布清单是按 sha256 寻址的（见 RELEASE.md 第九节）—— 同版本号的两个包
/// 内容不一致会让「按哈希判断是否需要更新」的判断彻底失效。
pub const MASKS: [u8; SHARD_COUNT] = [0x9E, 0x3B, 0xC7, 0x51];

/// 把 64 个十六进制字符的 PSK 编码成分片混淆后的 blob。
///
/// 输入非法时返回 `Err`。调用方（`build.rs`）应当直接 panic ——
/// 静默产出一个「看起来正常但密钥是错的」产物，会在发布后表现为
/// 全量客户端握不上手，且排查时完全看不出线索。
pub fn encode_psk(raw_hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = raw_hex.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|_| format!("不是合法的十六进制字符串（期望 {PSK_LEN} 字节 = 64 个 hex 字符）"))?;
    if bytes.len() != PSK_LEN {
        return Err(format!(
            "长度必须是 {PSK_LEN} 字节，实际 {} 字节",
            bytes.len()
        ));
    }
    Ok(encode_psk_bytes(&bytes))
}

/// 从已校验的字节编码。与 [`unmask_blob`] 严格互逆。
pub fn encode_psk_bytes(bytes: &[u8]) -> Vec<u8> {
    debug_assert_eq!(bytes.len(), PSK_LEN);
    let shard_len = PSK_LEN / SHARD_COUNT;

    let mut blob = Vec::with_capacity(1 + SHARD_COUNT + PSK_LEN);
    blob.push(SHARD_COUNT as u8);
    blob.extend_from_slice(&MASKS);

    // 分片 i 写到数据区的 (SHARD_COUNT - 1 - i) 位置，即逆序。
    // 这一行与 `unmask_blob` 里的 `stored` 计算必须保持互逆。
    let mut data = [0u8; PSK_LEN];
    for shard in 0..SHARD_COUNT {
        let stored = SHARD_COUNT - 1 - shard;
        for offset in 0..shard_len {
            let plain = bytes[shard * shard_len + offset];
            data[stored * shard_len + offset] = plain ^ MASKS[shard];
        }
    }
    blob.extend_from_slice(&data);
    blob
}

/// 从 blob 还原 32 字节密钥。
///
/// 非法 blob 返回 `Err`。运行时的调用方（`psk.rs`）把错误映射成
/// `CryptoError::PskNotConfigured` —— 这类错误只可能来自构建期配置错误，
/// 不该被当成网络异常重试。
pub fn unmask_blob(blob: &[u8]) -> Result<[u8; PSK_LEN], String> {
    if blob.is_empty() {
        return Err("构建期未注入 PSK".to_string());
    }
    let shard_count = blob[0] as usize;
    if shard_count == 0 || PSK_LEN % shard_count != 0 {
        return Err(format!("分片数量 {shard_count} 非法：必须能整除 {PSK_LEN}"));
    }
    let shard_len = PSK_LEN / shard_count;
    let masks_end = 1 + shard_count;
    let expected = masks_end + PSK_LEN;
    if blob.len() < expected {
        return Err(format!(
            "blob 长度不足：需要 {expected} 字节，实际 {} 字节",
            blob.len()
        ));
    }

    let masks = &blob[1..masks_end];
    let data = &blob[masks_end..expected];

    let mut out = [0u8; PSK_LEN];
    for shard in 0..shard_count {
        let stored = shard_count - 1 - shard;
        let src = &data[stored * shard_len..(stored + 1) * shard_len];
        let mask = masks[shard];
        for (offset, byte) in src.iter().enumerate() {
            out[shard * shard_len + offset] = byte ^ mask;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已知答案向量。
    ///
    /// 这组数字是**刻意写死**的：编解码逻辑一旦被改动（哪怕只是把逆序改成顺序），
    /// 这里立刻失败。上面那个「注释与代码不一致」的 bug 就是因为缺少这样一条
    /// 断言才溜到测试阶段。
    #[test]
    fn known_answer_vector() {
        let psk: Vec<u8> = (0..PSK_LEN as u8).collect();
        let blob = encode_psk_bytes(&psk);

        // 头部：分片数 + 4 个掩码。
        assert_eq!(blob[0], 4);
        assert_eq!(&blob[1..5], &MASKS);

        // 分片 0 存在数据区的最后一段（逆序）。
        // 掩码 0x9E ^ 0x00 = 0x9E，位置是 4 + 3*8 = 28。
        //
        // `0x00 ^` 是刻意保留的，不是冗余写法：它让这一条与下面那条
        // （`24 ^ MASKS[3]`）在形式上对称 —— 两条都是「分片首字节 ^ 该片掩码」，
        // 不对称只是因为第 0 片的首字节恰好是 0。clippy 说 `0x00 ^ x`
        // 等价于 `x` 是对的，但在这里保留这个模式更有信息量。
        //
        // allow 挂在块上而不是语句上：Rust 不允许把语句属性加在宏调用
        // （`assert_eq!`）上，会报 `unused attribute`。
        #[allow(clippy::identity_op)]
        {
            assert_eq!(blob[5 + 3 * 8], 0x00 ^ MASKS[0]);
        }
        // 分片 3 存在数据区的第一段。
        // 掩码 0x51 ^ 0x18 = 0x49，位置是 5。
        assert_eq!(blob[5], 24 ^ MASKS[3]);

        assert_eq!(unmask_blob(&blob).unwrap(), psk.as_slice());
    }

    #[test]
    fn roundtrip_preserves_all_bytes() {
        // 用非重复的字节序列，避免「所有字节相同」掩盖分段错位。
        let mut psk = [0u8; PSK_LEN];
        for (i, byte) in psk.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let blob = encode_psk_bytes(&psk);
        assert_eq!(blob.len(), 1 + SHARD_COUNT + PSK_LEN);
        assert_eq!(unmask_blob(&blob).unwrap(), psk);
    }

    #[test]
    fn roundtrip_via_hex_entry_point() {
        let hex_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let blob = encode_psk(hex_key).unwrap();
        let restored = unmask_blob(&blob).unwrap();
        assert_eq!(hex::encode(restored), hex_key);
    }

    #[test]
    fn masked_data_does_not_contain_plaintext() {
        // 全部字节相同的密钥最容易暴露「掩码没生效」—— 明文会以重复模式出现。
        let psk = [0x5Au8; PSK_LEN];
        let blob = encode_psk_bytes(&psk);
        assert!(
            !blob.windows(PSK_LEN).any(|w| w == psk),
            "blob 里不应出现明文密钥"
        );
    }

    #[test]
    fn encode_rejects_bad_input() {
        assert!(encode_psk("").is_err());
        assert!(encode_psk("0011").is_err(), "长度不足必须拒绝");
        assert!(encode_psk(&"zz".repeat(32)).is_err(), "非法 hex 必须拒绝");
        assert!(encode_psk(&"aa".repeat(33)).is_err(), "长度超出必须拒绝");
    }

    #[test]
    fn unmask_rejects_malformed_blob() {
        assert!(unmask_blob(&[]).is_err());
        assert!(unmask_blob(&[3, 0, 0, 0]).is_err(), "3 不能整除 32");
        assert!(unmask_blob(&[0]).is_err(), "分片数为 0");
        assert!(unmask_blob(&[4, 1, 2, 3, 4, 5, 6]).is_err(), "数据不足");
    }

    #[test]
    fn encode_decode_are_inverse_for_all_byte_values() {
        // 穷举一遍单字节值，确认掩码不引入可逆性问题。
        for seed in 0u8..=255 {
            let psk = [seed; PSK_LEN];
            let blob = encode_psk_bytes(&psk);
            assert_eq!(unmask_blob(&blob).unwrap(), psk, "seed={seed} 往返失败");
        }
    }
}
