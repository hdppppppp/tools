//! 构建脚本：把 PSK 从环境变量编译进产物。
//!
//! ## 为什么在构建期而不是运行时读环境变量
//!
//! 客户端（Android / Windows / Web）根本没有「环境变量」可用 —— 密钥必须在
//! 编译时写进二进制。为了四个目标共用同一套代码路径，服务端也走同样的构建期
//! 注入（服务端用 `TAOTAO_CRYPTO_PSK` 环境变量构建镜像即可）。
//!
//! ## 分片混淆的实现位置
//!
//! 编码/解码逻辑在 `src/psk_blob.rs`，这里用 `#[path] mod` 把它编进构建脚本。
//! **不要**在本文件里另写一份编码逻辑 —— 最初就是这么写的，结果注释写着
//! 「逆序存放」而代码是顺序存放，解码器按逆序读，生产密钥会还原错，
//! 表现是「所有客户端握不上手」且构建、启动、日志全部正常。
//! 共用同一份源码是唯一能杜绝这种漂移的办法。

use std::env;
use std::fs;
use std::path::PathBuf;

/// 把 `src/psk_blob.rs` 编进构建脚本。
///
/// 用 `#[path]` 而不是 `include!`：那个文件开头是 `//!` 内部文档注释，
/// 而 `include!` 是宏展开，内部属性出现在宏展开体里会报
/// 「expected outer doc comment」（E0753）。`#[path]` 是模块加载，
/// 内部文档注释在模块里是合法的。
///
/// `allow(dead_code)` 是必需的：这个文件同时被运行时和构建脚本使用，
/// 但构建脚本只调 `encode_psk`，用不到 `unmask_blob` ——
/// 不加这行会报「function `unmask_blob` is never used」。
/// 注意这个 allow 只作用于构建脚本侧，运行时那边仍然会检查未使用代码。
#[path = "src/psk_blob.rs"]
#[allow(dead_code)]
mod psk_blob;

fn main() {
    // 环境变量变化时重新构建，否则改了密钥却拿到旧产物 ——
    // 表现为「服务端换了密钥，客户端死活握不上手」。
    println!("cargo:rerun-if-env-changed=TAOTAO_CRYPTO_PSK");
    // 编解码逻辑变了也必须重新生成 blob。
    println!("cargo:rerun-if-changed=src/psk_blob.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo 一定会设置 OUT_DIR"));
    let blob_path = out_dir.join("psk_blob.rs");

    let blob = match env::var("TAOTAO_CRYPTO_PSK") {
        Ok(raw) if !raw.trim().is_empty() => psk_blob::encode_psk(&raw)
            // 构建期直接 panic：静默产出一个「看起来正常但密钥是错的」产物，
            // 会在发布后表现为全量客户端握不上手，排查时看不出任何线索。
            .unwrap_or_else(|err| panic!("TAOTAO_CRYPTO_PSK 非法：{err}")),
        _ => {
            // 不注入真实密钥时生成空 blob。运行时的
            // `build_psk_or_placeholder` 会据此退回占位密钥并如实报告
            // 「这不是真实密钥」，让调用方能拒绝启动。
            println!(
                "cargo:warning=未设置 TAOTAO_CRYPTO_PSK，本次构建不含真实密钥（仅可用于开发与测试）"
            );
            Vec::new()
        }
    };

    let source = format!(
        "/// 由 build.rs 生成，请勿手工修改。\n\
         pub const BLOB: &[u8] = &[{}];\n",
        blob.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    fs::write(&blob_path, source).expect("写入 psk_blob.rs 失败");
}
