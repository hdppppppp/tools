//! WebAssembly 绑定（wasm-bindgen），供 Web 分享播放器使用。
//!
//! ## 这个目标的特殊性
//!
//! Web 端是**公开**的：分享页 `s/{token}` 任何人都能打开，代码可以随便读。
//! 所以这里必须比其它三端更谨慎地对待「什么能进 wasm」：
//!
//! - **不要**把服务端的 PSK 编进 wasm。分享页只需要调公开接口，不需要握手。
//!   真要给分享页加密，应该用「匿名会话 + 短时效令牌」，而不是共享 PSK。
//! - wasm 的体积直接算进首屏下载量。`opt-level = "z"` + `lto = "fat"` 是必须的；
//!   `wasm-bindgen` 之后再用 `wasm-opt -Oz` 还能再压一截。
//!   （实测未压缩的原始 .wasm 约 455KB，主要来自 curve25519-dalek 与
//!   chacha20poly1305；后处理与 gzip 之后会小很多。任何具体数字都应以
//!   实际构建产物为准，不要照抄文档里的估算。）
//!
//! ## JS 侧的时间
//!
//! `now_ms` 由 JS 传 `Date.now()`。不要在 Rust 里调 `SystemTime::now()`：
//! `wasm32-unknown-unknown` 没有系统时钟，旧版本会直接 panic，
//! 新版本返回 0 —— 而返回 0 会让所有帧都因为「时间戳超窗」被拒，
//! 表现为「Web 端握手成功但每个请求都失败」。
//!
//! ## 命名约定
//!
//! 绑定层的方法名**刻意保持 Rust 的 snake_case**（wasm-bindgen 的默认行为），
//! 不加 `js_name` 转成 camelCase。理由：只给一部分方法加 `js_name` 会让 JS 侧
//! 出现「有的方法是 `seal`、有的是 `put_psk`」这种半吊子风格，而给全部方法加
//! 又要额外维护一份名字映射。
//!
//! 惯用的 camelCase API 由 `crypto/bindings/wasm/index.ts` 提供 ——
//! 那一层是手写的，可以自由决定对外形状，也和 Kotlin / TypeScript 两个包装层
//! 保持一致的调用体验。
//!
//! ## 构建
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown -p taotao-crypto-wasm
//! wasm-bindgen --target web --out-dir dist \
//!   target/wasm32-unknown-unknown/release/taotao_crypto_wasm.wasm
//! ```
//!
//! ⚠️ `wasm-bindgen` CLI 的版本必须与 `Cargo.lock` 里的 `wasm-bindgen` crate
//! 版本**严格一致**。不一致时它会报一句含糊的 schema 版本错误，
//! 而且**不产出任何文件** —— 表现为「构建成功但 dist 目录是空的」。

use taotao_crypto_core::{aad, ClientEngine, CryptoError, ServerEngine};
use wasm_bindgen::prelude::*;

/// 把 core 的错误转成 JS 异常。
///
/// 用 `JsError` 而不是返回 `null`：调用方如果忘了判空，`null` 会在很远的地方
/// 变成「Cannot read properties of null」，而异常能带上原始错误信息。
fn to_js(err: CryptoError) -> JsError {
    JsError::new(&err.to_string())
}

/// 客户端引擎。
#[wasm_bindgen]
pub struct Client {
    inner: ClientEngine,
}

#[wasm_bindgen]
impl Client {
    /// 创建客户端。`pskHex` 必须是 64 个十六进制字符。`deviceId` 折进握手密钥；
    /// Web 分享页无稳定设备号，传空串即不绑定（本层不接入设备绑定，仅保持协议一致）。
    #[wasm_bindgen(constructor)]
    pub fn new(psk_id: &str, psk_hex: &str, device_id: &str) -> Result<Client, JsError> {
        Ok(Client {
            inner: ClientEngine::new(psk_id, psk_hex, device_id).map_err(to_js)?,
        })
    }

    /// 发起握手，返回 `Uint8Array`。
    pub fn handshake(&mut self, now_ms: f64) -> Result<Vec<u8>, JsError> {
        // f64 → u64：JS 的 number 精度上限是 2^53，毫秒时间戳（约 1.7e12）
        // 远在安全范围内，但负数要挡掉，否则 `as u64` 会得到巨大的值，
        // 让时间戳窗口校验以「超窗」的形式失败。
        let now = if now_ms.is_finite() && now_ms >= 0.0 {
            now_ms as u64
        } else {
            return Err(JsError::new("nowMs 必须是有限的非负数"));
        };
        self.inner.handshake(now).map_err(to_js)
    }

    /// 处理 ServerHello，建立会话。
    pub fn finish(&mut self, server_hello: &[u8], now_ms: f64) -> Result<(), JsError> {
        let now = now_ms.max(0.0) as u64;
        self.inner.finish(server_hello, now).map_err(to_js)
    }

    /// 加密请求体。
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8], now_ms: f64) -> Result<Vec<u8>, JsError> {
        self.inner
            .seal(aad, plaintext, now_ms.max(0.0) as u64)
            .map_err(to_js)
    }

    /// 解密响应体。
    pub fn open(&mut self, aad: &[u8], frame: &[u8], now_ms: f64) -> Result<Vec<u8>, JsError> {
        self.inner
            .open(aad, frame, now_ms.max(0.0) as u64)
            .map_err(to_js)
    }

    /// 从帧反推 `X-Taotao-Crypto` 头值。
    pub fn header_for_frame(&self, frame: &[u8]) -> Result<String, JsError> {
        self.inner.header_for_frame(frame).map_err(to_js)
    }

    /// 会话 ID（十六进制）。无会话返回空串。
    #[wasm_bindgen(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id_hex()
    }

    /// 是否需要重新握手。
    pub fn needs_rekey(&self, now_ms: f64) -> bool {
        self.inner.needs_rekey(now_ms.max(0.0) as u64)
    }

    /// 是否已有一条可用会话。
    pub fn has_session(&self, now_ms: f64) -> bool {
        self.inner.has_session(now_ms.max(0.0) as u64)
    }

    /// 会话剩余有效毫秒数。
    pub fn session_remaining_ms(&self, now_ms: f64) -> f64 {
        self.inner.session_remaining_ms(now_ms.max(0.0) as u64) as f64
    }
}

/// 服务端引擎。
///
/// 只在「后端也用 wasm 跑」的场景下有用（比如 Cloudflare Workers）。
/// 常规 NestJS 部署走 `taotao-crypto-node`。
#[wasm_bindgen]
pub struct Server {
    inner: ServerEngine,
}

#[wasm_bindgen]
impl Server {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Server {
        Server {
            inner: ServerEngine::new(),
        }
    }

    /// 加入 / 更新一条 PSK。
    pub fn put_psk(&mut self, psk_id: &str, psk_hex: &str) -> Result<(), JsError> {
        self.inner.put_psk(psk_id, psk_hex).map_err(to_js)
    }

    /// 移除一条 PSK。
    pub fn remove_psk(&mut self, psk_id: &str) -> bool {
        self.inner.remove_psk(psk_id)
    }

    /// 处理 ClientHello，返回 ServerHello。`deviceId` 由握手请求携带并折进握手密钥。
    pub fn accept(
        &mut self,
        client_hello: &[u8],
        device_id: &str,
        now_ms: f64,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .accept(client_hello, device_id.as_bytes(), now_ms.max(0.0) as u64)
            .map_err(to_js)
    }

    /// 加密响应体。
    pub fn seal(
        &mut self,
        session_id_hex: &str,
        aad: &[u8],
        plaintext: &[u8],
        now_ms: f64,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .seal(session_id_hex, aad, plaintext, now_ms.max(0.0) as u64)
            .map_err(to_js)
    }

    /// 解密请求体。
    pub fn open(
        &mut self,
        session_id_hex: &str,
        aad: &[u8],
        frame: &[u8],
        now_ms: f64,
    ) -> Result<Vec<u8>, JsError> {
        self.inner
            .open(session_id_hex, aad, frame, now_ms.max(0.0) as u64)
            .map_err(to_js)
    }

    /// 会话是否仍然有效。
    pub fn has_session(&mut self, session_id_hex: &str, now_ms: f64) -> bool {
        self.inner
            .has_session(session_id_hex, now_ms.max(0.0) as u64)
    }

    /// 主动丢弃一条会话。
    pub fn drop_session(&mut self, session_id_hex: &str) -> bool {
        self.inner.drop_session(session_id_hex)
    }

    /// 清理过期会话。
    pub fn sweep_expired(&mut self, now_ms: f64) -> f64 {
        self.inner.sweep_expired(now_ms.max(0.0) as u64) as f64
    }

    /// 当前会话数量。
    #[wasm_bindgen(getter)]
    pub fn session_count(&self) -> f64 {
        self.inner.session_count() as f64
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// 协议版本。
#[wasm_bindgen]
pub fn protocol_version() -> u8 {
    taotao_crypto_core::PROTOCOL_VERSION
}

/// 当前 wasm 模块是否内嵌了真实 PSK。
///
/// Web 端正常情况下**不应该**是 true —— 分享页是公开的，内嵌 PSK 等于公开它。
#[wasm_bindgen]
pub fn has_real_psk() -> bool {
    taotao_crypto_core::build_psk_or_placeholder("__probe__")
        .map(|(_, is_real)| is_real)
        .unwrap_or(false)
}

/// 构造 AAD 上下文。
#[wasm_bindgen]
pub fn aad_context(method: &str, path_and_query: &str) -> Vec<u8> {
    aad(method, path_and_query)
}

/// 从 `X-Taotao-Crypto` 头值解析出 `[会话ID, 序号]`。格式非法返回 `null`。
#[wasm_bindgen]
pub fn parse_header(value: &str) -> Option<Vec<String>> {
    taotao_crypto_core::Session::parse_header_value(value).map(|(id, seq)| {
        vec![
            id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            seq.to_string(),
        ]
    })
}
