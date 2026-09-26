//! Node 原生扩展绑定（napi-rs），供 NestJS 后端使用。
//!
//! ## 服务端为什么也要用 Rust
//!
//! 服务端完全可以用 Node 的 `crypto` 模块实现同样的协议。选择原生扩展的理由：
//!
//! 1. **协议只有一份实现**。四个端共用 `taotao-crypto-core`，不存在「Node 侧
//!    的 HKDF info 拼错了两个字符」这种跨语言漂移。协议漂移的表现是
//!    「安卓能通、Web 不能通」，排查要同时开三个调试器。
//! 2. **抗重放的状态是进程内的**。会话表、握手 nonce 缓存放在 Rust 里，比
//!    放在 JS 对象里更难被误改（比如某处 `JSON.parse(JSON.stringify(...))`
//!    把 `Map` 变成了 `{}`）。
//! 3. **服务端可以跑多个 worker**。napi-rs 的 `#[napi]` 对象天然是线程安全的，
//!    而 JS 侧的共享状态需要额外的同步。
//!
//! ## 部署注意
//!
//! `.node` 是平台相关的二进制。CI 里必须为部署目标平台构建（Linux x64 上跑
//! 生产就要 Linux 的 `.node`），不能把 Windows 上编的产物推上去。
//! 容器镜像里要带上它，且 `package.json` 的 `files` 字段要包含它。

use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;
use taotao_crypto_core::{aad, ClientEngine, CryptoError, ServerEngine};

/// 把 core 的错误转成 napi 错误。
///
/// 统一映射到 `GenericFailure`：具体的错误分类（重放、过期、认证失败）由
/// 消息内容承载，调用方按消息前缀判断即可。不映射成不同的 `Status`，
/// 是因为 JS 侧真正需要的分支只有「重试握手」和「直接失败」两种。
fn to_napi(err: CryptoError) -> Error {
    Error::new(Status::GenericFailure, err.to_string())
}

/// 客户端引擎。
#[napi]
pub struct Client {
    inner: ClientEngine,
}

#[napi]
impl Client {
    /// 创建客户端。`pskHex` 必须是 64 个十六进制字符。`deviceId` 是本机稳定标识
    /// （Android ANDROID_ID / Windows MachineGuid），折进握手密钥；无设备端传空串。
    #[napi(constructor)]
    pub fn new(psk_id: String, psk_hex: String, device_id: String) -> Result<Self> {
        Ok(Self {
            inner: ClientEngine::new(&psk_id, &psk_hex, &device_id).map_err(to_napi)?,
        })
    }

    /// 发起握手，返回要发给服务端的 ClientHello。
    #[napi]
    pub fn handshake(&mut self, now_ms: i64) -> Result<Buffer> {
        let hello = self
            .inner
            .handshake(now_ms.max(0) as u64)
            .map_err(to_napi)?;
        Ok(Buffer::from(hello))
    }

    /// 处理 ServerHello，建立会话。
    #[napi]
    pub fn finish(&mut self, server_hello: Buffer, now_ms: i64) -> Result<()> {
        self.inner
            .finish(server_hello.as_ref(), now_ms.max(0) as u64)
            .map_err(to_napi)
    }

    /// 加密请求体。
    #[napi]
    pub fn seal(&mut self, aad: Buffer, plaintext: Buffer, now_ms: i64) -> Result<Buffer> {
        let frame = self
            .inner
            .seal(aad.as_ref(), plaintext.as_ref(), now_ms.max(0) as u64)
            .map_err(to_napi)?;
        Ok(Buffer::from(frame))
    }

    /// 解密响应体。
    #[napi]
    pub fn open(&mut self, aad: Buffer, frame: Buffer, now_ms: i64) -> Result<Buffer> {
        let plaintext = self
            .inner
            .open(aad.as_ref(), frame.as_ref(), now_ms.max(0) as u64)
            .map_err(to_napi)?;
        Ok(Buffer::from(plaintext))
    }

    /// 从帧反推 `X-Taotao-Crypto` 头值。
    #[napi]
    pub fn header_for_frame(&self, frame: Buffer) -> Result<String> {
        self.inner.header_for_frame(frame.as_ref()).map_err(to_napi)
    }

    /// 会话 ID（十六进制）。无会话返回空串。
    #[napi(getter)]
    pub fn session_id(&self) -> String {
        self.inner.session_id_hex()
    }

    /// 是否需要重新握手。
    #[napi]
    pub fn needs_rekey(&self, now_ms: i64) -> bool {
        self.inner.needs_rekey(now_ms.max(0) as u64)
    }

    /// 是否已有一条可用会话。
    #[napi]
    pub fn has_session(&self, now_ms: i64) -> bool {
        self.inner.has_session(now_ms.max(0) as u64)
    }

    /// 会话剩余有效毫秒数。
    #[napi]
    pub fn session_remaining_ms(&self, now_ms: i64) -> i64 {
        self.inner.session_remaining_ms(now_ms.max(0) as u64) as i64
    }
}

/// 服务端引擎。
#[napi]
pub struct Server {
    inner: ServerEngine,
}

/// `Server` 没有构造参数，默认构造就是「空 PSK 表 + 空会话表」，
/// 语义上没有歧义，所以补这个 impl 是对的（clippy 的
/// `new_without_default` 建议）。
///
/// 不影响 napi：`#[napi(constructor)]` 标在 `new` 上，JS 侧的
/// `new Server()` 仍然走它。这个 impl 只是 Rust 侧的类型能力。
impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl Server {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: ServerEngine::new(),
        }
    }

    /// 加入 / 更新一条 PSK。轮换期可以同时持有多条。
    #[napi]
    pub fn put_psk(&mut self, psk_id: String, psk_hex: String) -> Result<()> {
        self.inner.put_psk(&psk_id, &psk_hex).map_err(to_napi)
    }

    /// 移除一条 PSK。
    #[napi]
    pub fn remove_psk(&mut self, psk_id: String) -> bool {
        self.inner.remove_psk(&psk_id)
    }

    /// 处理 ClientHello，返回 ServerHello。新会话自动登记。
    /// `deviceId` 由握手请求携带，折进握手密钥；与客户端不一致则 MAC 失配、握手被拒。
    #[napi]
    pub fn accept(
        &mut self,
        client_hello: Buffer,
        device_id: String,
        now_ms: i64,
    ) -> Result<Buffer> {
        let response = self
            .inner
            .accept(
                client_hello.as_ref(),
                device_id.as_bytes(),
                now_ms.max(0) as u64,
            )
            .map_err(to_napi)?;
        Ok(Buffer::from(response))
    }

    /// 加密响应体。
    #[napi]
    pub fn seal(
        &mut self,
        session_id_hex: String,
        aad: Buffer,
        plaintext: Buffer,
        now_ms: i64,
    ) -> Result<Buffer> {
        let frame = self
            .inner
            .seal(
                &session_id_hex,
                aad.as_ref(),
                plaintext.as_ref(),
                now_ms.max(0) as u64,
            )
            .map_err(to_napi)?;
        Ok(Buffer::from(frame))
    }

    /// 解密请求体。
    #[napi]
    pub fn open(
        &mut self,
        session_id_hex: String,
        aad: Buffer,
        frame: Buffer,
        now_ms: i64,
    ) -> Result<Buffer> {
        let plaintext = self
            .inner
            .open(
                &session_id_hex,
                aad.as_ref(),
                frame.as_ref(),
                now_ms.max(0) as u64,
            )
            .map_err(to_napi)?;
        Ok(Buffer::from(plaintext))
    }

    /// 会话是否仍然有效。
    #[napi]
    pub fn has_session(&mut self, session_id_hex: String, now_ms: i64) -> bool {
        self.inner
            .has_session(&session_id_hex, now_ms.max(0) as u64)
    }

    /// 主动丢弃一条会话。
    #[napi]
    pub fn drop_session(&mut self, session_id_hex: String) -> bool {
        self.inner.drop_session(&session_id_hex)
    }

    /// 清理过期会话，返回清理条数。
    #[napi]
    pub fn sweep_expired(&mut self, now_ms: i64) -> i64 {
        self.inner.sweep_expired(now_ms.max(0) as u64) as i64
    }

    /// 当前会话数量。
    #[napi(getter)]
    pub fn session_count(&self) -> i64 {
        self.inner.session_count() as i64
    }

    /// 当前 PSK 数量。
    #[napi(getter)]
    pub fn psk_count(&self) -> i64 {
        self.inner.psk_count() as i64
    }
}

/// 协议版本。JS 侧据此校验 native 模块与后端代码版本是否匹配。
#[napi]
pub fn protocol_version() -> u32 {
    taotao_crypto_core::PROTOCOL_VERSION as u32
}

/// 当前二进制里是否注入了真实 PSK。
///
/// 返回 false 说明构建时没设 `TAOTAO_CRYPTO_PSK`，用的是源码里的占位密钥。
/// 生产环境必须在启动时检查这个值并拒绝启动。
#[napi]
pub fn has_real_psk() -> bool {
    taotao_crypto_core::build_psk_or_placeholder("__probe__")
        .map(|(_, is_real)| is_real)
        .unwrap_or(false)
}

/// 构造 AAD 上下文。
#[napi]
pub fn aad_context(method: String, path_and_query: String) -> Buffer {
    Buffer::from(aad(&method, &path_and_query))
}

/// 从 `X-Taotao-Crypto` 头值解析出 `[会话ID, 序号]`。格式非法返回 null。
#[napi]
pub fn parse_header(value: String) -> Option<Vec<String>> {
    taotao_crypto_core::Session::parse_header_value(&value)
        .map(|(id, seq)| vec![hex_encode(&id), seq.to_string()])
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
