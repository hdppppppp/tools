//! 握手：PSK 认证 + X25519 密钥协商。
//!
//! ## 为什么是「PSK + ECDH」而不是二选一
//!
//! - **纯 PSK**：密钥硬编码在客户端里，一旦被提取就永久失效，而且没有前向保密 ——
//!   攻击者录下历史流量，日后拿到 PSK 就能解密全部历史。
//! - **纯 ECDH**：中间人可以各自与两端握手，服务端无法区分「真客户端」和
//!   「转发的中间人」。
//!
//! 两者结合：用 PSK 给握手消息加 HMAC（证明「你持有 PSK」），用 X25519 协商
//! 出**每次会话不同**的数据密钥。PSK 泄漏的影响被限制在「可以冒充客户端握手」，
//! 已录制流量的历史数据仍然安全（前向保密）。
//!
//! ## 握手流程（1-RTT）
//!
//! ```text
//! 客户端                                    服务端
//!   |                                          |
//!   |  ClientHello                             |
//!   |  {version, psk_id, cnonce, C_eph_pub, ts, MAC}
//!   |----------------------------------------->|  ① 查 psk_id 取 PSK
//!   |                                          |  ② 校验 ts 在窗口内
//!   |                                          |  ③ 校验 cnonce 未见过
//!   |                                          |  ④ 校验 MAC
//!   |                                          |  ⑤ 生成 S_eph、session_id
//!   |  ServerHello                             |
//!   |  {version, session_id, cnonce, S_eph_pub, ts, ttl, MAC}
//!   |<-----------------------------------------|
//!   |  ⑥ 校验 MAC、校验 cnonce 与自己发的一致    |
//!   |                                          |
//!   |  双方各自计算 K = X25519(自己私钥, 对方公钥) |
//!   |  会话密钥 = HKDF(salt=cnonce, K, session_id)|
//! ```
//!
//! 绑定 `cnonce` 是防「握手重放」的关键：攻击者录下完整的一对
//! ClientHello/ServerHello 后原样重发，如果没有 cnonce 绑定，服务端会
//! 认下这次握手并派生出**同一个**会话密钥 —— 攻击者就能解密该会话的流量。
//! 绑定之后，重放的 ClientHello 会被服务端的 cnonce 缓存挡住。

use std::collections::{HashSet, VecDeque};

use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::kdf::{
    constant_time_eq, derive_handshake_key, derive_session_keys, hmac_sha256, RandomSource,
    SessionKeys, PSK_LEN,
};
use crate::protocol::{
    CLIENT_HELLO_MIN_LEN, CLIENT_HELLO_PREFIX_LEN, CLIENT_HELLO_SUFFIX_LEN,
    DEFAULT_SESSION_TTL_SECS, HELLO_NONCE_LEN, PROTOCOL_VERSION, SERVER_HELLO_LEN, SESSION_ID_LEN,
    TIMESTAMP_SKEW_MS, X25519_KEY_LEN,
};
use crate::psk::{Psk, PskStore};
use crate::session::Session;

/// 握手消息的 MAC 长度。
const MAC_LEN: usize = 32;

/// 占位 PSK：`psk_id` 查不到时用它走完**完全相同**的 MAC 计算路径。
///
/// 目的只有一个 —— 抹掉「id 存在」与「id 不存在」之间的耗时差。它永远不会
/// 导致任何消息被接受：调用点先判 `psk.is_none()`，占位密钥只是让计算量对齐。
const PLACEHOLDER_PSK: [u8; PSK_LEN] = [0u8; PSK_LEN];

/// 从 ClientHello 里取出 `psk_id`，**不做任何校验**。
///
/// 存在的理由是补上「统一错误」带来的运维盲区：`accept_client_hello` 现在对
/// 「id 不认识」和「MAC 不对」返回同一个错误（否则等于给攻击者一个枚举
/// psk_id 的接口），但线上排查密钥轮换问题时又确实需要知道客户端发的是哪个 id。
///
/// 所以把这条线索单独开一个口子：**服务端在 accept 失败时调用它写日志**，
/// 而不是把 id 塞进错误消息 —— 错误消息会原样回给客户端，而日志不会。
///
/// ⚠️ 返回值来自未经认证的输入，**只能写日志，不能用来做任何决策**。
/// 调用方还要自行转义：它可能包含换行符等控制字符（日志注入）。
pub fn peek_psk_id(client_hello: &[u8]) -> Option<&str> {
    if client_hello.len() < CLIENT_HELLO_MIN_LEN {
        return None;
    }
    let psk_id_len = client_hello[1] as usize;
    let end = CLIENT_HELLO_PREFIX_LEN.checked_add(psk_id_len)?;
    if client_hello.len() != end + CLIENT_HELLO_SUFFIX_LEN {
        return None;
    }
    core::str::from_utf8(&client_hello[CLIENT_HELLO_PREFIX_LEN..end]).ok()
}

/// 校验时间戳是否在允许窗口内。
///
/// 用绝对差值而不是「必须晚于」：手机时钟可能比服务端快，只允许单向偏差
/// 会让时钟超前的设备全部握手失败。
fn check_timestamp(ts_ms: u64, now_ms: u64, limit_ms: u64) -> Result<()> {
    let skew = ts_ms.abs_diff(now_ms);
    if skew > limit_ms {
        return Err(CryptoError::TimestampOutOfWindow {
            skew_ms: skew,
            limit_ms,
        });
    }
    Ok(())
}

/// 握手 nonce 缓存的条目上限。
///
/// 没有上限的话，一个持有合法 PSK 的客户端（或拿到泄露 PSK 的攻击者）可以在
/// 10 分钟窗口内无限灌入随机 nonce，把内存吃光。有了上限之后，攻击退化成
/// 「最旧的条目被挤掉」—— 被挤掉的 nonce 属于一个已经完成握手的客户端，
/// 攻击者重放它的 hello 最多让服务端多建一条会话（攻击者本来就有 PSK，
/// 正常握手也能建），拿不到额外好处。
///
/// 65536 条 × 24 字节 ≈ 1.5 MiB，对应 10 分钟窗口内约 109 次握手/秒的持续
/// 速率，对音乐 App 这种量级绰绰有余。
const MAX_HELLO_REPLAY_ENTRIES: usize = 65_536;

/// 两次按时间淘汰之间的最小间隔。
///
/// 淘汰要遍历整个队列。每次插入都做的话，缓存接近上限时每次握手都要走 6.5 万
/// 步 —— 攻击者用握手请求就能把这个 O(n) 放大成 CPU 耗尽。
///
/// 延迟淘汰**没有正确性代价**：nonce 是 16 字节随机值，正常客户端不会重复使用，
/// 多留一会儿只是多占一点内存，而上限已经封住了内存。
const EVICT_MIN_INTERVAL_MS: u64 = 1_000;

/// 握手 nonce 的防重放缓存。
///
/// 只需要挡住「同一个 ClientHello 被重发」这一种情况，所以按时间窗淘汰即可，
/// 不需要持久化。窗口取时间戳窗口的两倍，保证一个 nonce 在它还有可能通过
/// 时间戳校验的整个期间都被记住。
///
/// 内部用「哈希集查重 + 队列记序」而不是一个 `Vec` 线性扫描：查重是每次握手
/// 都要走的路径，做成 O(n) 等于给攻击者一个放大器 —— 他只要持续发握手，
/// 就能让每一次请求都付出「缓存当前大小」的代价。
#[derive(Debug)]
pub struct HelloReplayCache {
    /// 按插入顺序排列，用于按时间淘汰和超限兜底。
    order: VecDeque<(u64, [u8; HELLO_NONCE_LEN])>,
    /// 与 `order` 同内容，把「见过这个 nonce 吗」从 O(n) 降到 O(1)。
    seen: HashSet<[u8; HELLO_NONCE_LEN]>,
    window_ms: u64,
    /// 上次按时间淘汰的时刻，用于限制淘汰频率。
    last_evict_ms: u64,
}

impl Default for HelloReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloReplayCache {
    pub fn new() -> Self {
        Self {
            order: VecDeque::new(),
            seen: HashSet::new(),
            window_ms: TIMESTAMP_SKEW_MS * 2,
            last_evict_ms: 0,
        }
    }

    /// 检查并记录一个 nonce。返回 `false` 表示见过（重放）。
    pub fn check_and_insert(&mut self, nonce: [u8; HELLO_NONCE_LEN], now_ms: u64) -> bool {
        self.evict_if_due(now_ms);

        // `insert` 返回 false 就说明已经在了 —— 顺便完成查重，不用再扫一遍。
        if !self.seen.insert(nonce) {
            return false;
        }
        self.order.push_back((now_ms, nonce));

        // 上限兜底：淘汰还没到期也不能让内存无限涨。
        while self.order.len() > MAX_HELLO_REPLAY_ENTRIES {
            self.pop_front();
        }
        true
    }

    fn pop_front(&mut self) {
        if let Some((_, nonce)) = self.order.pop_front() {
            self.seen.remove(&nonce);
        }
    }

    fn evict_if_due(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_evict_ms) < EVICT_MIN_INTERVAL_MS {
            return;
        }
        self.last_evict_ms = now_ms;

        let window = self.window_ms;
        // 队列是按时间递增的，所以从队首一路弹出到第一个未过期即可。
        while let Some((ts, _)) = self.order.front() {
            if now_ms.saturating_sub(*ts) <= window {
                break;
            }
            self.pop_front();
        }
    }

    /// 仅测试使用：断言缓存条目数。
    ///
    /// 刻意不是 `pub` —— clippy 的 `len_without_is_empty` 针对的是**对外 API**，
    /// 而这里的方法只在测试构建里存在（`#[cfg(test)]`），既不是对外 API，
    /// 也就不需要配套的 `is_empty()`。改成 `pub` 反而会让 clippy 要求补一个
    /// 只为了对称而存在的空方法。
    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

/// ClientHello 的解析结果。
struct ParsedClientHello {
    psk_id: String,
    client_nonce: [u8; HELLO_NONCE_LEN],
    eph_pub: PublicKey,
    ts_ms: u64,
    /// MAC 覆盖的字节范围（即除去尾部 MAC 的全部内容）。
    signed_len: usize,
}

fn encode_client_hello(
    psk_id: &str,
    client_nonce: &[u8; HELLO_NONCE_LEN],
    eph_pub: &PublicKey,
    ts_ms: u64,
    mac: &[u8; MAC_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CLIENT_HELLO_MIN_LEN + psk_id.len());
    out.push(PROTOCOL_VERSION);
    out.push(psk_id.len() as u8);
    out.extend_from_slice(psk_id.as_bytes());
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out.extend_from_slice(mac);
    out
}

fn parse_client_hello(msg: &[u8]) -> Result<ParsedClientHello> {
    if msg.len() < CLIENT_HELLO_MIN_LEN {
        return Err(CryptoError::Truncated {
            need: CLIENT_HELLO_MIN_LEN,
            got: msg.len(),
        });
    }
    let version = msg[0];
    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion {
            got: version,
            supported: PROTOCOL_VERSION,
        });
    }

    let psk_id_len = msg[1] as usize;
    let expected_len = CLIENT_HELLO_PREFIX_LEN + psk_id_len + CLIENT_HELLO_SUFFIX_LEN;
    if msg.len() != expected_len {
        return Err(CryptoError::Truncated {
            need: expected_len,
            got: msg.len(),
        });
    }

    let psk_id_bytes = &msg[CLIENT_HELLO_PREFIX_LEN..CLIENT_HELLO_PREFIX_LEN + psk_id_len];
    let psk_id = core::str::from_utf8(psk_id_bytes)
        .map_err(|_| CryptoError::HandshakeAuthFailed)?
        .to_string();

    let mut cursor = CLIENT_HELLO_PREFIX_LEN + psk_id_len;

    let mut client_nonce = [0u8; HELLO_NONCE_LEN];
    client_nonce.copy_from_slice(&msg[cursor..cursor + HELLO_NONCE_LEN]);
    cursor += HELLO_NONCE_LEN;

    let mut eph_bytes = [0u8; X25519_KEY_LEN];
    eph_bytes.copy_from_slice(&msg[cursor..cursor + X25519_KEY_LEN]);
    cursor += X25519_KEY_LEN;

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&msg[cursor..cursor + 8]);
    let ts_ms = u64::from_be_bytes(ts_bytes);
    cursor += 8;

    Ok(ParsedClientHello {
        psk_id,
        client_nonce,
        eph_pub: PublicKey::from(eph_bytes),
        ts_ms,
        signed_len: cursor,
    })
}

fn encode_server_hello(
    session_id: &[u8; SESSION_ID_LEN],
    client_nonce: &[u8; HELLO_NONCE_LEN],
    eph_pub: &PublicKey,
    ts_ms: u64,
    ttl_secs: u32,
    mac: &[u8; MAC_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SERVER_HELLO_LEN);
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(session_id);
    out.extend_from_slice(client_nonce);
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out.extend_from_slice(&ttl_secs.to_be_bytes());
    out.extend_from_slice(mac);
    out
}

/// ServerHello 的解析结果。
struct ParsedServerHello {
    session_id: [u8; SESSION_ID_LEN],
    client_nonce: [u8; HELLO_NONCE_LEN],
    eph_pub: PublicKey,
    ts_ms: u64,
    ttl_secs: u32,
    signed_len: usize,
}

fn parse_server_hello(msg: &[u8]) -> Result<ParsedServerHello> {
    if msg.len() != SERVER_HELLO_LEN {
        return Err(CryptoError::Truncated {
            need: SERVER_HELLO_LEN,
            got: msg.len(),
        });
    }
    let version = msg[0];
    if version != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion {
            got: version,
            supported: PROTOCOL_VERSION,
        });
    }

    let mut cursor = 1;

    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&msg[cursor..cursor + SESSION_ID_LEN]);
    cursor += SESSION_ID_LEN;

    let mut client_nonce = [0u8; HELLO_NONCE_LEN];
    client_nonce.copy_from_slice(&msg[cursor..cursor + HELLO_NONCE_LEN]);
    cursor += HELLO_NONCE_LEN;

    let mut eph_bytes = [0u8; X25519_KEY_LEN];
    eph_bytes.copy_from_slice(&msg[cursor..cursor + X25519_KEY_LEN]);
    cursor += X25519_KEY_LEN;

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&msg[cursor..cursor + 8]);
    let ts_ms = u64::from_be_bytes(ts_bytes);
    cursor += 8;

    let mut ttl_bytes = [0u8; 4];
    ttl_bytes.copy_from_slice(&msg[cursor..cursor + 4]);
    let ttl_secs = u32::from_be_bytes(ttl_bytes);
    cursor += 4;

    Ok(ParsedServerHello {
        session_id,
        client_nonce,
        eph_pub: PublicKey::from(eph_bytes),
        ts_ms,
        ttl_secs,
        signed_len: cursor,
    })
}

/// 握手角色。
///
/// 唯一的作用是决定从 [`derive_session_keys`] 返回的那一对密钥里取哪一半：
/// 客户端取 `c2s`，服务端取 `s2c`。这个分支**必须**存在且不能搞反 ——
/// 取反的表现是「握手成功、双方都能算出密钥，但谁也解不开对方发的帧」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// 计算 X25519 共享秘密并派生本端的会话密钥对。
///
/// 两端走的是同一段逻辑，只有最后「取哪一半」不同，所以这里用 `role` 参数
/// 而不是写两份代码 —— 两份代码迟早会漂移，而漂移的表现是握手静默失败。
fn establish(
    role: Role,
    own_secret: &StaticSecret,
    peer_public: &PublicKey,
    salt: &[u8; HELLO_NONCE_LEN],
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<SessionKeys> {
    let shared: SharedSecret = own_secret.diffie_hellman(peer_public);

    // 低阶点攻击：攻击者发一个低阶公钥，会让共享秘密落进一个极小的子群，
    // 从而把密钥空间缩到可以穷举。x25519-dalek 提供了这个检查。
    if !shared.was_contributory() {
        return Err(CryptoError::HandshakeAuthFailed);
    }

    let mut shared_bytes = *shared.as_bytes();
    let (client_side, server_side) = derive_session_keys(&shared_bytes, salt, session_id);
    shared_bytes.zeroize();

    Ok(match role {
        Role::Client => client_side,
        Role::Server => server_side,
    })
}

/// 客户端握手状态机。
pub struct ClientHandshake {
    psk: Psk,
    ephemeral: StaticSecret,
    client_nonce: [u8; HELLO_NONCE_LEN],
    /// 本机设备号，折进握手密钥派生。收到 ServerHello 时要再用一次，故保存。
    device_id: Vec<u8>,
}

impl core::fmt::Debug for ClientHandshake {
    /// 手写 Debug：`StaticSecret` 的 Debug 实现会打印私钥字节，而握手状态机
    /// 经常出现在 `ClientEngine` 的 Debug 输出里（日志、崩溃上报都会带上）。
    /// 一旦它泄露，攻击者拿到临时私钥就能算出会话密钥。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("psk_id", &self.psk.id())
            .field("ephemeral", &"<已隐藏>")
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// 生成 ClientHello。
    ///
    /// 返回 `(状态机, hello 字节)`。状态机必须保存到收到 ServerHello 为止 ——
    /// 它持有 X25519 临时私钥，丢了就没法算出会话密钥。
    ///
    /// `device_id` 折进握手密钥派生（不写进 ClientHello 二进制报文，由外层传输
    /// 携带给服务端）。设备号不匹配的两端算出的握手密钥不同，MAC 必然失配。
    pub fn start<R: RandomSource>(
        psk: Psk,
        device_id: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>)> {
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes)?;
        let ephemeral = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        let mut client_nonce = [0u8; HELLO_NONCE_LEN];
        rng.fill(&mut client_nonce)?;

        let eph_pub = PublicKey::from(&ephemeral);
        let mut handshake_key = derive_handshake_key(psk.key(), psk.id().as_bytes(), device_id);

        let mut signed = Vec::with_capacity(CLIENT_HELLO_MIN_LEN);
        signed.push(PROTOCOL_VERSION);
        signed.push(psk.id().len() as u8);
        signed.extend_from_slice(psk.id().as_bytes());
        signed.extend_from_slice(&client_nonce);
        signed.extend_from_slice(eph_pub.as_bytes());
        signed.extend_from_slice(&now_ms.to_be_bytes());

        let mac = hmac_sha256(&handshake_key, &signed);
        // 派生出来的握手密钥用完即擦。它与相邻的 `secret_bytes.zeroize()` 是
        // 同一条规矩：本模块里凡是「从 PSK 或共享秘密算出来的东西」都不留在栈上。
        handshake_key.zeroize();
        let hello = encode_client_hello(psk.id(), &client_nonce, &eph_pub, now_ms, &mac);

        Ok((
            Self {
                psk,
                ephemeral,
                client_nonce,
                device_id: device_id.to_vec(),
            },
            hello,
        ))
    }

    /// 处理 ServerHello，建立会话。
    pub fn finish(self, server_hello: &[u8], now_ms: u64) -> Result<Session> {
        let parsed = parse_server_hello(server_hello)?;
        check_timestamp(parsed.ts_ms, now_ms, TIMESTAMP_SKEW_MS)?;

        let mut handshake_key =
            derive_handshake_key(self.psk.key(), self.psk.id().as_bytes(), &self.device_id);
        let expected_mac = hmac_sha256(&handshake_key, &server_hello[..parsed.signed_len]);
        let mac_ok = constant_time_eq(&expected_mac, &server_hello[parsed.signed_len..]);
        handshake_key.zeroize();
        if !mac_ok {
            return Err(CryptoError::HandshakeAuthFailed);
        }

        // 服务端必须回显我们发出的 nonce。不回显就意味着它在用另一个会话的
        // 参数糊弄我们，或者这是一次重放。
        if !constant_time_eq(&parsed.client_nonce, &self.client_nonce) {
            return Err(CryptoError::HandshakeAuthFailed);
        }

        let keys = establish(
            Role::Client,
            &self.ephemeral,
            &parsed.eph_pub,
            &self.client_nonce,
            &parsed.session_id,
        )?;

        Ok(Session::new(
            parsed.session_id,
            keys,
            now_ms,
            parsed.ttl_secs,
        ))
    }
}

/// 服务端握手结果。
#[derive(Debug)]
pub struct AcceptedHandshake {
    /// 新建的会话。
    pub session: Session,
    /// 要回给客户端的 ServerHello 字节。
    pub response: Vec<u8>,
}

/// 服务端处理 ClientHello。
///
/// **所有失败都返回同一个 [`CryptoError::HandshakeAuthFailed`]**（除了长度/版本
/// 这类格式错误）：区分「psk_id 不存在」和「MAC 不对」等于告诉攻击者他的
/// psk_id 猜对了，而 psk_id 是可以被枚举的。调用方也**不要**把具体原因回给
/// 客户端（回一个统一的 400 就够）；需要排查时用 [`peek_psk_id`] 单独取 id
/// 写日志。
pub fn accept_client_hello<R: RandomSource>(
    store: &PskStore,
    client_hello: &[u8],
    device_id: &[u8],
    now_ms: u64,
    replay_cache: &mut HelloReplayCache,
    rng: &mut R,
) -> Result<AcceptedHandshake> {
    let parsed = parse_client_hello(client_hello)?;

    // 时间戳先查：它不需要任何密钥，最便宜。
    check_timestamp(parsed.ts_ms, now_ms, TIMESTAMP_SKEW_MS)?;

    // ⚠️ psk_id 查不到时**不能提前返回**，两个原因：
    //
    // ① 返回一个不同的错误码，等于确认「这个 psk_id 存在」。psk_id 只是版本
    //    标签（`prod-v1` 这种），不是秘密，可以被枚举 —— 一旦确认，攻击者就
    //    省掉了猜 id 这一步，只需要专心对付密钥。
    // ② 提前返回还会省掉一次 HKDF + HMAC，形成可测的时序差。就算把错误码
    //    统一了，攻击者靠响应时间仍然能问出同一个问题。
    //
    // 所以查不到时用一条固定的占位密钥走完**完全相同**的计算路径，最后统一
    // 返回 HandshakeAuthFailed —— 与「MAC 不对」在错误码和耗时上都不可区分。
    //
    // 代价是运维失去了「客户端用的 id 我不认识」这条线索。补偿手段是
    // [`peek_psk_id`]：服务端在 accept 失败时单独取出来写日志，那条路径不回给
    // 客户端。
    let psk = store.get(&parsed.psk_id);
    let mut handshake_key = match psk {
        Some(psk) => derive_handshake_key(psk.key(), psk.id().as_bytes(), device_id),
        None => derive_handshake_key(&PLACEHOLDER_PSK, b"", device_id),
    };
    let expected_mac = hmac_sha256(&handshake_key, &client_hello[..parsed.signed_len]);
    let mac_ok = constant_time_eq(&expected_mac, &client_hello[parsed.signed_len..]);
    if psk.is_none() || !mac_ok {
        handshake_key.zeroize();
        return Err(CryptoError::HandshakeAuthFailed);
    }

    // nonce 缓存放在 MAC 校验**之后**：否则攻击者可以拿伪造的 hello 灌满缓存，
    // 把真客户端的 nonce 挤出去（内存耗尽 + 拒绝服务）。
    if !replay_cache.check_and_insert(parsed.client_nonce, now_ms) {
        handshake_key.zeroize();
        return Err(CryptoError::ReplayDetected { seq: 0 });
    }

    let mut secret_bytes = [0u8; 32];
    rng.fill(&mut secret_bytes)?;
    let ephemeral = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();

    let mut session_id = [0u8; SESSION_ID_LEN];
    rng.fill(&mut session_id)?;

    let eph_pub = PublicKey::from(&ephemeral);
    let ttl_secs = DEFAULT_SESSION_TTL_SECS;

    let mut signed = Vec::with_capacity(SERVER_HELLO_LEN);
    signed.push(PROTOCOL_VERSION);
    signed.extend_from_slice(&session_id);
    signed.extend_from_slice(&parsed.client_nonce);
    signed.extend_from_slice(eph_pub.as_bytes());
    signed.extend_from_slice(&now_ms.to_be_bytes());
    signed.extend_from_slice(&ttl_secs.to_be_bytes());

    let mac = hmac_sha256(&handshake_key, &signed);
    handshake_key.zeroize();
    let response = encode_server_hello(
        &session_id,
        &parsed.client_nonce,
        &eph_pub,
        now_ms,
        ttl_secs,
        &mac,
    );

    let keys = establish(
        Role::Server,
        &ephemeral,
        &parsed.eph_pub,
        &parsed.client_nonce,
        &session_id,
    )?;

    Ok(AcceptedHandshake {
        session: Session::new(session_id, keys, now_ms, ttl_secs),
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::PSK_LEN;

    /// 确定性随机源，让握手测试可复现。
    struct SeqRandom(u8);
    impl RandomSource for SeqRandom {
        fn fill(&mut self, out: &mut [u8]) -> Result<()> {
            for byte in out.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    const NOW: u64 = 1_700_000_000_000;
    /// 测试用设备号；客户端与服务端必须一致，握手才成立。
    const DEVICE: &[u8] = b"test-device-01";

    fn client_psk() -> Psk {
        Psk::new("prod-v1", [0x11; PSK_LEN]).unwrap()
    }

    fn server_store() -> PskStore {
        let mut store = PskStore::new();
        store.insert(client_psk());
        store
    }

    #[test]
    fn full_handshake_establishes_matching_sessions() {
        let mut rng = SeqRandom(1);
        let (client_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        assert_eq!(hello[0], PROTOCOL_VERSION);

        let mut cache = HelloReplayCache::new();
        let accepted =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW + 10, &mut cache, &mut rng).unwrap();

        let client_session = client_hs.finish(&accepted.response, NOW + 20).unwrap();

        assert_eq!(client_session.id(), accepted.session.id());

        // 两侧密钥必须互为镜像：客户端 seal 出来的，服务端要能 open。
        let mut c = client_session;
        let mut s = accepted.session;
        let frame = c
            .seal(
                &crate::protocol::aad_context("GET", "/api/v1/favorites"),
                b"{}",
                NOW + 30,
            )
            .unwrap();
        let opened = s
            .open(
                &crate::protocol::aad_context("GET", "/api/v1/favorites"),
                &frame.bytes,
                NOW + 30,
            )
            .unwrap();
        assert_eq!(opened.plaintext, b"{}");

        // 反方向同样要通。
        let resp = s
            .seal(
                &crate::protocol::aad_context("200", "/api/v1/favorites"),
                b"ok",
                NOW + 40,
            )
            .unwrap();
        let opened = c
            .open(
                &crate::protocol::aad_context("200", "/api/v1/favorites"),
                &resp.bytes,
                NOW + 40,
            )
            .unwrap();
        assert_eq!(opened.plaintext, b"ok");
    }

    #[test]
    fn replaying_client_hello_is_rejected() {
        let mut rng = SeqRandom(1);
        let (_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();

        accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap();
        // 同一个 hello 原样重发 —— 这是握手重放，必须挡住。
        let err =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap_err();
        assert!(matches!(err, CryptoError::ReplayDetected { .. }));
    }

    #[test]
    fn hello_replay_cache_evicts_old_entries() {
        let mut cache = HelloReplayCache::new();
        assert!(cache.check_and_insert([1u8; HELLO_NONCE_LEN], NOW));
        assert_eq!(cache.len(), 1);
        // 远超窗口之后再插入，旧条目应被淘汰。
        assert!(cache.check_and_insert([2u8; HELLO_NONCE_LEN], NOW + TIMESTAMP_SKEW_MS * 3));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn unknown_psk_id_is_rejected() {
        let mut rng = SeqRandom(1);
        let other = Psk::new("staging", [0x22; PSK_LEN]).unwrap();
        let (_hs, hello) = ClientHandshake::start(other, DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();
        let err =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap_err();
        // 必须是**统一的**认证失败，不能是 UnknownPskId —— 后者等于告诉攻击者
        // 「这个 psk_id 存在」，把 psk_id 变成可以枚举的。
        assert_eq!(err, CryptoError::HandshakeAuthFailed);
    }

    #[test]
    fn unknown_psk_id_is_indistinguishable_from_wrong_key() {
        // 两种失败必须返回完全一样的错误，否则攻击者能用错误码枚举 psk_id。
        let mut rng = SeqRandom(1);
        let mut cache_a = HelloReplayCache::new();
        let mut cache_b = HelloReplayCache::new();

        // 情形一：id 存在，但密钥不对。
        let wrong_key = Psk::new("prod-v1", [0x33; PSK_LEN]).unwrap();
        let (_hs, hello_a) = ClientHandshake::start(wrong_key, DEVICE, NOW, &mut rng).unwrap();
        let err_a = accept_client_hello(&server_store(), &hello_a, DEVICE, NOW, &mut cache_a, &mut rng)
            .unwrap_err();

        // 情形二：id 根本不存在。
        let unknown = Psk::new("staging", [0x22; PSK_LEN]).unwrap();
        let (_hs, hello_b) = ClientHandshake::start(unknown, DEVICE, NOW, &mut rng).unwrap();
        let err_b = accept_client_hello(&server_store(), &hello_b, DEVICE, NOW, &mut cache_b, &mut rng)
            .unwrap_err();

        assert_eq!(err_a, err_b, "两种失败必须不可区分");
    }

    #[test]
    fn peek_psk_id_reads_id_without_authenticating() {
        let mut rng = SeqRandom(1);
        let (_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        assert_eq!(peek_psk_id(&hello), Some("prod-v1"));

        // 长度对不上时必须返回 None，不能越界读。
        assert_eq!(peek_psk_id(&hello[..10]), None);
        assert_eq!(peek_psk_id(&[]), None);
    }

    #[test]
    fn hello_replay_cache_is_bounded() {
        // 灌入远超上限的随机 nonce，内存必须被上限封住。
        let mut cache = HelloReplayCache::new();
        let limit = MAX_HELLO_REPLAY_ENTRIES;
        for i in 0..(limit + 1000) {
            let mut nonce = [0u8; HELLO_NONCE_LEN];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            // 时间固定在窗口内，确保淘汰逻辑不会替我们兜底 —— 这里要验的正是
            // 「按时间淘汰没生效时，上限仍然挡得住」。
            assert!(cache.check_and_insert(nonce, NOW));
        }
        assert_eq!(cache.len(), limit, "缓存必须被上限封住");
    }

    #[test]
    fn hello_replay_cache_still_detects_replay_after_eviction_gate() {
        // 淘汰被限频之后，「重复 nonce」仍然必须被立刻发现 —— 查重走的是哈希集，
        // 与淘汰频率无关。
        let mut cache = HelloReplayCache::new();
        let nonce = [7u8; HELLO_NONCE_LEN];
        assert!(cache.check_and_insert(nonce, NOW));
        // 同一毫秒内再插一次：淘汰会被限频跳过，但查重不能失效。
        assert!(!cache.check_and_insert(nonce, NOW));
        assert!(!cache.check_and_insert(nonce, NOW + 10));
    }

    #[test]
    fn wrong_psk_is_rejected() {
        // 客户端用同一个 id、不同密钥 —— 服务端查得到 id 但 MAC 对不上。
        let fake = Psk::new("prod-v1", [0x33; PSK_LEN]).unwrap();
        let mut rng = SeqRandom(1);
        let (_hs, hello) = ClientHandshake::start(fake, DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();
        let err =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap_err();
        assert_eq!(err, CryptoError::HandshakeAuthFailed);
    }

    #[test]
    fn tampered_hello_is_rejected() {
        let mut rng = SeqRandom(1);
        let (_hs, mut hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        // 改一个字节的临时公钥 —— MAC 必须失配。
        hello[CLIENT_HELLO_PREFIX_LEN + HELLO_NONCE_LEN] ^= 0x01;
        let mut cache = HelloReplayCache::new();
        let err =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap_err();
        assert_eq!(err, CryptoError::HandshakeAuthFailed);
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let mut rng = SeqRandom(1);
        let (_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();
        let err = accept_client_hello(
            &server_store(),
            &hello,
            DEVICE,
            NOW + TIMESTAMP_SKEW_MS + 1,
            &mut cache,
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn client_rejects_tampered_server_hello() {
        let mut rng = SeqRandom(1);
        let (client_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();
        let accepted =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap();

        let mut bad = accepted.response.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert_eq!(
            client_hs.finish(&bad, NOW).unwrap_err(),
            CryptoError::HandshakeAuthFailed
        );
    }

    #[test]
    fn client_rejects_mismatched_client_nonce() {
        let mut rng = SeqRandom(1);
        let (client_hs, hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        let mut cache = HelloReplayCache::new();
        let mut accepted =
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap();

        // 服务端回显了错误的 nonce。重算 MAC 让它「合法」，客户端仍必须拒绝。
        let nonce_offset = 1 + SESSION_ID_LEN;
        accepted.response[nonce_offset] ^= 0x01;
        let handshake_key = derive_handshake_key(client_psk().key(), client_psk().id().as_bytes(), DEVICE);
        let signed_len = SERVER_HELLO_LEN - MAC_LEN;
        let mac = hmac_sha256(&handshake_key, &accepted.response[..signed_len]);
        accepted.response[signed_len..].copy_from_slice(&mac);

        assert_eq!(
            client_hs.finish(&accepted.response, NOW).unwrap_err(),
            CryptoError::HandshakeAuthFailed
        );
    }

    #[test]
    fn truncated_messages_are_rejected() {
        assert!(parse_client_hello(&[PROTOCOL_VERSION, 0]).is_err());
        assert!(parse_server_hello(&[PROTOCOL_VERSION; 10]).is_err());
        let mut cache = HelloReplayCache::new();
        let mut rng = SeqRandom(1);
        assert!(accept_client_hello(&server_store(), &[], DEVICE, NOW, &mut cache, &mut rng).is_err());
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut rng = SeqRandom(1);
        let (_hs, mut hello) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        hello[0] = 99;
        let mut cache = HelloReplayCache::new();
        assert!(matches!(
            accept_client_hello(&server_store(), &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap_err(),
            CryptoError::UnsupportedVersion { got: 99, .. }
        ));
    }

    #[test]
    fn each_handshake_yields_distinct_keys() {
        // 同一对 PSK 连续握手两次，会话密钥必须不同（前向保密的基础）。
        let mut rng = SeqRandom(1);
        let (hs1, hello1) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        let (hs2, hello2) = ClientHandshake::start(client_psk(), DEVICE, NOW, &mut rng).unwrap();
        assert_ne!(hello1, hello2, "每次握手的临时公钥与 nonce 都必须不同");

        let mut cache = HelloReplayCache::new();
        let a1 = accept_client_hello(&server_store(), &hello1, DEVICE, NOW, &mut cache, &mut rng).unwrap();
        let a2 = accept_client_hello(&server_store(), &hello2, DEVICE, NOW, &mut cache, &mut rng).unwrap();

        let s1 = hs1.finish(&a1.response, NOW).unwrap();
        let s2 = hs2.finish(&a2.response, NOW).unwrap();
        assert_ne!(s1.id(), s2.id(), "会话 ID 必须唯一");

        // 交叉解密必须失败：会话 1 的密钥解不开会话 2 的帧。
        let mut s1 = s1;
        let mut s2 = s2;
        let frame = s1.seal(b"ctx", b"secret", NOW).unwrap();
        assert!(s2.open(b"ctx", &frame.bytes, NOW).is_err());
    }

    #[test]
    fn rotation_allows_old_and_new_psk_to_coexist() {
        let mut store = server_store();
        store.insert(Psk::new("prod-v2", [0x44; PSK_LEN]).unwrap());

        let mut rng = SeqRandom(1);
        let mut cache = HelloReplayCache::new();

        for psk in [client_psk(), Psk::new("prod-v2", [0x44; PSK_LEN]).unwrap()] {
            let (hs, hello) = ClientHandshake::start(psk, DEVICE, NOW, &mut rng).unwrap();
            let accepted = accept_client_hello(&store, &hello, DEVICE, NOW, &mut cache, &mut rng).unwrap();
            hs.finish(&accepted.response, NOW).unwrap();
        }
    }
}
