//! 跨语言引擎门面。
//!
//! 这一层存在的唯一理由：JNI / napi / wasm-bindgen 三个绑定层**不应该各自
//! 实现一遍「客户端状态怎么流转」「服务端会话表怎么查」**。那样做的话，
//! 三份实现迟早漂移，而漂移的表现是「Web 端能解开、安卓端解不开」——
//! 定位这种问题要同时在三个语言里下断点。
//!
//! 所以：状态机只在这里写一遍，绑定层只做「Rust 类型 ↔ 宿主语言类型」的搬运。
//!
//! ## 时间戳为什么由调用方传
//!
//! `now_ms` 一律由宿主传入，不在这里调系统时钟。原因有三：
//! 1. `wasm32-unknown-unknown` 上的 `SystemTime::now()` 不可靠，而 JS 侧
//!    `Date.now()` 是准的。
//! 2. 服务端可能想用「本机时钟 + 漂移补偿」，只有调用方知道该用哪个。
//! 3. 测试要能注入固定时间，否则时间戳窗口的用例没法写。

use std::collections::HashMap;

use crate::error::{CryptoError, Result};
use crate::handshake::{accept_client_hello, AcceptedHandshake, ClientHandshake, HelloReplayCache};
use crate::kdf::{OsRandom, RandomSource};
use crate::protocol::{aad_context, SESSION_ID_LEN};
use crate::psk::{Psk, PskStore};
use crate::session::Session;

/// 服务端会话表的软上限。
///
/// 超过之后 [`ServerEngine::accept`] 会先做一次全量清理；仍然超限就拒绝新建
/// 会话。没有这个上限的话，攻击者只要反复握手就能把服务端内存吃光 ——
/// 每次握手的成本几乎为零，而会话对象会一直留在表里。
pub const MAX_SERVER_SESSIONS: usize = 100_000;

/// 两次全表清理之间的最小间隔。
///
/// 清理是 O(n) 的 `retain`。放在每次 `accept` 里无条件执行的话，会话表接近上限
/// （10 万）时**每一次握手都要扫 10 万条** —— 攻击者只要持续发握手请求，就能用
/// 极低的成本把服务端 CPU 打满。限频之后，清理的摊销成本从「每握手 O(n)」
/// 变成「每秒 O(n)」。
///
/// 延迟清理没有正确性代价：过期会话在被访问时会顺手回收（见 `seal` / `open`），
/// 而且表满时仍然会强制清一次来腾位置。
const SWEEP_MIN_INTERVAL_MS: u64 = 30_000;

/// 客户端引擎：持有 PSK、握手中间态和已建立的会话。
///
/// 生命周期由宿主语言管理（JNI 是 long 句柄，wasm-bindgen / napi 是对象）。
#[derive(Debug)]
pub struct ClientEngine {
    psk: Psk,
    /// 本机设备号，握手时折进握手密钥派生（见 [`crate::kdf::derive_handshake_key`]）。
    device_id: Vec<u8>,
    pending: Option<ClientHandshake>,
    session: Option<Session>,
}

impl ClientEngine {
    /// `device_id` 是本机稳定标识（Android `ANDROID_ID`、Windows `MachineGuid`）；
    /// 无设备号的端（如 Web）传空串即退化为不绑定。
    pub fn new(psk_id: &str, psk_hex: &str, device_id: &str) -> Result<Self> {
        Ok(Self {
            psk: Psk::from_hex(psk_id, psk_hex)?,
            device_id: device_id.as_bytes().to_vec(),
            pending: None,
            session: None,
        })
    }

    /// 发起握手，返回要发给服务端的 ClientHello 字节。
    ///
    /// 会丢弃上一个未完成的握手状态 —— 允许调用方直接重试，不必先清理。
    pub fn handshake(&mut self, now_ms: u64) -> Result<Vec<u8>> {
        let mut rng = OsRandom;
        self.handshake_with(now_ms, &mut rng)
    }

    /// 同 [`ClientEngine::handshake`]，但允许注入随机源（测试用）。
    pub fn handshake_with<R: RandomSource>(&mut self, now_ms: u64, rng: &mut R) -> Result<Vec<u8>> {
        let (pending, hello) = ClientHandshake::start(self.psk.clone(), &self.device_id, now_ms, rng)?;
        self.pending = Some(pending);
        self.session = None;
        Ok(hello)
    }

    /// 处理 ServerHello，建立会话。
    ///
    /// 失败时会清掉 pending —— 留着它只会让下一次调用拿到一个语义不明的状态。
    pub fn finish(&mut self, server_hello: &[u8], now_ms: u64) -> Result<()> {
        let pending = self.pending.take().ok_or(CryptoError::SessionNotReady)?;
        let session = pending.finish(server_hello, now_ms)?;
        self.session = Some(session);
        Ok(())
    }

    /// 是否已经有一条可用的会话。
    pub fn has_session(&self, now_ms: u64) -> bool {
        self.session.as_ref().is_some_and(|s| !s.is_expired(now_ms))
    }

    /// 是否需要重新握手（过期、快过期或帧数接近上限）。
    pub fn needs_rekey(&self, now_ms: u64) -> bool {
        match &self.session {
            None => true,
            Some(session) => session.is_expired(now_ms) || session.needs_rekey(now_ms),
        }
    }

    /// 会话 ID 的十六进制；无会话时返回空串。
    pub fn session_id_hex(&self) -> String {
        self.session
            .as_ref()
            .map(Session::id_hex)
            .unwrap_or_default()
    }

    /// 会话剩余有效毫秒数；无会话时返回 0。
    pub fn session_remaining_ms(&self, now_ms: u64) -> u64 {
        self.session
            .as_ref()
            .map(|s| s.remaining_ms(now_ms))
            .unwrap_or(0)
    }

    /// 加密一个请求体。
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.session_mut(now_ms)?
            .seal(aad, plaintext, now_ms)
            .map(|f| f.bytes)
    }

    /// 解密一个响应体。
    pub fn open(&mut self, aad: &[u8], frame: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        self.session_mut(now_ms)?
            .open(aad, frame, now_ms)
            .map(|f| f.plaintext)
    }

    /// 取本端下一个发送序号，用于拼 `X-Taotao-Crypto` 头。
    ///
    /// 必须在 [`ClientEngine::seal`] **之后**调用 —— seal 会推进序号。
    pub fn last_sealed_header(&self, now_ms: u64) -> Result<String> {
        let session = self.session.as_ref().ok_or(CryptoError::SessionNotReady)?;
        if session.is_expired(now_ms) {
            return Err(CryptoError::SessionExpired);
        }
        // seal 已经把 next_seq 推进到「下一个」，所以刚发出去的那一帧是 next_seq - 1。
        let seq = session.next_seq_for_header().saturating_sub(1);
        Ok(session.header_value(seq))
    }

    /// 从刚封装出的帧反推 HTTP 头值。
    ///
    /// 之所以让调用方从**帧**反推而不是让 [`ClientEngine::seal`] 返回两个值：
    /// 四个绑定层里只有 wasm-bindgen 和 napi 能优雅地返回结构体，JNI 返回
    /// 多值要么建 Java 对象、要么拼字节数组，两边都容易出错。序号本来就写在
    /// 帧头里（明文的第 1..9 字节），从帧里读出来是最不容易错的方式。
    pub fn header_for_frame(&self, frame: &[u8]) -> Result<String> {
        let session = self.session.as_ref().ok_or(CryptoError::SessionNotReady)?;
        let (_version, seq, _ts) = Session::peek_header(frame)?;
        Ok(session.header_value(seq))
    }

    fn session_mut(&mut self, now_ms: u64) -> Result<&mut Session> {
        let session = self.session.as_mut().ok_or(CryptoError::SessionNotReady)?;
        if session.is_expired(now_ms) {
            return Err(CryptoError::SessionExpired);
        }
        Ok(session)
    }
}

/// 服务端引擎：持有 PSK 表、握手重放缓存和会话表。
#[derive(Debug)]
pub struct ServerEngine {
    psks: PskStore,
    hello_replay: HelloReplayCache,
    sessions: HashMap<[u8; SESSION_ID_LEN], Session>,
    /// 上次全表清理的时刻，用于限制清理频率（见 [`SWEEP_MIN_INTERVAL_MS`]）。
    last_sweep_ms: u64,
}

impl Default for ServerEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerEngine {
    pub fn new() -> Self {
        Self {
            psks: PskStore::new(),
            hello_replay: HelloReplayCache::new(),
            sessions: HashMap::new(),
            last_sweep_ms: 0,
        }
    }

    /// 加入 / 更新一条 PSK。轮换期可以同时持有多条。
    pub fn put_psk(&mut self, psk_id: &str, psk_hex: &str) -> Result<()> {
        self.psks.insert(Psk::from_hex(psk_id, psk_hex)?);
        Ok(())
    }

    /// 移除一条 PSK。返回是否真的移除了。
    pub fn remove_psk(&mut self, psk_id: &str) -> bool {
        self.psks.remove(psk_id)
    }

    /// 处理 ClientHello，返回 ServerHello，并把新会话登记进会话表。
    ///
    /// `device_id` 由外层传输携带（握手 HTTP 体里的字段），服务端用它折进握手
    /// 密钥派生。设备号与客户端不一致时 MAC 失配、握手被拒。
    pub fn accept(&mut self, client_hello: &[u8], device_id: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        let mut rng = OsRandom;
        self.accept_with(client_hello, device_id, now_ms, &mut rng)
    }

    pub fn accept_with<R: RandomSource>(
        &mut self,
        client_hello: &[u8],
        device_id: &[u8],
        now_ms: u64,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        // 清理放在最前面：否则「表满了」会在客户端已通过 MAC 校验之后才拒绝，
        // 白白消耗一次 X25519 运算。
        //
        // 但必须限频 —— 清理是 O(n) 的，无条件放在每次握手里等于给攻击者一个
        // 放大器：发一次握手就让服务端扫一遍整张会话表。表满时必须清（要腾
        // 位置），否则按固定间隔清就够了。
        let at_capacity = self.sessions.len() >= MAX_SERVER_SESSIONS;
        if at_capacity || now_ms.saturating_sub(self.last_sweep_ms) >= SWEEP_MIN_INTERVAL_MS {
            self.sweep_expired(now_ms);
            self.last_sweep_ms = now_ms;
        }
        if self.sessions.len() >= MAX_SERVER_SESSIONS {
            return Err(CryptoError::SessionNotReady);
        }

        let AcceptedHandshake { session, response } = accept_client_hello(
            &self.psks,
            client_hello,
            device_id,
            now_ms,
            &mut self.hello_replay,
            rng,
        )?;

        self.sessions.insert(session.id(), session);
        Ok(response)
    }

    /// 用会话 ID（十六进制）加密响应体。
    pub fn seal(
        &mut self,
        session_id_hex: &str,
        aad: &[u8],
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let id = parse_session_id(session_id_hex)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(CryptoError::SessionNotReady)?;
        if session.is_expired(now_ms) {
            // 顺手回收：过期会话继续留在表里只会白占内存。
            self.sessions.remove(&id);
            return Err(CryptoError::SessionExpired);
        }
        session.seal(aad, plaintext, now_ms).map(|f| f.bytes)
    }

    /// 用会话 ID（十六进制）解密请求体。
    pub fn open(
        &mut self,
        session_id_hex: &str,
        aad: &[u8],
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>> {
        let id = parse_session_id(session_id_hex)?;
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(CryptoError::SessionNotReady)?;
        if session.is_expired(now_ms) {
            self.sessions.remove(&id);
            return Err(CryptoError::SessionExpired);
        }
        session.open(aad, frame, now_ms).map(|f| f.plaintext)
    }

    /// 会话是否仍然有效。
    pub fn has_session(&mut self, session_id_hex: &str, now_ms: u64) -> bool {
        let Ok(id) = parse_session_id(session_id_hex) else {
            return false;
        };
        self.sessions
            .get(&id)
            .is_some_and(|s| !s.is_expired(now_ms))
    }

    /// 主动丢弃一条会话（例如客户端登出）。
    pub fn drop_session(&mut self, session_id_hex: &str) -> bool {
        let Ok(id) = parse_session_id(session_id_hex) else {
            return false;
        };
        self.sessions.remove(&id).is_some()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn psk_count(&self) -> usize {
        self.psks.len()
    }

    /// 清理过期会话。由 [`ServerEngine::accept`] 顺带调用。
    pub fn sweep_expired(&mut self, now_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_expired(now_ms));
        before - self.sessions.len()
    }
}

fn parse_session_id(hex_str: &str) -> Result<[u8; SESSION_ID_LEN]> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| CryptoError::SessionNotReady)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::SessionNotReady)
}

/// 构造 AAD 上下文，供绑定层直接调用，避免各语言自己拼字符串拼错。
///
/// 各语言侧拼错 AAD 的表现是「解密失败」，但错误信息里看不出是 AAD 的问题，
/// 所以把这个函数暴露到绑定层，强制调用方走同一条路径。
pub fn aad(method: &str, path_and_query: &str) -> Vec<u8> {
    aad_context(method, path_and_query)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const NOW: u64 = 1_700_000_000_000;
    /// 测试用设备号；客户端与服务端必须一致，握手才成立。
    const DEVICE: &str = "test-device-01";

    fn pair() -> (ClientEngine, ServerEngine) {
        let client = ClientEngine::new("prod-v1", PSK_HEX, DEVICE).unwrap();
        let mut server = ServerEngine::new();
        server.put_psk("prod-v1", PSK_HEX).unwrap();
        (client, server)
    }

    fn connect(client: &mut ClientEngine, server: &mut ServerEngine, now: u64) {
        let hello = client.handshake(now).unwrap();
        let response = server.accept(&hello, DEVICE.as_bytes(), now).unwrap();
        client.finish(&response, now).unwrap();
    }

    #[test]
    fn full_roundtrip_through_engine() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);

        assert!(client.has_session(NOW));
        assert!(!client.needs_rekey(NOW));
        assert_eq!(client.session_id_hex().len(), 32);
        assert_eq!(server.session_count(), 1);

        let aad = aad("POST", "/api/v1/playlists");
        let frame = client
            .seal(&aad, r#"{"name":"夜跑"}"#.as_bytes(), NOW)
            .unwrap();
        let header = client.last_sealed_header(NOW).unwrap();

        let (sid, seq) = Session::parse_header_value(&header).unwrap();
        assert_eq!(sid, client_session_id(&client));
        assert_eq!(seq, 1);

        let plaintext = server
            .seal_open_helper(client.session_id_hex().as_str(), &aad, &frame, NOW)
            .unwrap();
        assert_eq!(plaintext, r#"{"name":"夜跑"}"#.as_bytes());
    }

    fn client_session_id(client: &ClientEngine) -> [u8; SESSION_ID_LEN] {
        let bytes = hex::decode(client.session_id_hex()).unwrap();
        bytes.as_slice().try_into().unwrap()
    }

    /// 测试辅助：服务端 open。
    impl ServerEngine {
        fn seal_open_helper(
            &mut self,
            sid: &str,
            aad: &[u8],
            frame: &[u8],
            now: u64,
        ) -> Result<Vec<u8>> {
            self.open(sid, aad, frame, now)
        }
    }

    #[test]
    fn header_for_frame_matches_sealed_sequence() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);

        let aad = aad("GET", "/api/v1/favorites");
        for expected in 1..=3u64 {
            let frame = client.seal(&aad, b"{}", NOW).unwrap();
            let header = client.header_for_frame(&frame).unwrap();
            let (sid, seq) = Session::parse_header_value(&header).unwrap();
            assert_eq!(seq, expected);
            assert_eq!(sid, client_session_id(&client));
        }
    }

    #[test]
    fn header_for_frame_requires_session() {
        let (client, _server) = pair();
        assert_eq!(
            client.header_for_frame(&[0u8; 64]).unwrap_err(),
            CryptoError::SessionNotReady
        );
    }

    #[test]
    fn server_response_decrypts_on_client() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);

        let sid = client.session_id_hex();
        let resp = server
            .seal(&sid, &aad("200", "/api/v1/playlists"), b"ok", NOW)
            .unwrap();
        let plaintext = client
            .open(&aad("200", "/api/v1/playlists"), &resp, NOW)
            .unwrap();
        assert_eq!(plaintext, b"ok");
    }

    #[test]
    fn seal_without_session_fails() {
        let (mut client, _server) = pair();
        assert_eq!(
            client.seal(b"ctx", b"x", NOW).unwrap_err(),
            CryptoError::SessionNotReady
        );
        assert!(!client.has_session(NOW));
        assert!(client.needs_rekey(NOW));
        assert_eq!(client.session_id_hex(), "");
    }

    #[test]
    fn finish_without_handshake_fails() {
        let (mut client, _server) = pair();
        assert_eq!(
            client.finish(&[0u8; 109], NOW).unwrap_err(),
            CryptoError::SessionNotReady
        );
    }

    #[test]
    fn rehandshake_replaces_session() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        let first = client.session_id_hex();

        connect(&mut client, &mut server, NOW + 1000);
        let second = client.session_id_hex();
        assert_ne!(first, second);
        assert_eq!(
            server.session_count(),
            2,
            "旧会话仍在表里（另一个客户端可能还在用）"
        );

        // 旧会话 ID 在客户端已经不再被引用，但服务端还能用它解密 ——
        // 这是刻意的：并发请求可能在重握手之后才到达。
        assert!(server.has_session(&first, NOW + 1000));
    }

    #[test]
    fn unknown_session_id_is_rejected() {
        let (mut _client, mut server) = pair();
        let bogus = "00".repeat(SESSION_ID_LEN);
        assert!(!server.has_session(&bogus, NOW));
        assert_eq!(
            server.seal(&bogus, b"ctx", b"x", NOW).unwrap_err(),
            CryptoError::SessionNotReady
        );
        assert_eq!(
            server.open(&bogus, b"ctx", &[0u8; 64], NOW).unwrap_err(),
            CryptoError::SessionNotReady
        );
    }

    #[test]
    fn malformed_session_id_is_rejected() {
        let (_client, mut server) = pair();
        assert!(!server.has_session("not-hex", NOW));
        assert!(!server.has_session("", NOW));
        assert!(server.seal("0011", b"ctx", b"x", NOW).is_err());
    }

    #[test]
    fn expired_sessions_are_swept() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        assert_eq!(server.session_count(), 1);

        let later = NOW + 31 * 60 * 1000; // 超过 30 分钟默认有效期
        assert_eq!(server.sweep_expired(later), 1);
        assert_eq!(server.session_count(), 0);
    }

    #[test]
    fn accept_sweeps_expired_sessions_when_due() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        assert_eq!(server.session_count(), 1);

        // 既超过会话 TTL，也超过了清理间隔 —— 再握手时旧会话应被顺带清掉。
        // 这条锁住的是「限频不等于不清理」：清理被限频之后，如果哪天把
        // 「到期」判断改错，过期会话会一直堆在表里直到触顶。
        let later = NOW + 31 * 60 * 1000;
        let hello = client.handshake(later).unwrap();
        server.accept(&hello, DEVICE.as_bytes(), later).unwrap();
        assert_eq!(
            server.session_count(),
            1,
            "过期的旧会话应被清掉，只剩刚建的这条"
        );
    }

    #[test]
    fn expired_session_access_evicts_it() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        let sid = client.session_id_hex();

        let later = NOW + 31 * 60 * 1000;
        assert_eq!(
            server.seal(&sid, b"ctx", b"x", later).unwrap_err(),
            CryptoError::SessionExpired
        );
        // 访问过期会话会顺手回收，不用等下一次 sweep。
        assert_eq!(server.session_count(), 0);
    }

    #[test]
    fn client_expiry_is_reported() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        assert_eq!(client.session_remaining_ms(NOW), 30 * 60 * 1000);

        let later = NOW + 31 * 60 * 1000;
        assert!(!client.has_session(later));
        assert_eq!(client.session_remaining_ms(later), 0);
        assert_eq!(
            client.seal(b"ctx", b"x", later).unwrap_err(),
            CryptoError::SessionExpired
        );
    }

    #[test]
    fn psk_rotation_through_engine() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);

        server.put_psk("prod-v2", "ff".repeat(32).as_str()).unwrap();
        assert_eq!(server.psk_count(), 2);

        // 新客户端用 v2 也能握手（灰度期新旧并存）。
        let mut new_client = ClientEngine::new("prod-v2", "ff".repeat(32).as_str(), DEVICE).unwrap();
        connect(&mut new_client, &mut server, NOW + 1000);
        assert!(new_client.has_session(NOW + 1000));

        assert!(server.remove_psk("prod-v1"));
        assert!(!server.remove_psk("prod-v1"));
        assert_eq!(server.psk_count(), 1);
    }

    #[test]
    fn drop_session_works() {
        let (mut client, mut server) = pair();
        connect(&mut client, &mut server, NOW);
        let sid = client.session_id_hex();
        assert!(server.drop_session(&sid));
        assert!(!server.drop_session(&sid));
        assert_eq!(server.session_count(), 0);
    }

    #[test]
    fn server_rejects_hello_with_unknown_psk() {
        let mut server = ServerEngine::new();
        server.put_psk("prod-v1", PSK_HEX).unwrap();
        let mut client = ClientEngine::new("staging", &"aa".repeat(32), DEVICE).unwrap();
        let hello = client.handshake(NOW).unwrap();
        // 统一返回认证失败，而不是「不认识这个 psk_id」—— 后者会把 psk_id
        // 变成可以枚举的。详见 error.rs 里那段说明。
        assert_eq!(
            server.accept(&hello, DEVICE.as_bytes(), NOW).unwrap_err(),
            CryptoError::HandshakeAuthFailed
        );
        assert_eq!(server.session_count(), 0);
    }

    #[test]
    fn replayed_hello_creates_no_session() {
        let (mut client, mut server) = pair();
        let hello = client.handshake(NOW).unwrap();
        server.accept(&hello, DEVICE.as_bytes(), NOW).unwrap();
        assert_eq!(server.session_count(), 1);

        assert!(server.accept(&hello, DEVICE.as_bytes(), NOW).is_err());
        assert_eq!(server.session_count(), 1, "重放握手不能创建第二条会话");
    }

    #[test]
    fn aad_helper_matches_protocol() {
        assert_eq!(aad("GET", "/a"), crate::protocol::aad_context("GET", "/a"));
    }

    #[test]
    fn wrong_psk_hex_is_rejected_at_construction() {
        assert!(ClientEngine::new("prod", "not-hex", DEVICE).is_err());
        assert!(ClientEngine::new("prod", "0011", DEVICE).is_err());
        assert!(ClientEngine::new("", PSK_HEX, DEVICE).is_err());
    }
}
