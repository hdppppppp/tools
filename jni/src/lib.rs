//! JNI 绑定：一份代码同时供 Android 与 Windows 使用。
//!
//! ## 为什么桌面端也走 JNI
//!
//! 桃桃音乐的 Windows 客户端是 Compose Desktop，运行在 JVM 上。它和 Android
//! 需要的是**同一个** JNI 接口，区别只有编译目标：
//!
//! | 平台 | 目标三元组 | 产物 |
//! | --- | --- | --- |
//! | Android arm64 | `aarch64-linux-android` | `libtaotao_crypto.so` |
//! | Android x86_64（模拟器） | `x86_64-linux-android` | `libtaotao_crypto.so` |
//! | Windows x64 | `x86_64-pc-windows-msvc` | `taotao_crypto.dll` |
//!
//! 同一份 Rust 源码、同一套 Kotlin 声明、同一组测试向量。这是选 JNI 而不是
//! JNA 的全部理由 —— 换成 JNA 就要多维护一套 C 头文件和一层 C ABI 门面。
//!
//! ## jni 0.22 的 API 形态（升级时必读）
//!
//! 0.22 把 `JNIEnv` 拆成了两层，这是破坏性改动：
//!
//! - **`EnvUnowned<'local>`**：native 方法参数里收到的那个，只是 FFI 安全的裸指针
//!   包装，**没有任何 JNI 方法**。直接调 `env.new_string(...)` 会报
//!   「no method named `new_string` found for `&mut EnvUnowned`」。
//! - **`Env<'local>`**：真正的 JNI 方法都在这里，通过
//!   `EnvUnowned::with_env(|env| ...)` 临时借出来。
//!
//! 另外 `JNIEnv` 现在只是 `EnvUnowned` 的废弃别名，照着 0.21 的示例写会编译失败。
//!
//! ## 错误与 panic 的处理
//!
//! `with_env` 内部已经用 `catch_unwind` 包住了闭包，所以 panic 不会跨 FFI 边界
//! （跨 FFI 的 panic 是未定义行为）。但它的 `resolve::<P>()` 需要一个
//! `ErrorPolicy`，而内置的 `ThrowRuntimeExAndDefault` 要求返回值实现 `Default` ——
//! `jbyteArray` 是裸指针，没有 `Default`。
//!
//! 所以这里用 [`run`] 做了一层包装：闭包统一返回 `Result<()>`，
//! 真正的返回值通过外层局部变量带出来。这样 `resolve` 只需要处理 `()`，
//! 而我们的领域错误在闭包内部就被转成了 Java 异常。

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
use jni::{jni_str, Env, EnvUnowned};
use taotao_crypto_core::{aad, ClientEngine, CryptoError, ServerEngine};

/// 领域错误统一转成这个 Java 异常类。
///
/// 类名必须与 Kotlin 侧 `CryptoException` 的全限定名一致。
/// **不一致时 `throw_new` 会静默失败** —— Rust 侧返回 null，
/// Kotlin 侧看到的是 `NullPointerException` 而不是真正的错误原因。
fn throw_crypto(env: &mut Env<'_>, message: &str) -> jni::errors::Result<()> {
    env.throw_new(
        jni_str!("com/taotao/music/crypto/CryptoException"),
        JNIString::new(message),
    )
}

/// 统一的 FFI 入口包装。
///
/// 三件事：借出 `Env`、把领域错误转成 Java 异常、给 panic 兜底。
/// `fallback` 是「没能产出值」时返回给 Java 的东西（通常是 null / false / 0）。
///
/// 闭包返回 `Result<()>` 而不是 `Result<T>` 是刻意的：`resolve` 要求的
/// `Default` 约束对裸指针不成立，把真正的返回值放到闭包外面带出来就绕开了它。
///
/// 参数取 `&mut EnvUnowned` 而不是按值消费：`EnvUnowned` 不是 `Copy`，
/// 而调用方（native 方法）拿到的就是它本身，按值传会让每个入口都要多写一次
/// 所有权转移。`with_env` 本来就只需要 `&mut self`。
fn run<'local, T>(
    env: &mut EnvUnowned<'local>,
    fallback: T,
    body: impl FnOnce(&mut Env<'local>) -> Result<T, CryptoError>,
) -> T {
    let mut produced: Option<T> = None;

    env.with_env(|env| -> jni::errors::Result<()> {
        match body(env) {
            Ok(value) => produced = Some(value),
            Err(err) => {
                // 只把 Display 传出去。协议内部细节（期望的 MAC、密钥字节）
                // 不进异常消息 —— 异常消息会进日志和崩溃上报。
                throw_crypto(env, &err.to_string())?;
            }
        }
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();

    // panic 时 produced 仍是 None，走 fallback。
    produced.unwrap_or(fallback)
}

// ---------------------------------------------------------------------------
// 句柄注册表
// ---------------------------------------------------------------------------

/// 注册表条目。
enum Entry {
    Client(ClientEngine),
    Server(ServerEngine),
}

static REGISTRY: OnceLock<Mutex<HashMap<i64, Entry>>> = OnceLock::new();
/// 句柄分配器。从 1 开始，0 保留给「空句柄」。
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn registry() -> &'static Mutex<HashMap<i64, Entry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn insert(entry: Entry) -> jlong {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    // Mutex 中毒说明另一个线程在持锁时 panic 了。这里选择恢复而不是传播：
    // 注册表的数据结构没有被破坏，继续用比让整个加密层瘫痪要好。
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(handle, entry);
    handle
}

/// 在注册表上执行一段操作，拿到对应句柄的条目。
///
/// 句柄无效时返回 `None`，由调用方决定降级行为（通常是返回错误）。
fn with_entry<T>(handle: jlong, f: impl FnOnce(&mut Entry) -> T) -> Option<T> {
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.get_mut(&handle).map(f)
}

fn remove_entry(handle: jlong) -> bool {
    let mut guard = registry().lock().unwrap_or_else(|e| e.into_inner());
    guard.remove(&handle).is_some()
}

// ---------------------------------------------------------------------------
// 类型转换辅助
// ---------------------------------------------------------------------------

/// Java String → Rust String。JString 的 Display 实现不会失败。
fn read_string(value: &JString<'_>) -> String {
    value.to_string()
}

/// Java byte[] → Vec<u8>。空数组或 null 都返回空 Vec。
fn read_bytes(env: &mut Env<'_>, value: JByteArray<'_>) -> Vec<u8> {
    env.convert_byte_array(value).unwrap_or_default()
}

/// Vec<u8> → Java byte[]。
fn write_bytes(env: &mut Env<'_>, value: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(value) {
        Ok(array) => array.into_raw(),
        Err(err) => {
            // 这里的失败是 JNI 层面的（比如内存不足），抛出去让 Java 侧看到。
            let _ = throw_crypto(env, &format!("构造字节数组失败：{err}"));
            core::ptr::null_mut()
        }
    }
}

/// Rust String → Java String。
fn write_string(env: &mut Env<'_>, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(err) => {
            let _ = throw_crypto(env, &format!("构造字符串失败：{err}"));
            core::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// 元信息
// ---------------------------------------------------------------------------

/// 协议版本。Kotlin 侧据此判断 native 库是否与当前 App 版本匹配。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_nativeVersion<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jint {
    taotao_crypto_core::PROTOCOL_VERSION as jint
}

/// 当前动态库里是否注入了真实 PSK。
///
/// 返回 false 说明构建时没设 `TAOTAO_CRYPTO_PSK`，用的是占位密钥。
/// 发布包必须据此拒绝启用加密 —— 占位密钥写在源码里，所有人都能算出来。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_nativeHasRealPsk<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jboolean {
    run(&mut env, JNI_FALSE, |_env| {
        let (_, is_real) = taotao_crypto_core::build_psk_or_placeholder("__probe__")?;
        Ok(if is_real { JNI_TRUE } else { JNI_FALSE })
    })
}

/// 构造 AAD 上下文。各语言侧必须走这个函数，不要自己拼字符串。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_nativeAad<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    method: JString<'local>,
    path_and_query: JString<'local>,
) -> jbyteArray {
    let method = read_string(&method);
    let path = read_string(&path_and_query);
    run(&mut env, core::ptr::null_mut(), |env| {
        Ok(write_bytes(env, &aad(&method, &path)))
    })
}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// 创建客户端引擎。`pskHex` 必须是 64 个十六进制字符。`deviceId` 是本机稳定标识
/// （Android ANDROID_ID），折进握手密钥；无设备号传空串即不绑定。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientNew<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    psk_id: JString<'local>,
    psk_hex: JString<'local>,
    device_id: JString<'local>,
) -> jlong {
    let psk_id = read_string(&psk_id);
    let psk_hex = read_string(&psk_hex);
    let device_id = read_string(&device_id);
    run(&mut env, 0, |_env| {
        Ok(insert(Entry::Client(ClientEngine::new(
            &psk_id, &psk_hex, &device_id,
        )?)))
    })
}

/// 发起握手，返回 ClientHello 字节。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientHandshake<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    now_ms: jlong,
) -> jbyteArray {
    run(&mut env, core::ptr::null_mut(), |env| {
        let now = now_ms.max(0) as u64;
        let hello = with_entry(handle, |entry| match entry {
            Entry::Client(client) => client.handshake(now),
            Entry::Server(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &hello))
    })
}

/// 处理 ServerHello，建立会话。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientFinish<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    server_hello: JByteArray<'local>,
    now_ms: jlong,
) -> jboolean {
    run(&mut env, JNI_FALSE, |env| {
        let hello = read_bytes(env, server_hello);
        let now = now_ms.max(0) as u64;
        // 握手失败必须让 Java 侧看到异常，否则调用方会以为会话建好了，
        // 后续每个请求都拿到「会话未建立」这种更远的错误。
        //
        // `?` 在这里就完成了这件事：失败会被 `run` 的包装转成
        // CryptoException 抛回 Java。成功时 `finish` 返回的就是 `()`，
        // 所以不需要（也不该）再绑定一个变量出来 —— 那只会让读者以为
        // 这个返回值后面还要用到。
        with_entry(handle, |entry| match entry {
            Entry::Client(client) => client.finish(&hello, now),
            Entry::Server(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(JNI_TRUE)
    })
}

/// 加密请求体，返回帧字节。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientSeal<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
    now_ms: jlong,
) -> jbyteArray {
    run(&mut env, core::ptr::null_mut(), |env| {
        let aad = read_bytes(env, aad);
        let plaintext = read_bytes(env, plaintext);
        let now = now_ms.max(0) as u64;
        let frame = with_entry(handle, |entry| match entry {
            Entry::Client(client) => client.seal(&aad, &plaintext, now),
            Entry::Server(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &frame))
    })
}

/// 解密响应体。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientOpen<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    aad: JByteArray<'local>,
    frame: JByteArray<'local>,
    now_ms: jlong,
) -> jbyteArray {
    run(&mut env, core::ptr::null_mut(), |env| {
        let aad = read_bytes(env, aad);
        let frame = read_bytes(env, frame);
        let now = now_ms.max(0) as u64;
        let plaintext = with_entry(handle, |entry| match entry {
            Entry::Client(client) => client.open(&aad, &frame, now),
            Entry::Server(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &plaintext))
    })
}

/// 从帧反推 `X-Taotao-Crypto` 头值。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientHeaderForFrame<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    frame: JByteArray<'local>,
) -> jstring {
    run(&mut env, core::ptr::null_mut(), |env| {
        let frame = read_bytes(env, frame);
        let header = with_entry(handle, |entry| match entry {
            Entry::Client(client) => client.header_for_frame(&frame),
            Entry::Server(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_string(env, &header))
    })
}

/// 会话 ID（十六进制）。无会话时返回空串。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientSessionId<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let id = with_entry(handle, |entry| match entry {
        Entry::Client(client) => client.session_id_hex(),
        Entry::Server(_) => String::new(),
    })
    .unwrap_or_default();
    run(&mut env, core::ptr::null_mut(), |env| {
        Ok(write_string(env, &id))
    })
}

/// 是否需要重新握手。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientNeedsRekey<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    now_ms: jlong,
) -> jboolean {
    let now = now_ms.max(0) as u64;
    let needs = with_entry(handle, |entry| match entry {
        Entry::Client(client) => client.needs_rekey(now),
        // 句柄无效时保守地返回 true：调用方会重新握手，
        // 而不是拿着一个坏会话继续跑。
        Entry::Server(_) => true,
    })
    .unwrap_or(true);
    if needs {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// 会话剩余有效毫秒数。无会话返回 0。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientSessionRemainingMs<
    'local,
>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    now_ms: jlong,
) -> jlong {
    let now = now_ms.max(0) as u64;
    with_entry(handle, |entry| match entry {
        Entry::Client(client) => client.session_remaining_ms(now) as jlong,
        Entry::Server(_) => 0,
    })
    .unwrap_or(0)
}

/// 释放客户端引擎。必须调用，否则泄漏。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_clientFree<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    if remove_entry(handle) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

/// 创建服务端引擎。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverNew<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jlong {
    insert(Entry::Server(ServerEngine::new()))
}

/// 加入 / 更新一条 PSK。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverPutPsk<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    psk_id: JString<'local>,
    psk_hex: JString<'local>,
) -> jboolean {
    let psk_id = read_string(&psk_id);
    let psk_hex = read_string(&psk_hex);
    run(&mut env, JNI_FALSE, |_env| {
        with_entry(handle, |entry| match entry {
            Entry::Server(server) => server.put_psk(&psk_id, &psk_hex),
            Entry::Client(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(JNI_TRUE)
    })
}

/// 移除一条 PSK。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverRemovePsk<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    psk_id: JString<'local>,
) -> jboolean {
    let id = read_string(&psk_id);
    let removed = with_entry(handle, |entry| match entry {
        Entry::Server(server) => server.remove_psk(&id),
        Entry::Client(_) => false,
    })
    .unwrap_or(false);
    if removed {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// 处理 ClientHello，返回 ServerHello。新会话会自动登记进会话表。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverAccept<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    client_hello: JByteArray<'local>,
    device_id: JString<'local>,
    now_ms: jlong,
) -> jbyteArray {
    let device_id = read_string(&device_id);
    run(&mut env, core::ptr::null_mut(), |env| {
        let hello = read_bytes(env, client_hello);
        let now = now_ms.max(0) as u64;
        let response = with_entry(handle, |entry| match entry {
            Entry::Server(server) => server.accept(&hello, device_id.as_bytes(), now),
            Entry::Client(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &response))
    })
}

/// 加密响应体。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverSeal<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    session_id_hex: JString<'local>,
    aad: JByteArray<'local>,
    plaintext: JByteArray<'local>,
    now_ms: jlong,
) -> jbyteArray {
    let sid = read_string(&session_id_hex);
    run(&mut env, core::ptr::null_mut(), |env| {
        let aad = read_bytes(env, aad);
        let plaintext = read_bytes(env, plaintext);
        let now = now_ms.max(0) as u64;
        let frame = with_entry(handle, |entry| match entry {
            Entry::Server(server) => server.seal(&sid, &aad, &plaintext, now),
            Entry::Client(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &frame))
    })
}

/// 解密请求体。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverOpen<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    session_id_hex: JString<'local>,
    aad: JByteArray<'local>,
    frame: JByteArray<'local>,
    now_ms: jlong,
) -> jbyteArray {
    let sid = read_string(&session_id_hex);
    run(&mut env, core::ptr::null_mut(), |env| {
        let aad = read_bytes(env, aad);
        let frame = read_bytes(env, frame);
        let now = now_ms.max(0) as u64;
        let plaintext = with_entry(handle, |entry| match entry {
            Entry::Server(server) => server.open(&sid, &aad, &frame, now),
            Entry::Client(_) => Err(CryptoError::SessionNotReady),
        })
        .unwrap_or(Err(CryptoError::SessionNotReady))?;
        Ok(write_bytes(env, &plaintext))
    })
}

/// 会话是否仍然有效。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverHasSession<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    session_id_hex: JString<'local>,
    now_ms: jlong,
) -> jboolean {
    let sid = read_string(&session_id_hex);
    let now = now_ms.max(0) as u64;
    let has = with_entry(handle, |entry| match entry {
        Entry::Server(server) => server.has_session(&sid, now),
        Entry::Client(_) => false,
    })
    .unwrap_or(false);
    if has {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// 主动丢弃一条会话。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverDropSession<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    session_id_hex: JString<'local>,
) -> jboolean {
    let sid = read_string(&session_id_hex);
    let dropped = with_entry(handle, |entry| match entry {
        Entry::Server(server) => server.drop_session(&sid),
        Entry::Client(_) => false,
    })
    .unwrap_or(false);
    if dropped {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// 当前会话数量，用于监控与容量告警。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverSessionCount<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jlong {
    with_entry(handle, |entry| match entry {
        Entry::Server(server) => server.session_count() as jlong,
        Entry::Client(_) => 0,
    })
    .unwrap_or(0)
}

/// 清理过期会话，返回清理掉的条数。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverSweepExpired<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    now_ms: jlong,
) -> jlong {
    let now = now_ms.max(0) as u64;
    with_entry(handle, |entry| match entry {
        Entry::Server(server) => server.sweep_expired(now) as jlong,
        Entry::Client(_) => 0,
    })
    .unwrap_or(0)
}

/// 释放服务端引擎。
#[no_mangle]
pub extern "system" fn Java_com_taotao_music_crypto_NativeCrypto_serverFree<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    if remove_entry(handle) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
