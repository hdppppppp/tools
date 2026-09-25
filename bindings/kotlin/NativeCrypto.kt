// 桃桃音乐加密层 —— Kotlin 侧参考绑定。
//
// 这个文件**不在构建路径里**，是给接入方复制的参考实现。接入时把它放到
// `androidApp/src/main/java/com/taotao/music/crypto/` 下即可 ——
// 包名和类名必须与 Rust 侧的 JNI 符号严格对应：
//
//   Java_com_taotao_music_crypto_NativeCrypto_clientNew
//   └──┬─┘ └───┬────┘ └───┬──┘ └────┬────┘ └──┬──┘
//      │       │          │         │         └── 方法名（首字母大写）
//      │       │          │         └──────────── 类名
//      │       │          └────────────────────── 包名（点变下划线）
//      │       └───────────────────────────────── 固定前缀
//      └───────────────────────────────────────── 固定前缀
//
// 改包名或类名而忘了同步 Rust 侧，表现是 `UnsatisfiedLinkError`，
// 而且只在真机上出现（JVM 单元测试跑不到 native 方法）。

package com.taotao.music.crypto

/**
 * 加密层抛出的异常。
 *
 * 类名必须与 Rust 侧 `EXCEPTION_CLASS` 常量一致（`com/taotao/music/crypto/CryptoException`）。
 * 不一致时 `env.throw_new` 会静默失败，Rust 侧返回 null，
 * Kotlin 侧看到的是 `NullPointerException` 而不是真正的错误原因。
 */
class CryptoException(message: String) : RuntimeException(message)

/**
 * JNI 入口的原始声明。
 *
 * 全部是 `external` + `static`，与 Rust 侧的 `extern "system"` 函数一一对应。
 * **不要**直接调用这些方法 —— 用下面的 [TaotaoCryptoClient] / [TaotaoCryptoTokens]，
 * 它们负责句柄的分配与释放。直接调用的后果是句柄泄漏（native 内存，GC 管不到）。
 */
internal object NativeCrypto {

    /** 协议版本。用于校验 native 库与 App 版本是否匹配。 */
    external fun nativeVersion(): Int

    /**
     * 当前动态库里是否注入了真实 PSK。
     *
     * 返回 false 说明构建时没设 `TAOTAO_CRYPTO_PSK`，用的是源码里的占位密钥。
     * **发布包必须在启用加密前检查这个值并拒绝启动** ——
     * 占位密钥写在源码里，所有人都能算出来，静默用它上线比不加密还危险。
     */
    external fun nativeHasRealPsk(): Boolean

    /** 构造 AAD 上下文。不要自己拼字符串，拼接顺序错会导致解密失败且无从排查。 */
    external fun nativeAad(method: String, pathAndQuery: String): ByteArray

    // ---- 客户端 ----

    external fun clientNew(pskId: String, pskHex: String): Long
    external fun clientHandshake(handle: Long, nowMs: Long): ByteArray?
    external fun clientFinish(handle: Long, serverHello: ByteArray, nowMs: Long): Boolean
    external fun clientSeal(handle: Long, aad: ByteArray, plaintext: ByteArray, nowMs: Long): ByteArray?
    external fun clientOpen(handle: Long, aad: ByteArray, frame: ByteArray, nowMs: Long): ByteArray?
    external fun clientHeaderForFrame(handle: Long, frame: ByteArray): String?
    external fun clientSessionId(handle: Long): String
    external fun clientNeedsRekey(handle: Long, nowMs: Long): Boolean
    external fun clientSessionRemainingMs(handle: Long, nowMs: Long): Long
    external fun clientFree(handle: Long): Boolean

    // ---- 服务端 ----

    external fun serverNew(): Long
    external fun serverPutPsk(handle: Long, pskId: String, pskHex: String): Boolean
    external fun serverRemovePsk(handle: Long, pskId: String): Boolean
    external fun serverAccept(handle: Long, clientHello: ByteArray, nowMs: Long): ByteArray?
    external fun serverSeal(
        handle: Long,
        sessionIdHex: String,
        aad: ByteArray,
        plaintext: ByteArray,
        nowMs: Long,
    ): ByteArray?

    external fun serverOpen(
        handle: Long,
        sessionIdHex: String,
        aad: ByteArray,
        frame: ByteArray,
        nowMs: Long,
    ): ByteArray?

    external fun serverHasSession(handle: Long, sessionIdHex: String, nowMs: Long): Boolean
    external fun serverDropSession(handle: Long, sessionIdHex: String): Boolean
    external fun serverSessionCount(handle: Long): Long
    external fun serverSweepExpired(handle: Long, nowMs: Long): Long
    external fun serverFree(handle: Long): Boolean
}

/** 动态库名。Android 会去找 `libtaotao_crypto.so`，Windows 去找 `taotao_crypto.dll`。 */
private const val LIBRARY_NAME = "taotao_crypto"

/** HTTP 头名。 */
const val CRYPTO_HEADER = "X-Taotao-Crypto"

/**
 * 客户端加密通道。
 *
 * 一个实例对应一条加密会话，**应当长期持有并复用**：每次请求重新握手会让
 * X25519 的开销（约 50 微秒）叠在每个请求上，低端安卓机上足以造成可感知的卡顿。
 *
 * 线程安全说明：native 侧的句柄操作在 Rust 的 Mutex 上串行化，所以本类
 * 可以在多线程间共享。但同一个 [seal] 序列的序号是全局递增的，
 * 并发调用会得到乱序的序号 —— 这是允许的（服务端用滑窗容忍乱序），
 * 但如果调用方依赖「序号顺序 = 请求顺序」，需要自己加锁。
 */
class TaotaoCryptoClient(pskId: String, pskHex: String) : AutoCloseable {

    private var handle: Long = NativeCrypto.clientNew(pskId, pskHex)

    /** 当前会话 ID（十六进制）。无会话时为空串。 */
    val sessionId: String
        get() = NativeCrypto.clientSessionId(handle)

    /** 是否已有可用会话。 */
    fun hasSession(nowMs: Long = now()): Boolean = !NativeCrypto.clientNeedsRekey(handle, nowMs)

    /**
     * 是否需要重新握手。
     *
     * 服务端会在会话有效期走到 90% 时就让这里返回 true，避免过期瞬间的
     * 并发请求全部失败并各自触发重试握手（惊群）。
     */
    fun needsRekey(nowMs: Long = now()): Boolean = NativeCrypto.clientNeedsRekey(handle, nowMs)

    /** 会话剩余有效毫秒数。 */
    fun sessionRemainingMs(nowMs: Long = now()): Long =
        NativeCrypto.clientSessionRemainingMs(handle, nowMs)

    /** 发起握手，返回要发给服务端的 ClientHello。 */
    fun handshake(nowMs: Long = now()): ByteArray =
        NativeCrypto.clientHandshake(handle, nowMs)
            ?: throw CryptoException("握手发起失败")

    /** 处理 ServerHello，建立会话。 */
    fun finish(serverHello: ByteArray, nowMs: Long = now()) {
        if (!NativeCrypto.clientFinish(handle, serverHello, nowMs)) {
            throw CryptoException("握手认证失败")
        }
    }

    /** 加密请求体。 */
    fun seal(aad: ByteArray, plaintext: ByteArray, nowMs: Long = now()): ByteArray =
        NativeCrypto.clientSeal(handle, aad, plaintext, nowMs)
            ?: throw CryptoException("加密失败")

    /** 解密响应体。 */
    fun open(aad: ByteArray, frame: ByteArray, nowMs: Long = now()): ByteArray =
        NativeCrypto.clientOpen(handle, aad, frame, nowMs)
            ?: throw CryptoException("解密失败")

    /** 从刚加密出的帧反推 `X-Taotao-Crypto` 头值。 */
    fun headerForFrame(frame: ByteArray): String =
        NativeCrypto.clientHeaderForFrame(handle, frame)
            ?: throw CryptoException("构造加密头失败")

    override fun close() {
        if (handle != 0L) {
            NativeCrypto.clientFree(handle)
            handle = 0L
        }
    }

    companion object {
        init {
            // 加载失败时给出可操作的提示，而不是让 UnsatisfiedLinkError 裸奔。
            try {
                System.loadLibrary(LIBRARY_NAME)
            } catch (error: UnsatisfiedLinkError) {
                throw IllegalStateException(
                    "加载加密层动态库失败。安卓请确认 jniLibs/<abi>/lib$LIBRARY_NAME.so 已打包，" +
                        "Windows 请确认 $LIBRARY_NAME.dll 在 java.library.path 上。",
                    error,
                )
            }
        }

        fun now(): Long = System.currentTimeMillis()

        /** 构造 AAD。所有调用点都必须走这里。 */
        fun aad(method: String, pathAndQuery: String): ByteArray =
            NativeCrypto.nativeAad(method, pathAndQuery)

        /** 协议版本。 */
        val protocolVersion: Int get() = NativeCrypto.nativeVersion()

        /** 当前动态库是否注入了真实 PSK。发布包必须检查。 */
        val hasRealPsk: Boolean get() = NativeCrypto.nativeHasRealPsk()
    }
}

/**
 * 服务端加密通道（仅在服务端也用 JVM 跑时有用）。
 *
 * NestJS 后端请用 `crypto/node` 的 `.node` 扩展。
 */
class TaotaoCryptoTokens : AutoCloseable {

    private var handle: Long = NativeCrypto.serverNew()

    fun putPsk(pskId: String, pskHex: String) {
        if (!NativeCrypto.serverPutPsk(handle, pskId, pskHex)) {
            throw CryptoException("注册 PSK $pskId 失败")
        }
    }

    fun removePsk(pskId: String): Boolean = NativeCrypto.serverRemovePsk(handle, pskId)

    /** 处理 ClientHello，返回 ServerHello。 */
    fun accept(clientHello: ByteArray, nowMs: Long = now()): ByteArray =
        NativeCrypto.serverAccept(handle, clientHello, nowMs)
            ?: throw CryptoException("握手处理失败")

    fun seal(sessionIdHex: String, aad: ByteArray, plaintext: ByteArray, nowMs: Long = now()): ByteArray =
        NativeCrypto.serverSeal(handle, sessionIdHex, aad, plaintext, nowMs)
            ?: throw CryptoException("加密响应失败")

    fun open(sessionIdHex: String, aad: ByteArray, frame: ByteArray, nowMs: Long = now()): ByteArray =
        NativeCrypto.serverOpen(handle, sessionIdHex, aad, frame, nowMs)
            ?: throw CryptoException("解密请求失败")

    fun hasSession(sessionIdHex: String, nowMs: Long = now()): Boolean =
        NativeCrypto.serverHasSession(handle, sessionIdHex, nowMs)

    fun dropSession(sessionIdHex: String): Boolean =
        NativeCrypto.serverDropSession(handle, sessionIdHex)

    val sessionCount: Long get() = NativeCrypto.serverSessionCount(handle)

    fun sweepExpired(nowMs: Long = now()): Long = NativeCrypto.serverSweepExpired(handle, nowMs)

    override fun close() {
        if (handle != 0L) {
            NativeCrypto.serverFree(handle)
            handle = 0L
        }
    }

    companion object {
        fun now(): Long = System.currentTimeMillis()
    }
}

/**
 * 解析 `X-Taotao-Crypto` 头值。
 *
 * 返回 `null` 表示格式非法 —— 调用方应当直接返回 400，而不是尝试「容错解析」。
 * 容错解析会让格式错误的头被当成合法请求处理，掩盖客户端侧的 bug。
 */
fun parseCryptoHeader(value: String): Pair<String, Long>? {
    val parts = value.split('.')
    if (parts.size != 3) return null
    if (parts[0] != "v1") return null
    if (parts[1].length != 32) return null
    if (!parts[1].all { it.isDigit() || it in 'a'..'f' }) return null
    val seq = parts[2].toLongOrNull() ?: return null
    return parts[1] to seq
}
