# 008 · 全局传输层加密（Rust 多目标）

| 项 | 值 |
| --- | --- |
| 严重度 | 高 |
| 状态 | **模块已实现并通过测试；未接入任何现有链路**（按需求「先写好加密，先不着急接入」） |
| 依赖 | 无。不阻塞 005 / 006 / 007，也不被它们阻塞 |
| 代码 | 独立仓库 [`hdppppppp/tools`](https://github.com/hdppppppp/tools)（Rust workspace，4 个 crate） |
| 文档 | 本文件 + 仓库根的 `README.md` |
| 构建 | GitHub Actions（`.github/workflows/`），本地无需安装任何交叉编译环境 |

> **位置说明**：本文档随加密层一起维护在独立仓库
> [`hdppppppp/tools`](https://github.com/hdppppppp/tools)。
> 主项目的 `plans/008-rust-crypto-layer.md` 保留一份快照作为项目计划记录，
> **最新版本以本仓库为准**。

---

## 一、目标与边界

### 要解决的问题

1. **防篡改 + 防重放**。抓包改参数、重放请求是当前 API 最容易被滥用的两条路径。
2. **载荷加密**。请求/响应体的明文内容（歌曲直链、用户资料、歌单名）不该被
   旁路轻易读到。
3. **抬高逆向门槛**。让「抓包 + 改脚本模拟请求」从半小时的工作量变成需要
   逆向 native 库。

### 明确不做

| 不做的事 | 原因 |
| --- | --- |
| 加密音频流（`/songs/:id/play`） | 代理的是几百 MB 的流，逐块 AEAD 让 CPU 占用翻倍，而音频本身没有秘密 —— 秘密是**直链**，直链在服务端到上游那一段 |
| 加密大文件上传（APK / jar / 补丁） | 同上，吞吐换不到安全收益 |
| 替代 TLS | 这是应用层的第二道防线，不是用来在明文 HTTP 上裸奔的 |
| 保护上游音源直链 | 那是服务端到 QQ/网易/酷我那一段的隔离问题，客户端加密只是其中一环，需单独方案 |
| 追求「密钥不可提取」 | 随客户端分发的密钥理论上一定能被提取。见第五节，目标是把成本从「grep 十六进制字符串」抬到「写脚本逆向」 |

---

## 二、为什么是 Rust + 四个目标

四个运行环境（Android JVM、Windows JVM、Node、浏览器）各自有成熟的加密库。
选「一份 Rust 实现 + 四个绑定」而不是「各端用各自的库」，核心理由只有一条：

> **协议漂移的表现是「某个端解不开」，而排查它要同时在四个语言里下断点。**

HKDF 的 info 字符串多一个斜杠、AAD 拼接顺序差一个字节、序号从 0 还是从 1 开始 ——
这类错误在单一实现里是编译期或测试期就能发现的，跨四个语言就是线上事故。

配套的两个收益：

- **纯 Rust 依赖链**。`chacha20poly1305` / `x25519-dalek` / `hkdf` 都是纯 Rust，
  没有 C 依赖。换成 `ring` 或 `openssl` 会立刻卡在 `wasm32-unknown-unknown`
  和 NDK 的链接上 —— 这是能不能同时出四个产物的硬约束。
- **Windows 端复用 JNI**。桌面端是 Compose Desktop（JVM），与 Android 需要
  同一个 JNI 接口，只是编译目标不同。选 JNA 就要多维护一套 C 头文件。

### 产物矩阵

| 目标 | 三元组 | 产物 | 绑定 |
| --- | --- | --- | --- |
| Android arm64-v8a | `aarch64-linux-android` | `libtaotao_crypto.so` | JNI |
| Android x86_64 | `x86_64-linux-android` | `libtaotao_crypto.so` | JNI |
| Windows x64 | `x86_64-pc-windows-msvc` | `taotao_crypto.dll` | JNI |
| 后端 | 本机三元组 | `taotao_crypto.node` | napi-rs |
| Web | `wasm32-unknown-unknown` | `taotao_crypto_bg.wasm` + JS 胶水 | wasm-bindgen |

---

## 三、协议

### 3.1 算法选型

| 用途 | 算法 | 理由 |
| --- | --- | --- |
| 密钥协商 | **X25519** | 32 字节密钥、无需参数校验、恒定时间实现成熟 |
| 认证加密 | **ChaCha20-Poly1305** | 见下 |
| 密钥派生 | **HKDF-SHA256** | 标准、无状态、info 参数天然支持域分离 |
| 握手认证 | **HMAC-SHA256** | 只用来证明「你持有 PSK」 |
| 随机数 | 系统源 | Android `getrandom(2)` / Windows `BCryptGenRandom` / 浏览器 `crypto.getRandomValues` |

**为什么不用 AES-256-GCM**：

- Web 端没有 AES 硬件指令，纯软件 AES 在 wasm 上比 ChaCha20 慢一大截；
  ChaCha20 是纯 ARX 运算，在 wasm 上几乎不损失性能。
- 安卓碎片化：老机型没有 ARMv8 Crypto 扩展时会退化到查表实现，
  存在缓存计时侧信道。ChaCha20 没有 S 盒查表，天然抗时序攻击。

### 3.2 握手（1-RTT）

```
客户端                                        服务端
  │  ClientHello                                │
  │  {ver, psk_id, cnonce(16), C_eph_pub(32),   │
  │   ts_ms(8), MAC(32)}                        │
  │────────────────────────────────────────────▶│ ① 查 psk_id → PSK
  │                                             │ ② 校验 ts 在 ±5 分钟窗口内
  │                                             │ ③ 校验 MAC（HMAC-SHA256）
  │                                             │ ④ 校验 cnonce 未见过
  │                                             │ ⑤ 生成 S_eph / session_id
  │  ServerHello                                │
  │  {ver, session_id(16), cnonce(16),          │
  │   S_eph_pub(32), ts_ms(8), ttl(4), MAC(32)} │
  │◀────────────────────────────────────────────│
  │ ⑥ 校验 MAC、校验 cnonce 与己方一致            │
  │                                             │
  │ K  = X25519(己方临时私钥, 对方临时公钥)        │
  │ PRK = HKDF-Extract(salt = cnonce, K)        │
  │ k_c2s = HKDF-Expand(PRK, "…/key/c2s" ‖ sid) │
  │ k_s2c = HKDF-Expand(PRK, "…/key/s2c" ‖ sid) │
```

**三个关键设计点**：

1. **cnonce 必须回显且绑定**。它是防握手重放的核心：攻击者录下完整的一对
   ClientHello/ServerHello 后原样重发，如果没有 nonce 绑定，服务端会认下这次
   握手并派生出**同一个**会话密钥 —— 攻击者就能解密该会话的流量。绑定之后
   重放的 ClientHello 会被服务端的 nonce 缓存挡在 MAC 校验之后。
2. **握手密钥与数据密钥隔离**。PSK 不直接参与加密，先经 HKDF 派生握手密钥。
   不隔离的话，握手 MAC 就成了数据密钥的已知明文对。
3. **双向密钥必须不同**。`c2s` 和 `s2c` 用不同 info 派生。共用一条密钥的话，
   服务端加密的响应可以被原样当作客户端请求发回来（反射攻击），而 MAC 合法。

**低阶点防护**：X25519 收到低阶公钥会让共享秘密落进极小的子群，从而把密钥
空间缩到可穷举。`was_contributory()` 检查失败直接拒绝握手。

### 3.3 数据帧

```text
偏移  长度  字段
0     1     version
1     8     seq        会话内单调递增
9     8     ts_ms      Unix 毫秒
17    12    nonce      每帧随机，绝不复用
29    N     ciphertext
29+N  16    tag
```

**AAD = session_id(16) ‖ aad_context ‖ frame_header(17)**

三段各有分工：

- `session_id` 是纵深防御。密钥本已按会话隔离，但放进 AAD 后「帧被搬到另一个
  会话」会在认证层就失败，而不是依赖「密钥不同」这个间接推论。
- `aad_context` = `"{METHOD} {PATH}?{QUERY}"`。**必须含方法和查询串**：
  只绑路径的话 `GET /playlists/{id}` 和 `DELETE /playlists/{id}` 共享同一个 AAD，
  攻击者能把读请求的密文改发成删除请求；不含查询串的话，攻击者可以保留密文
  只改 `page` 参数来遍历数据。
- `frame_header` 让序号和时间戳自身也受认证保护，攻击者改不动序号来绕过重放滑窗。

### 3.4 防重放的三层

| 层 | 机制 | 窗口 |
| --- | --- | --- |
| 时间戳 | 帧/握手的时间戳与本地时钟比对 | ±5 分钟 |
| 握手 nonce 缓存 | 服务端记 `cnonce`，见过即拒 | 10 分钟（2× 时间戳窗口） |
| 会话序号滑窗 | 64 位位图，容忍乱序，拒绝重复与过旧 | 每会话 |

**为什么序号用滑窗而不是「只记最大值」**：HTTP 请求会并发，序号 5 的响应可能
比序号 4 先到。只记最大值会把迟到的 4 误判成重放，表现为「偶发请求失败」，
且极难复现。

**校验顺序是刻意的**：解密 → 时间戳 → 防重放。
- 时间戳**不能**排在解密前面 —— 它在帧头里，而帧头是 AAD 的一部分，在 AEAD
  校验通过之前它只是攻击者可以随意改的字节。用未经认证的时间戳做拒绝决策，
  等于白送对方一个丢弃开关。代价是每帧付一次 AEAD 解密，换一个可信的时间戳。
- 防重放放最后，因为只有解密成功才值得占用滑窗位置；否则攻击者能拿伪造帧
  把滑窗填满，把真帧挤成「重放」。
- 同理，服务端的 nonce 缓存插入放在 MAC 校验**之后**，否则伪造 hello 能灌满缓存
  （内存耗尽 + 拒绝服务）。

### 3.5 会话生命周期

- 默认 TTL **30 分钟**，服务端可在 ServerHello 里下发更短值。
- **提前 10% 有效期就要求 rekey**。等真正过期才换的话，过期瞬间的并发请求会
  全部失败并各自触发一次重试握手，形成惊群。
- 单会话帧数上限 **2^24**。ChaCha20-Poly1305 用 96 位**随机** nonce 时按生日界
  约 2^32 个消息后碰撞概率不可忽略，留两个数量级余量。达到上限主动 rekey ——
  nonce 复用会直接摧毁机密性（异或出明文），且完全没有报错。
- 服务端会话表上限 **10 万**，超限先全量清理再拒绝新建。没有上限的话，
  攻击者反复握手就能吃光内存（每次握手成本几乎为零）。

---

## 四、密钥管理

### 4.1 PSK + ECDH 组合

| 方案 | 问题 |
| --- | --- |
| 纯 PSK | 密钥硬编码在客户端，提取即永久失效；且无前向保密 —— 录下历史流量后拿到 PSK 就能解密全部历史 |
| 纯 ECDH | 中间人可各自与两端握手，服务端无法区分真客户端和转发的中间人 |
| **PSK + ECDH** | PSK 给握手加 HMAC 证明身份，X25519 协商每次会话不同的数据密钥。PSK 泄漏的影响被限制在「可冒充客户端握手」，已录制的历史流量仍安全（前向保密） |

### 4.2 轮换（无需停服、无需同时升级两端）

1. 服务端**先加上**新 PSK（此时表里有新旧两条）。
2. 客户端陆续切到新 PSK，按 `psk_id` 握手，服务端都能认。
3. 确认没有客户端再用旧 id 后，服务端移除旧 PSK。

服务端侧提供 `put_psk` / `remove_psk`，PSK 表支持同 id 覆盖（这正是轮换时
更新密钥的路径）。测试 `rotation_allows_old_and_new_psk_to_coexist` 覆盖了
新旧并存期。

### 4.3 从主种子派生

`derive_psk_from_seed(seed, psk_id)` 让一套主密钥管理多套环境（dev / staging /
prod），换 `psk_id` 就得到互不相通的密钥。避免「测试环境的密钥泄漏导致生产
可被解密」。

### 4.4 注入方式

**开发构建**：不设任何东西，退回源码里的占位密钥，并且
`hasRealPsk()` / `has_real_psk()` / `nativeHasRealPsk()` **如实返回 `false`**。
发布包必须据此拒绝启用加密 —— 静默用一个所有人相同的占位密钥上线，比不加密
还危险。

**发布构建**：`TAOTAO_CRYPTO_PSK`（64 个十六进制字符）→ `core/build.rs` →
编译进产物。四个产物的 PSK 必须相同。

---

## 五、抗逆向：能做到什么，做不到什么

### 必须先说清楚的

**随客户端分发的密钥理论上一定能被提取。** 有物理设备的人总能跑 Frida、
dump 内存、反汇编代码段。任何声称「密钥不可提取」的方案都是在骗自己。

所以这里的目标是**把提取成本从「grep 一下 hex 字符串」抬到「需要写脚本逆向
拼装逻辑」**。

### 具体手段

| 手段 | 效果 |
| --- | --- |
| **PSK 不落明文常量**。构建期拆成 4 片，每片独立异或掩码、片序逆置 | `strings` / 十六进制搜索直接失效 |
| **掩码用编译期固定值**而非随机值 | 保持可复现构建。随机会让同版本号的两个包内容不同，破坏「按 sha256 寻址」的更新链路 |
| **零化**（`zeroize`）。密钥用完即擦 | 降低内存 dump 命中率 |
| **派生隔离**。PSK 从不直接参与加密 | 即使拿到内存中的会话密钥，也推不出 PSK |
| **`strip = "symbols"` + `lto = "fat"`** | 剥掉静态符号表（逆向时用来还原函数名和调用关系的那份数据）；动态符号表保留，否则 cdylib 根本加载不了 |
| **字符串混淆**（`cryptify`，编译期加密）。客户端产物开 `obfuscate` feature，服务端不开 | 协议标签与错误文案不再以明文出现。`时间戳超出允许窗口：偏差 {} ms` 这类文案等于直接告诉逆向者「此处做了防重放时间窗校验」。密钥经 `CRYPTIFY_KEY` 注入；**固定密钥**同样是为可复现构建 —— 见下一节 |
| **`opt-level = 3`**（**不是**抗逆向手段，仅作记录） | 为性能而选：`"z"` 实测让握手慢 **29 倍**（6029 µs → 205 µs），代价是产物 +18.1%。见 `README.md` 第六节 |

> **修正**：这张表早期曾把 `opt-level = "z"` 列为抗逆向手段（「体积最小化，
> 顺带让控制流更难读」）。该主张**已被实测证伪** —— `"z"` 只是让控制流难读，
> 不是混淆，对提取 PSK 的成本几乎没有抬升；而它把握手拖慢了 29 倍。
> 现在 `opt-level` 是纯粹的**性能开关**，与本节主题无关，保留在此仅为避免
> 后人再次误读。

### 字符串混淆：用 `cryptify`，只给客户端开

**为什么是 `cryptify`。** 它是 MIT 许可的编译期字符串加密宏 —— 这一点是硬条件，
`goldberg` 那类能做控制流平坦化的宏库是 GPL-3.0，作为**库**链接进产物会让整个
App 变 GPL（编译器类工具如 OLLVM 不污染产物，链接 GPL 库才污染，这个区别是关键）。
更关键的是它**支持固定密钥**：密钥取自 `CRYPTIFY_KEY`，缺省用内置固定值。若密钥
每次构建随机，同版本号的两个包内容就会不同，直接破坏上一行说的「按 sha256 寻址」
的更新链路。实测（wasm32-unknown-unknown，连编两次比对 sha256）确认可复现。

**接入点**：`core/src/obf.rs`。开启 `obfuscate` feature 时 `obf!` 走编译期加密，
关闭时退化为 `String`。**两个分支返回同一类型**是刻意的 —— 否则调用点的类型会随
feature 漂移，而这类问题只在 CI 的某一种配置里暴露。

**服务端侧刻意不做混淆。** `.node` 只在服务器上加载、不对外分发，混淆它等于白付
每次调用的解密开销，还会让排障时的错误文案变得不可读。所以 `node/Cargo.toml`
**不**给 core 开 `obfuscate`，而 `jni`（`.so`/`.dll`）与 `wasm` 开。这个分界由
`tools/check-obfuscated.sh` 在 CI 上守着：客户端产物里出现明文协议标签或错误文案
就直接构建失败 —— 因为「feature 没接上」是静默失败，构建、测试、上传全都正常。

**哪些没能覆盖，以及为什么。** 这一节的诚实部分 —— 混淆不是万能的：

| 残留 | 来源 | 为什么去不掉 |
| --- | --- | --- |
| `core/src/frame.rs` 等**本项目源码路径** | `panic!` 的 `Location` 常量 | `strip` 只剥符号表，不剥 Location 字符串。stable 无 `-Z location-detail=none`，而 `panic = "abort"` 又被绑定层的 `catch_unwind` 挡住 |
| `/rustc/<commit>/...` | 预编译 std 的 rlib | `--remap-path-prefix` 改不到已经编进 rlib 的路径 |
| registry 依赖的**精确版本号** | 同上，来自 `panic!` 的 `Location` | 同上 |
| `psk_blob.rs` 的几条错误文案 | 该文件被 `build.rs` 用 `#[path]` 共用 | 构建脚本里不存在 `crate::obf`，`obf!` 编译不过。而且 `SHARD_COUNT` / `MASKS` 本身就是编译期常量，已经把分片方案写在二进制里，藏文案不改变攻击者已知的信息量 |
| `X-Taotao-Crypto` 头名 | `protocol::HEADER_NAME` | 它在**每一次请求的 HTTP 头里明文传输**，混淆二进制里的那份没有意义；而且它是公开 API |
| 绑定层（`jni`/`wasm`）自己的文案 | 例如 `nowMs 必须是有限的非负数` | 这些消息**在运行期返回给宿主语言**（Java 异常 / JS 错误），调用方本来就能看到 |

用量化工具确认残留：`python tools/scan-leaks.py <产物>`，它按七类分别列出条数。
**不要**把这些残留加进 `check-obfuscated.sh` 的断言 —— 那会让检查永远为红，
进而被无视，比没有检查更糟。

**还能做什么但没做。** 真正的控制流混淆（平坦化、间接跳转）需要 LLVM pass 层面的
介入：`0xlane/ollvm-rust` 那条路要 nightly（`-Zllvm-plugins`）、要插件与 rustc 的
LLVM 版本严格匹配，且它的字符串加密 pass **在 Rust 上不生效**（上游已知问题）。
收益与维护成本不成比例，暂不做。

---

## 六、四个绑定

### 6.1 状态机只写一遍

`core/src/engine.rs` 提供 `ClientEngine` / `ServerEngine`，三个绑定层**只做类型
搬运**，不含任何协议逻辑。这是整个设计里最重要的结构决定 —— 三个语言各实现
一遍状态流转，漂移是必然的。

### 6.2 JNI（Android `.so` + Windows `.dll`）

- 类名 `com.taotao.music.crypto.NativeCrypto`，导出 **24 个**
  `Java_com_taotao_music_crypto_NativeCrypto_*` 符号（已用 PE 导出表实测校验）。
- 跨 FFI 只能传整数，所以用 `long` 作句柄指向内部注册表。
  **必须显式 `clientFree` / `serverFree`** —— JNI 层看不到 Java GC，做不到自动回收。
- **jni crate 0.22 是破坏性重构**：`JNIEnv` 被拆成 `EnvUnowned`（FFI 安全，无方法）
  和 `Env`（真正的方法在这），必须 `env.with_env(|env| ...)` 才能用。
  照着 0.21 的示例写会报「no method named `new_string` found for `&mut EnvUnowned`」。
- **错误与 panic 的处理**：`with_env` 内部已经 `catch_unwind`，但它的
  `resolve::<P>()` 要求返回值实现 `Default` —— 裸指针没有。所以用一层 `run`
  包装：闭包统一返回 `Result<()>`，真正的返回值通过外层局部变量带出来。

> ⚠️ 这也是 workspace 的 release profile **不能**设 `panic = "abort"` 的原因。
> abort 下 `catch_unwind` 完全失效，一次数组越界就会把整个进程带走，用户看到
> 的是应用闪退且没有任何 Java 栈信息。体积代价约 40KB（unwind 表），换可诊断性
> 值得。这条已经写进 `Cargo.toml` 的注释里。

### 6.3 napi-rs（`.node`）

- 导出 `Client` / `Server` 两个类 + 4 个自由函数。
- **`.node` 是平台相关的**。部署到 Linux 必须在 Linux 上构建，不能复用本机
  Windows 产物。CI 和 `package.json` 的 `files` 字段都要覆盖。
- `build.rs` 里的 `napi_build::setup()` 不能少：缺了它编译能过、`require()`
  也不报错，但导出对象是空的，所有方法都是 `undefined is not a function`。

### 6.4 wasm-bindgen（`.wasm`）

- **Web 端是公开的**，分享页 `s/{token}` 任何人都能打开、代码可以随便读。
  所以：**不要把服务端 PSK 编进 wasm**。分享页只需要调公开接口，不需要握手。
  真要给分享页加密，应该用「匿名会话 + 短时效令牌」。
- `now_ms` 必须由 JS 传 `Date.now()`。**不要**在 Rust 里调 `SystemTime::now()`：
  `wasm32-unknown-unknown` 没有系统时钟，旧版本直接 panic，新版本返回 0 ——
  而返回 0 会让所有帧因「时间戳超窗」被拒，表现为「Web 端握手成功但每个请求
  都失败」。
- `getrandom` 的 `js` feature 只能由 `wasm/Cargo.toml` 开启，不能写在 core 里
  —— core 还要给安卓和 Windows 用，在那边开 `js` 会让它们编译失败。

### 6.5 时间戳一律由宿主传入

四个绑定都要求调用方传 `now_ms`，不在 core 里读系统时钟。三个理由：
wasm 上时钟不可靠、服务端可能需要漂移补偿、测试要能注入固定时间。

---

## 七、与现有契约的边界

加密层当前**没有接入任何现有链路**，所以下面这些契约暂时都不受影响。
但接入时必须逐条核对 —— 每一条都能悄无声息地弄坏线上功能。

| 现有契约（见 RELEASE.md 第七节） | 加密层接入时的约束 |
| --- | --- |
| `/search` 必须是**裸 NDJSON** | NDJSON 要逐行 flush，**不能**整体加密。搜索结果要么走明文，要么逐行加密（协议需扩展） |
| 歌词默认必须是 `text/plain` 裸文本 | 同上，纯文本响应不能整体加密 |
| 访问令牌无效必须 401 不能 403 | 加密层的「会话过期」错误必须映射到 **401**（触发客户端重新握手 + 续期），不能借用 403 |
| 业务错误不能借用 401 | 「解密失败」「帧认证失败」是**请求本身有问题**，应映射到 **400**，绝不能借 401 —— 那会把用户踢回登录页 |
| `/app/bootstrap` 永远不能返回 401 | 该接口必须豁免加密，或加密失败时降级为明文 |
| `coverUrl` / `apkUrl` 必须免鉴权绝对 https | 这些是客户端直接交给图片库/下载器的，**不能**套加密 |
| 线上有装机客户端 | 见第八节 |

### 必须豁免的端点

1. **流式响应**：`/search`（NDJSON）、歌词（`text/plain`）、音频代理
2. **二进制上传**：APK / jar / 补丁包（`RAW_BODY_PATHS` 里那 5 条）
3. **静态资源**：`/admin`、`/share`、`/s/{token}`
4. **图片/下载直链**：`coverUrl` / `apkUrl`
5. **健康检查**：`/health`

---

## 八、上线策略（未来接入时）

按需求，本次**只交付模块，不接入**。真正接入时建议的路径：

### 阶段 1 · 服务端就绪（对现有客户端零影响）

服务端引入 `taotao_crypto.node`，但**只做能力声明**：

- 新增 `X-Taotao-Crypto-Supported: 1` 响应头，告诉客户端服务端支持加密。
- 不改变任何现有端点的行为。老客户端完全不感知。
- 用「影子模式」跑：服务端对支持加密的请求**尝试解密并记录结果**，
  但不因解密失败而拒绝 —— 先验证协议在真实流量下没问题。

### 阶段 2 · 客户端灰度

- 客户端新增能力，但**默认关闭**，由服务端下发的开关控制。
- 开关粒度按「用户分桶」而不是「全局」：出问题只影响一个桶，可以立刻关掉。
- 只在**幂等的 GET 接口**上先开。写接口等 GET 全绿之后再放。

### 阶段 3 · 全量

- 所有支持加密的端点默认加密。
- 服务端保留「明文通道」至少一个发布周期 —— 老客户端还在用。

### 回滚

服务端的开关是唯一的回滚点，且**不需要发版**。这是选择「服务端双通道 +
版本协商」而不是「一刀切」的全部理由。

---

## 九、实现状态

### 已完成并实测验证

| 项 | 位置 | 验证方式 |
| --- | --- | --- |
| 协议核心（9 个模块） | `core/src/` | **87 项单元测试全绿** |
| JNI 绑定（24 个导出） | `jni/src/lib.rs` | 编译 + PE 导出表校验（24/24 保留） |
| napi 绑定 | `node/src/lib.rs` | **Node 端到端跑通**（见下） |
| wasm 绑定 | `wasm/src/lib.rs` | **wasm 端到端跑通**（见下） |
| 构建脚本（4 目标 + 符号校验 + 版本校验） | `tools/build.ps1` | 实际执行 |
| 参考绑定（Kotlin / Node TS / wasm TS） | `bindings/` | 未编译（无接入环境） |

### 实测产物

| 目标 | 产物 | 体积 | 状态 |
| --- | --- | --- | --- |
| Windows x64 | `taotao_crypto.dll` | 390,656 字节 | 已构建，导出符号已校验 |
| 后端 | `taotao_crypto.node` | 361,472 字节 | 已构建，端到端跑通 |
| Web | `taotao_crypto_bg.wasm` + JS 胶水 | 103,233 字节 | 已构建，端到端跑通 |
| Android arm64 / x86_64 | `libtaotao_crypto.so` | — | **未构建**（本机无 NDK） |

### 端到端验证（Node 与 wasm 各跑一遍，断言相同）

1. 握手成功，会话 ID 两侧一致
2. 请求方向加密/解密往返正确（含中文 UTF-8）
3. 响应方向加密/解密往返正确
4. **重放帧被拒**（`检测到重放：序号 1 已处理过`）
5. **跨端点重放被拒**（把密文改发到 `DELETE /playlists/1` → `帧认证失败`，证明 AAD 绑定生效）
6. **错误 PSK 握手被拒**（`握手认证失败`）
7. `has_real_psk()` 在开发构建下如实返回 `false`

### 开发过程中发现并修掉的三个真问题

这三个都是「编译能过、日志正常、但线上会静默出错」的类型，值得记录：

1. **PSK 分片编解码漂移**。`build.rs` 的注释写着「逆序存放」而代码是顺序存放，
   解码器按逆序读 —— **生产密钥会还原错，所有客户端握不上手**。
   根因是编解码分散在两处、只靠注释约定。修法是抽成 `core/src/psk_blob.rs`
   单一来源（构建脚本用 `#[path]` 加载同一文件），并补一条**已知答案向量**测试。

2. **`panic = "abort"` 会摧毁 JNI 的错误处理**。JNI 和 napi 都靠 `catch_unwind`
   把 Rust panic 转成宿主语言异常；abort 下 panic 直接杀进程，一次数组越界
   就是应用闪退且无任何 Java 栈信息。已改为 `panic = "unwind"` 并在
   `Cargo.toml` 里写明原因。

3. **同一 workspace 里三个 cdylib 撞名**。`jni` / `node` / `wasm` 都叫
   `taotao_crypto`，在 `target/release/deps` 下撞名，链接期报
   `LNK1104: cannot open file ...taotao_crypto.dll`。已加 `_jni` / `_node` /
   `_wasm` 后缀，交付名由构建脚本在拷贝时改。

另外两条环境层面的坑（不是代码问题，但会浪费排查时间）：

4. `cargo test --doc` 在 Windows 上稳定撞 `ERROR_NO_DATA`（"所有的管道范例都在
   使用中"），让测试套件永远不绿。已把文档示例改成 `text` 代码块，
   正确性由等价的单元测试保证。
5. `wasm-bindgen` CLI 版本与 `Cargo.lock` 不匹配时，命令**返回 0、只打一句
   含糊警告、一个文件都不产出**。构建脚本已加显式版本比对。

### 尚未做

| 项 | 说明 |
| --- | --- |
| **接入任何现有链路** | 按需求刻意不做 |
| **Android `.so` 实际构建** | 本机无 NDK。构建脚本已就绪，装好 NDK 后 `-Target android` 即可 |
| **Kotlin / TS 包装层的编译验证** | 三个包装层是参考实现，没有接入环境可编译 |
| **跨语言一致性测试向量** | 目前 Node 与 wasm 各跑一遍同样的断言，但不是同一份「固定输入→固定输出」的向量文件。接入前应补 |
| **运行时 PSK 注入** | 服务端目前也是构建期注入 |
| **逐行加密（NDJSON）** | 协议未覆盖流式响应 |

> **性能基准已完成**（2026-09-25）：`cargo bench -p taotao-crypto-core`，
> 同时量耗时与堆分配次数。结果与结论见 `README.md` 第六节。
> 最重要的一条：`opt-level = "z"` 曾让握手慢 **29 倍**（6029 µs → 205 µs），
> 已改为 `opt-level = 3`，代价是产物 +20%。

---

## 十、接入时的调用形态（参考，未实现）

### Android / Windows（Kotlin）

```kotlin
// 一次性初始化
val crypto = TaotaoCryptoClient(pskId = "prod-v1", pskHex = BuildConfig.CRYPTO_PSK)
if (!TaotaoCryptoNative.hasRealPsk()) {
    // 发布包走到这里说明构建时漏设了 TAOTAO_CRYPTO_PSK
    throw IllegalStateException("加密层未注入真实密钥")
}

// 会话建立（内部缓存，过期前自动重握手）
if (crypto.needsRekey()) {
    val hello = crypto.handshake()
    val serverHello = postRaw("/api/v1/crypto/handshake", hello)
    crypto.finish(serverHello)
}

// 每个请求
val aad = TaotaoCryptoNative.aad("POST", "/api/v1/favorites")
val frame = crypto.seal(aad, bodyBytes)
connection.setRequestProperty("X-Taotao-Crypto", crypto.headerForFrame(frame))
connection.setRequestProperty("Content-Type", "application/octet-stream")
connection.outputStream.write(frame)
```

### 后端（TypeScript / NestJS）

```ts
import { Client, Server, aadContext } from "../native/taotao_crypto.node";

const server = new Server();
server.putPsk("prod-v1", process.env.TAOTAO_CRYPTO_PSK!);

// 握手端点
@Post("crypto/handshake")
@Public()
handshake(@Body() body: Buffer) {
  return server.accept(body, Date.now());   // 返回 ServerHello
}

// 全局拦截器里解密（豁免端点见第七节）
const [sessionId] = parseHeader(request.headers["x-taotao-crypto"]);
const aad = aadContext(request.method, request.originalUrl);
request.body = JSON.parse(server.open(sessionId, aad, rawBody, Date.now()).toString());
```

---

## 十一、需要人工确认的决策点

1. **PSK 是否接受构建期注入**。当前实现只支持构建期（客户端没得选）。
   服务端如果要求从密钥管理服务在运行时读，需要加一条运行时注入路径。
2. **接入范围**。第七节列了 5 类必须豁免的端点，实际豁免清单要在接入时
   逐条核对 —— 漏一条的表现是「某个功能静默失效」。
3. **性能预算**。已实测（见 `README.md` 第六节）：握手 205 µs，1 KB 帧
   封装/解封各 2.37 µs，64 KB 帧 68.5 µs / 48.8 µs，每帧 1 次堆分配。
   **这些是 x86_64 桌面数字**，低端安卓机通常还要再慢 3～10 倍，
   对首屏的实际影响仍需在真机上量。已经能确定的一条：不要把
   `opt-level` 退回 `"z"` —— 实测会让握手慢 29 倍。
4. **`X-Taotao-Crypto` 头的名字**。当前用的是这个，与现有 `X-Admin-Token`
   的命名习惯一致（后者已废弃）。
