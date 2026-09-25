# 桃桃音乐传输层加密模块

**一份 Rust 协议实现，四个平台绑定门面，四类产物。**

客户端与后端之间的请求/响应体，在应用层再加一道认证加密。目标不是「密钥不可提取」，
而是把「抓包读明文、改参数重放」从半小时的体力活，变成需要真正理解协议、
提取密钥、重建握手才能做到的事。

| 目标 | 产物 | 绑定方式 | 由谁消费 |
| --- | --- | --- | --- |
| Android | `libtaotao_crypto.so`（arm64-v8a / x86_64） | JNI | `androidApp` |
| Windows | `taotao_crypto.dll` | JNI | `desktopApp`（Compose Desktop 是 JVM） |
| 后端 | `taotao_crypto.node`（Linux x64 / Windows x64） | napi-rs | `server` |
| Web | `taotao_crypto_bg.wasm` + JS 胶水 | wasm-bindgen | `webApp` 分享播放器 |

> 本文讲**协议本身**：为什么这样设计、每个字段在防什么。
> 威胁模型与选型辩护见 [`SECURITY.md`](SECURITY.md)，
> 完整设计（上线灰度、与现有契约的边界、调用形态）见 [`docs/design.md`](docs/design.md)。

---

## 一、它保护什么，不保护什么

**保护**：载荷机密性、参数完整性、重放拒绝、中间人替换公钥。

**不保护**：反编译客户端后提取 PSK（PSK 模型的固有性质，见 §5.5）、
内存转储、流量分析、服务端被完全攻陷。

具体到桃桃音乐，它挡的是这几类实际风险：

| 风险 | 手段 |
| --- | --- |
| 抓包读到歌曲直链、用户资料、歌单名 | ChaCha20-Poly1305 加密请求/响应体 |
| 改请求参数（比如把 `page` 改大遍历数据） | AEAD 认证标签 + AAD 绑定查询串 |
| 把读请求的密文改发成删除请求 | AAD 里含 HTTP 方法 |
| 录下请求原样重放 | 时间戳窗口 + 握手 nonce 缓存 + 序号滑窗 |
| 把 A 端点的密文搬到 B 端点 | AAD 绑定 `"{METHOD} {PATH}?{QUERY}"` |
| 中间人各自与两端握手 | PSK 参与握手 HMAC，没有 PSK 算不出合法 MAC |
| 长期密钥泄露后解密历史流量 | 每次握手生成临时 X25519 密钥对，前向保密 |

---

## 二、协议

### 2.1 算法选型

| 用途 | 算法 | 为什么 |
| --- | --- | --- |
| 密钥协商 | **X25519** | 32 字节密钥、无需参数校验、常量时间实现成熟 |
| 认证加密 | **ChaCha20-Poly1305** | 见下 |
| 密钥派生 | **HKDF-SHA256** | 标准、无状态、`info` 参数天然支持域分离 |
| 握手认证 | **HMAC-SHA256** | 只用来证明「你持有 PSK」 |
| 常量时间比较 | `subtle` crate | 手写比较会引入时序侧信道 |
| 随机数 | 系统源 | Android `getrandom(2)` / Windows `BCryptGenRandom` / 浏览器 `crypto.getRandomValues` |

#### 为什么是 ChaCha20-Poly1305 而不是 AES-256-GCM

两个原因都与「要同时跑在四个目标上」直接相关：

1. **WebAssembly 里没有 AES 硬件指令。** wasm 的 SIMD 里没有 AES-NI 等价物，
   AES 在浏览器里只能走软件实现 —— 慢，而且实现质量取决于编译器版本。
   ChaCha20 是纯 ARX 运算（加、异或、循环移位），在 wasm 上几乎不损失性能。
2. **老安卓机型上 AES 会退化成查表实现。** 没有 ARMv8 Crypto 扩展的设备上，
   软件 AES 通常用 T 表实现，而 T 表查表的访存地址与密钥相关 ——
   这是经典的缓存计时侧信道（Bernstein 2005）。ChaCha20 没有 S 盒查表，
   天然常量时间。

代价：在有 AES-NI 的现代 x86 上 ChaCha20 比 AES-GCM 慢一些。但本场景的载荷是
几十 KB 的 JSON，不是音频流 —— 这个差距完全无所谓。

### 2.2 握手（1-RTT）

```
客户端                                          服务端
  │  ClientHello                                  │
  │  {ver, psk_id, cnonce(16), C_eph_pub(32),     │
  │   ts_ms(8), MAC(32)}                          │
  │──────────────────────────────────────────────▶│ ① 查 psk_id → PSK
  │                                               │ ② 校验 ts 在 ±5 分钟窗口内
  │                                               │ ③ 校验 MAC（HMAC-SHA256）
  │                                               │ ④ 校验 cnonce 未见过
  │                                               │ ⑤ 生成 S_eph / session_id
  │  ServerHello                                  │
  │  {ver, session_id(16), cnonce(16),            │
  │   S_eph_pub(32), ts_ms(8), ttl(4), MAC(32)}   │
  │◀──────────────────────────────────────────────│
  │ ⑥ 校验 MAC、校验 cnonce 与己方一致              │
  │                                               │
  │ K   = X25519(己方临时私钥, 对方临时公钥)         │
  │ PRK = HKDF-Extract(salt = cnonce, K)          │
  │ k_c2s = HKDF-Expand(PRK, "…/key/c2s" ‖ sid)   │
  │ k_s2c = HKDF-Expand(PRK, "…/key/s2c" ‖ sid)   │
```

握手报文是**固定布局的二进制**，不是 JSON —— 长度在 `core/src/protocol.rs` 里
以常量固化（`CLIENT_HELLO_MIN_LEN`、`SERVER_HELLO_LEN`），
`frame_layout_constants_are_consistent` 测试会断言它们自洽。

三个关键设计点：

**① cnonce 必须回显且参与派生。** 这是防握手重放的核心。攻击者录下完整的一对
ClientHello/ServerHello 后原样重发 —— 如果 nonce 不绑定，服务端会认下这次握手
并派生出**同一个**会话密钥，攻击者就能解密该会话的全部流量。把 cnonce 作为
HKDF 的 salt 并让服务端回显校验之后，重放的 hello 会被 nonce 缓存挡在 MAC 校验之后。

**② 握手密钥与数据密钥隔离。** PSK 不直接参与加密，先经 HKDF 派生握手密钥。
不隔离的话，握手 MAC 就成了数据密钥的已知明文对。

**③ 双向密钥必须用不同 info 派生。** 共用一条密钥的话，服务端加密的响应
可以被原样当作客户端请求发回来（反射攻击），而 MAC 是合法的。

**低阶点防护**：X25519 收到低阶公钥会让共享秘密落进极小的子群，把密钥空间
缩到可穷举。`was_contributory()` 检查失败直接拒绝握手。

### 2.3 数据帧

```text
偏移   长度   字段
0      1     version
1      8     seq        会话内单调递增
9      8     ts_ms      Unix 毫秒
17     12    nonce      每帧随机，绝不复用
29     N     ciphertext
29+N   16    tag
```

HTTP 头 `X-Taotao-Crypto` 承载 `v1.<session_id 十六进制>.<seq>`，
服务端据此定位会话；帧体就是上表这段字节，直接当请求体发出去。

#### AAD 的三段，各有分工

```
AAD = session_id(16) ‖ aad_context ‖ frame_header(17)
```

- **`session_id`** 是纵深防御。密钥本来已经按会话隔离了，但放进 AAD 之后，
  「帧被搬到另一个会话」会在认证层直接失败，而不是依赖「密钥不同」这个间接推论。
- **`aad_context` = `"{METHOD} {PATH}?{QUERY}"`**，例如 `POST /api/v1/favorites`。
  必须含**方法**：只绑路径的话 `GET /api/v1/playlists/{id}` 和
  `DELETE /api/v1/playlists/{id}` 共享同一个 AAD，攻击者能把读请求的密文
  改发成删除请求。必须含**查询串**：分页和搜索关键字都在 query 里，
  不绑的话攻击者可以保留密文只改 `page` 参数来遍历数据。
- **`frame_header`** 让序号和时间戳自身也受认证保护 —— 否则攻击者改掉序号
  就能绕过重放滑窗。

响应方向的上下文由调用方按同样规则构造，通常是 `"{STATUS} {PATH}"`。

### 2.4 防重放的三层

| 层 | 机制 | 窗口 |
| --- | --- | --- |
| 时间戳 | 帧/握手的时间戳与本地时钟比对 | ±5 分钟 |
| 握手 nonce 缓存 | 服务端记 `cnonce`，见过即拒 | 10 分钟（2× 时间戳窗口） |
| 会话序号滑窗 | 64 位位图，容忍乱序，拒绝重复与过旧 | 每会话 |

**为什么序号用滑窗而不是「只记最大值」**：HTTP 请求会并发，序号 5 的响应
可能比序号 4 先到。只记最大值会把迟到的 4 误判成重放，表现为「偶发请求失败」，
且极难复现。

**校验顺序是刻意的：解密 → 时间戳 → 防重放。**

- **时间戳不可能排在解密前面。** 它就在帧头里，而帧头是 AAD 的一部分 ——
  在 AEAD 校验通过之前，它只是一个未经认证的、由攻击者提供的数字。拿它做
  拒绝决策等于白送对方一个丢弃开关。代价是每一帧都要付一次 AEAD 解密，
  换来一个可信的时间戳。
  （想省这次解密，只能用 `Session::peek_header` 读**未认证**的时间戳做廉价
  预筛 —— 比如明显超出窗口的直接丢。但那只是优化，最终判断仍在解密之后。）
- 防重放放**最后**，因为只有解密成功才值得占用滑窗位置。反过来的话，
  攻击者能拿大量伪造帧把滑窗填满，合法帧反而被当成重放拒掉。
- 同理，服务端的 nonce 缓存插入放在 **MAC 校验之后** —— 否则攻击者用垃圾
  hello 就能把缓存灌满（内存耗尽 + 拒绝服务），合法客户端反而建不了会话。

### 2.5 会话生命周期

| 参数 | 值 | 理由 |
| --- | --- | --- |
| 会话 TTL | 30 分钟 | 够长以避免频繁握手，够短以限制单会话密钥的暴露窗口 |
| 提前 rekey | 剩余 10% 时 | 避免 TTL 到期瞬间所有客户端同时重握手（惊群） |
| 单会话帧上限 | 2^24（约 1677 万） | nonce 生日界，见下 |
| 时间戳窗口 | ±5 分钟 | 容忍设备时钟漂移，同时限制重放窗口 |
| 握手 nonce 缓存 | 10 分钟 | 覆盖时间戳窗口的两倍 |
| 服务端会话表上限 | 100,000 | 防内存耗尽 |

**为什么单会话有 2^24 帧上限**：帧 nonce 是 96 位**随机**值，碰撞概率按生日界
估算 —— 用 2^32 个帧时碰撞概率约 2^-33（已经在「值得担心的工程风险」范围内），
2^24 个帧时约 2^-49（可忽略）。所以留两个数量级余量。达到上限主动 rekey，
而不是继续用到出问题：**nonce 复用会直接摧毁机密性（异或出明文），
而且完全没有报错**。

**为什么服务端会话表要设上限**：每次握手的成本几乎为零，没有上限的话攻击者
反复握手就能吃光内存。超限时先全量清理再拒绝新建。

---

## 三、密钥管理

### 3.1 为什么是 PSK + ECDH 而不是二者之一

| 方案 | 问题 |
| --- | --- |
| 纯 PSK | 密钥硬编码在客户端，提取即永久失效；**无前向保密** —— 录下历史流量后拿到 PSK 就能解密全部历史 |
| 纯 ECDH | 中间人可各自与两端握手，服务端无法区分真客户端和转发的中间人 |
| **PSK + ECDH** | PSK 给握手加 HMAC 证明身份，X25519 协商每次会话不同的数据密钥。PSK 泄漏的影响被限制在「可冒充客户端握手」，已录制的历史流量仍然安全 |

这正是「握手用 HMAC-SHA256 认证 + 数据用协商出的会话密钥加密」这个组合的原因。

### 3.2 轮换：不停服、不同时升级两端

1. 服务端**先加上**新 PSK（此时表里新旧两条并存）。
2. 客户端陆续切到新 PSK，按 `psk_id` 握手，服务端两条都能认。
3. 确认没有客户端再用旧 id 之后，服务端移除旧 PSK。

服务端侧提供 `put_psk` / `remove_psk`，PSK 表支持同 id 覆盖 ——
这正是轮换时更新密钥的路径。测试 `rotation_allows_old_and_new_psk_to_coexist`
覆盖了新旧并存期。

### 3.3 从主种子派生

`derive_psk_from_seed(seed, psk_id)` 让一套主密钥管理多套环境
（dev / staging / prod），换 `psk_id` 就得到互不相通的密钥。
避免「测试环境的密钥泄漏导致生产可被解密」。

### 3.4 注入方式

**开发构建**：不设任何环境变量，退回源码里的占位密钥，并且密钥状态查询
**如实返回 `false`** —— 各层名字不同，指的是同一件事：

| 层 | 名字 |
| --- | --- |
| Rust 原始绑定 | `has_real_psk()`（`node/src/lib.rs`、`wasm/src/lib.rs`） |
| JNI | `nativeHasRealPsk()` |
| 包装后的 API | `hasRealPsk()`（TypeScript）/ Kotlin 属性 `hasRealPsk` |

> 发布包必须据此拒绝启用加密。静默用一个所有人相同的占位密钥上线，
> 比不加密还危险 —— 它看起来是「安全的」，但任何人都能算出密钥。

**发布构建**：`TAOTAO_CRYPTO_PSK`（64 个十六进制字符）→ `core/build.rs`
→ 编译进产物。四个产物的 PSK 必须相同。

### 3.5 关于 PSK 可提取性的诚实说明

**PSK 在客户端产物里是可提取的。** 分片混淆（`core/src/psk_blob.rs`）把 32 字节
密钥拆成 4 片、按逆序存放、各片与不同掩码异或 —— 这只让「用 `strings` 扫一遍」
不再奏效，**不提供任何密码学意义上的保密**。

这不是实现缺陷，而是 PSK 模型的必然结果：客户端必须持有密钥才能完成握手，
任何持有密钥的客户端都能被逆向出密钥。换成证书、换成任何方案，只要客户端
需要长期凭据，这个结论都不变。

由此得到的实际约束：

1. **含真密钥的产物不能公开分发。** 所以开发构建用占位密钥，可以放心公开。
2. **不要四端共用一个 PSK 跨越信任边界。** 客户端 PSK 泄露是时间问题，
   它一旦泄露就等于服务端的校验密钥泄露 —— 把轮换纳入运维计划。
3. **运行时必须校验 `hasRealPsk()`。** 服务端启动时为 `false` 就拒绝启动。

---

## 四、代码结构

协议逻辑**只有一份实现**，四个语言侧拿到的是同一套字节格式。

```text
core/src/
├── protocol.rs    常量与 AAD 上下文构造（所有跨语言魔数的唯一定义处）
├── kdf.rs         HKDF / HMAC / 随机数源抽象
├── aead.rs        ChaCha20-Poly1305 封装
├── frame.rs       帧编解码 + 防重放滑窗（ReplayWindow）
├── handshake.rs   PSK 认证 + X25519 协商 + 握手 nonce 缓存
├── session.rs     会话状态机（seal / open / header_value）
├── psk.rs         PSK 装载、轮换、从主种子派生
├── psk_blob.rs    构建期密钥分片的编解码（与 build.rs 共用同一份实现）
├── engine.rs      跨语言门面：把状态机收成一个对象，绑定层只做类型转换
└── error.rs       统一错误类型
```

分层关系：

```text
┌─────────────────────────────────────────────────────┐
│ 绑定门面（只做类型转换，不含任何协议逻辑）              │
│  jni/  .so + .dll      node/  .node    wasm/  .wasm │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│ taotao-crypto-core                                  │
│ protocol → handshake → session → frame → aead       │
└─────────────────────────────────────────────────────┘
```

**绑定层禁止出现业务分支** —— 这是 `engine.rs` 存在的全部理由。
任何一侧出现「只有我这边解不开」的问题，一定是绑定层或调用方拼 AAD 的方式错了。

`core/` 不依赖任何 C 库，这是它能同时交叉编译到四个目标的前提。

### 最小用法

```text
let psk = Psk::from_hex("prod-v1", "<64 个 hex 字符>")?;
let now = 1_700_000_000_000u64;
let mut rng = OsRandom;

// 1. 客户端发起握手
let (handshake, hello_bytes) = ClientHandshake::start(psk, now, &mut rng)?;
// ...把 hello_bytes 发出去，拿回 server_hello...
let mut session = handshake.finish(&server_hello, now)?;

// 2. 加密请求
let aad = protocol::aad_context("GET", "/api/v1/favorites");
let frame = session.seal(&aad, b"{}", now)?;
// frame.bytes 作为请求体；session.header_value(frame.seq) 作为 X-Taotao-Crypto 头
```

完整可运行的版本是 `core/src/lib.rs` 末尾的 `end_to_end_through_public_api`
测试 —— 那里会真的握手、真的加密解密并断言结果。

### 四个绑定

| 目录 | 绑定方式 | 产物 | 要点 |
| --- | --- | --- | --- |
| `jni/` | JNI | Android `.so` + Windows `.dll` | 桌面端是 JVM，与安卓共用一份 |
| `node/` | napi-rs | `.node` | 后端用 |
| `wasm/` | wasm-bindgen | `.wasm` + JS | 分享播放器用 |

**时间戳一律由宿主传入**，不在 Rust 侧读时钟 —— wasm 里拿不到可靠的单调时钟，
而且宿主传时间戳让测试可以完全确定性地复现。

`bindings/` 下另有 Kotlin / TypeScript 的**参考包装层**，把各语言的裸绑定
包成一致的 camelCase API，并附上接入时必须核对的豁免路径清单。
**它们不在任何构建路径里，也没有被编译验证过** —— 接入时要先跑通再依赖。

---

## 五、测试

```bash
cargo test --workspace --lib        # 98 项
```

全部使用确定性随机源，可复现。覆盖：AEAD 往返与篡改拒绝、帧头认证、
防重放滑窗边界、握手全流程与低阶点、密钥轮换、会话生命周期、
PSK 分片编解码的已知答案向量、Debug 输出不泄露密钥。

`tools/smoke-test.cjs` 是**端到端冒烟测试**：加载编译产物、跑完整握手、
双向加解密、重放拒绝、跨端点重放拒绝、错误 PSK 拒绝，以及「未知 `psk_id`
与错误密钥返回同一种失败」，共 15 项。

```bash
node tools/smoke-test.cjs dist/node/taotao_crypto.node
node tools/smoke-test.cjs dist/node/taotao_crypto.node --expect-real-psk
```

> `cargo build` 成功和 `.node` 能被 `dlopen` 是两件事 —— 冒烟测试是唯一
> 能发现「编译通过但产物加载不了」的环节。
>
> 为什么没有 doctest：`cargo test --doc` 在 Windows 上会为每个示例再拉起一个
> rustc 进程，稳定撞到 `ERROR_NO_DATA`（"所有的管道范例都在使用中"），
> 让测试套件永远不绿。文档示例因此写成 `text` 代码块。

---

## 六、性能与资源占用

CPU 时间在移动端直接换算成耗电，所以这一层要看的不是「能不能跑」，而是
「每次操作花多少」。基准同时量**耗时**和**堆分配次数** —— 后者决定 Android 上的
GC 压力，而且比耗时更稳定（耗时会被 CPU 频率和后台负载干扰）。

```bash
cargo bench -p taotao-crypto-core
```

基准直接吃 `profile.release`，所以量到的就是**交付产物的真实性能**，不是理想值。

单机实测（x86_64 Windows）：

| 场景 | 耗时 | 吞吐 | 堆分配 |
| --- | ---: | ---: | ---: |
| 握手（ClientHello + ServerHello） | 205 µs | — | 14 次 |
| 封装 1 KB | 2.37 µs | 412 MB/s | 1 次 |
| 解封 1 KB | 2.37 µs | 411 MB/s | 1 次 |
| 封装 64 KB | 68.5 µs | 913 MB/s | 1 次 |
| 解封 64 KB | 48.8 µs | 1.28 GB/s | 1 次 |
| 会话往返 1 KB（含防重放滑窗） | 5.22 µs | — | 2 次 |
| 取 12 字节随机数（每帧一次） | 84 ns | — | 0 次 |

握手是每 30 分钟才付一次的开销，数据帧才是每个请求都走的真热路径。
但这 205 µs **不能退化成毫秒级** —— 一旦退化，在低端安卓机上就是一次可感知的卡顿。

### `opt-level` 是这个模块最贵的一个开关

`opt-level = "z"`（优先体积）会让**握手慢 29 倍**（6029 µs → 205 µs），
而数据帧慢 3～6 倍。也就是说体积优化对**椭圆曲线运算**的伤害远大于对称加密 ——
X25519 的域运算全靠内联和循环展开，而 ChaCha20/Poly1305 有 SIMD 后端兜底。

代价只有体积：Windows `.dll` 393 KB → 473 KB（+20%），四个目标加起来
+200 KB 量级，摊到安装包上是噪声。所以这里选了 `opt-level = 3`。

完整论证、以及「只给密码学原语开高优化、其余保持 `"z"`」那个被实测否掉的方案，
都写在 `Cargo.toml` 的 `[profile.release]` 注释里。

> ⚠️ 这个数字**强依赖 profile**。`session.rs` 的模块注释原先写「X25519 大约
> 50 微秒」—— 那是按满优化写的，而当时的 `opt-level = "z"` 让同一段代码实际
> 跑了 6029 µs。改 `opt-level` 之前先跑基准，别让注释和现实脱节。

### 每帧只分配一次

| | 改动前 | 现在 |
| --- | ---: | ---: |
| `seal_frame` 分配次数 | 3 | **1** |
| `open_frame` 分配次数 | 2 | **1**（空报文 0） |
| 会话往返分配次数 | 5 | **2** |
| 封装 64 KB 的分配字节 | 131 KB | **66 KB** |

两条改动：

- **AAD 在栈缓冲上拼**（`frame.rs` 的 `with_aad`，289 字节内联，更长的上下文
  才落堆）。AAD 是「会话 ID ‖ 端点上下文 ‖ 帧头」三段拼接，而 ChaCha20-Poly1305
  只接受一段连续的 AAD —— 拼接躲不掉，但拼接的**目标**不必在堆上。
- **原地加解密**（`aead::seal_in_place` / `open_in_place`）。封装时直接把明文写进
  整帧缓冲区的**最终位置**再原地加密，省掉「先加密出一份密文、再拷进新缓冲区」
  的那次全量拷贝。大报文上这一项就是 1.7 倍（64 KB：117 µs → 68.5 µs）。

> 原地解密依赖一个必须成立的前提：`decrypt_in_place_detached` 是**先验签、
> 后解密**。验签失败时它根本不会执行 `apply_keystream`，缓冲区里仍是密文，
> 不会留下未认证的明文。这条依赖写在 `aead.rs` 的注释里，也有测试锁住
> （`open_in_place_leaves_buffer_untouched_on_failure`）—— 换实现时会被发现。

### 看过但没动的两处

- **每帧一次 `OsRandom`**（取 12 字节 AEAD nonce）。看着是系统调用就以为贵，
  实测只要 **84 ns**，约占单帧总耗时的 3%。改成「会话内计数器 nonce」能把
  2^24 的生日界换成严格不重复，但那是在改协议的安全论证，换不来可观测收益。
- **`aad_context()` 仍返回 `Vec`**。它是每请求一次、且在绑定层跨过 FFI 之后才调，
  与字符串编解码本身同一量级，不值得为它改公开签名。

---

## 七、获取产物

产物由 CI 构建，本地**不需要** Rust、NDK、wasm-bindgen、MSVC。

| 入口 | 密钥 | 需要登录 | 何时更新 |
| --- | --- | --- | --- |
| **开发构建** `dev-latest` | 占位（`hasRealPsk() = false`） | 否 | 每次 push 到 main |
| **正式版本** `v*` tag | 注入真实 PSK | 是（draft） | 打 tag 后产出 |

```bash
# 开发构建：免登录直链，浏览器直接打开也能下
#   https://github.com/hdppppppp/tools/releases/download/dev-latest/android.zip

gh release download dev-latest --repo hdppppppp/tools --pattern '*.zip'
# 逐个解到各自平台目录 —— 不要 `unzip '*.zip' -d dist/` 一把梭：
# node 的两个平台都会产出 taotao_crypto.node，混在一个目录里必然互相覆盖，
# 而且拿错时的报错是「invalid ELF header」这种跟代码毫无关系的字样。
for p in android windows node-linux-x64 node-windows-x64 wasm; do
  unzip -o "$p.zip" -d "dist/$p"
done
```

主项目一行拉取（脚本在**主项目**的 `tools/` 下，默认取 `dev-latest`，自带 SHA256 校验）：

```powershell
pwsh tools/fetch-crypto.ps1                     # 全部四平台
pwsh tools/fetch-crypto.ps1 -Only wasm,node-linux-x64
pwsh tools/fetch-crypto.ps1 -Version v0.1.0     # 生产版本（需 -Token）
```

> 没有 `pwsh`（只有 Windows 自带的 5.1）时，把 `pwsh` 换成 `&`：
> `& .\tools\fetch-crypto.ps1`。脚本内部按版本做了兼容。

> ⚠️ **不要从 Actions Artifacts 拿产物。** 那些需要登录 GitHub 才能下载，
> 藏在 run 页面最底部、90 天过期。对外交付统一走 Release。

### 工作流

| 文件 | 触发 | 作用 |
| --- | --- | --- |
| `.github/workflows/build.yml` | `workflow_call` | 四平台构建的**唯一实现** |
| `.github/workflows/ci.yml` | push / PR / 手动 | 占位密钥；main 上额外产出 `dev-latest` |
| `.github/workflows/release.yml` | `v*` tag | 注入真密钥并发布正式 Release |

`ci.yml` 与 `release.yml` 的区别**只有**是否注入 PSK —— 构建步骤本身只写一遍。
拆成两个文件维护的典型后果是两边悄悄漂移，而日常 CI 一直是绿的。

两道保险保证生产产物不会漏掉密钥：

1. `psk-guard` 检查 Secret 非空且是 64 个十六进制字符，否则**直接失败**。
   不设这一关的话，Secret 没配时 `secrets.X` 会安静地求值成空字符串，
   构建照样绿，只是产物退化成占位密钥 —— 症状是「发布出去的客户端全部握不上手」，
   而所有构建日志都是正常的。
2. `node` job 的冒烟测试带 `--expect-real-psk`，实际加载产物断言
   `hasRealPsk() === true`。

配置 Secret：仓库 Settings → Secrets and variables → Actions → New repository secret，
名字必须是 `TAOTAO_CRYPTO_PSK`。

### 本地构建（逃生通道）

要快速迭代加密层本身时才用。要求 Rust 工具链，Android 目标额外要 NDK。

```powershell
pwsh tools/build.ps1 -Target all        # 工具链不全的目标会跳过并提示，不阻断其它目标
pwsh tools/build.ps1 -Target android    # 需要 Android NDK
pwsh tools/build.ps1 -Target wasm       # 需要 wasm-bindgen-cli（版本必须与 Cargo.lock 一致）
pwsh tools/build.ps1 -Target all -OutDir ..\music\crypto\dist   # 直接输出到主项目
```

本地没有 NDK 时 `-Target android` 会给出安装提示后跳过，不会让整条命令失败。

### CI 里几处刻意钉死的地方

- **NDK 版本**固定在 `build.yml` 的 `NDK_VERSION`，不用 runner 预装的「最新版」。
  镜像升级会静默换掉工具链。另外 `.cargo/config.toml` 用的链接器名
  （`aarch64-linux-android24-clang`）是 NDK r29 之前才有的 wrapper，r29+ 已移除。
- **wasm-bindgen CLI 版本**从 `Cargo.lock` 动态解析，不硬编码。
  与 crate 版本不一致时 CLI **返回 0、只打一句含糊警告、一个文件都不产出**，
  所以流程里显式比对版本并检查产物非空。
- **16KB 页面对齐**在构建阶段就用 `llvm-readelf` 校验。Google Play 从 2025-11 起
  对 targetSdk 35+ 强制要求；漏了上架被拒时只会说「APK 未按 16KB 页面对齐」，
  不会告诉你是哪个 `.so`。
- **JNI 导出符号**在 Windows job 里用 `dumpbin` 数一遍（预期 20+）。
  `strip` 配置一旦改错导致动态符号表被剥，表现是「加载成功但调用时报
  `UnsatisfiedLinkError`」，在安卓真机上极难定位。

### 发布

1. 改 `Cargo.toml` 里 `[workspace.package] version`
2. 提交
3. 打 tag 并推送：`git tag v0.1.0 && git push origin v0.1.0`
4. CI 跑完在 Releases 里拿到 **draft** 版本，检查无误后手动发布

版本号与协议版本是**两件事**：`PROTOCOL_VERSION`（当前为 1）一旦变化就意味着
线上要同时升级服务端和客户端，不能跟着语义化版本一起漂。tag 与 `Cargo.toml`
的 version 不一致时 `version-guard` 会拦下来。

---

## 八、目录

```text
├── Cargo.toml            工作区、共享依赖、release 优化配置
├── .cargo/config.toml    Android 链接器与 16KB 页面对齐
├── .github/workflows/    CI（build.yml 是四平台构建的唯一实现）
├── core/                 协议实现（唯一的逻辑来源，无任何绑定依赖）
│   ├── build.rs          构建期把 PSK 编译进产物并做分片混淆
│   └── benches/          性能与堆分配基准（`cargo bench`）
├── jni/                  JNI 绑定 → Android .so + Windows .dll
├── node/                 napi-rs 绑定 → .node
├── wasm/                 wasm-bindgen 绑定 → .wasm
├── bindings/             参考包装层（不在构建路径里，接入时复制）
│   ├── kotlin/           NativeCrypto.kt + 包装类
│   ├── node/             index.ts
│   └── wasm/             index.ts
├── docs/design.md        完整设计文档
└── tools/
    ├── build.ps1         本地构建（逃生通道）
    └── smoke-test.cjs    端到端冒烟测试（CI 与本地共用）
```

---

## 九、不做什么

- **不加密音频流和大文件上传。** `/songs/:id/play` 代理的是几百 MB 音频流，
  逐块 AEAD 会让 CPU 占用翻倍而收益极低（音频本身没有秘密，直链才是）；
  APK / jar 下载同理。逐帧加密需要改动客户端解码链路，留待后续。
- **不加密 `/search` 的裸 NDJSON 流式响应。** 协议目前只支持整体加密。
- **不替代 TLS。** 这是应用层的第二道防线 —— 用来抬高抓包和重放的门槛，
  不是用来在明文 HTTP 上裸奔的。
- **不追求「密钥不可提取」。** 没有做控制流平坦化、反调试、白盒密码学 ——
  收益递减而维护成本很高。
- **PSK 只支持构建期注入。** 运行时从密钥管理服务拉取的路径尚未实现。
- **不与 `server/native/kiwi-crypto` 合并。** 那是主项目里一套独立的
  C++17 + OpenSSL 加密模块，面向服务端单机场景；本仓库是跨四平台的传输层。
  两套算法选型不同（AES-256-GCM-SIV vs ChaCha20-Poly1305），
  接入时不要把它们当成同一层。

豁免清单见 `bindings/*/index.ts` 里的 `ENCRYPTION_EXEMPT_PATTERNS`。
