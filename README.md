# 桃桃音乐传输层加密模块

四个平台共用的加密层：**一份 Rust 协议实现**，四个绑定门面，四类产物。

| 目标 | 产物 | 绑定方式 | 由谁消费 |
| --- | --- | --- | --- |
| Android | `libtaotao_crypto.so`（arm64-v8a / x86_64） | JNI | `androidApp` |
| Windows | `taotao_crypto.dll` | JNI | `desktopApp`（Compose Desktop 是 JVM） |
| 后端 | `taotao_crypto.node`（Linux x64 / Windows x64） | napi-rs | `server` |
| Web | `taotao_crypto_bg.wasm` + JS 胶水 | wasm-bindgen | `webApp` 分享播放器 |

完整设计（威胁模型、帧格式、上线策略、与现有契约的边界）见 [`docs/design.md`](docs/design.md)。

---

## 本地不装任何环境也能拿到产物

这是本仓库的主要工作方式：**编译全部交给 GitHub Actions，本地只消费产物。**

本地不需要 Rust、不需要 NDK、不需要 wasm-bindgen、不需要 MSVC。

### 取产物

两个入口，按用途选：

| 入口 | 密钥 | 是否需要登录 | 何时更新 |
| --- | --- | --- | --- |
| **开发构建** `dev-latest` | 占位（`hasRealPsk()=false`） | **不需要** | 每次 push 到 main |
| **正式版本** `v*` tag | 注入真实 PSK | 需要（draft 状态） | 打 tag 后由 release.yml 产出 |

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

主项目一行拉取（脚本在**主项目**里，默认就取 `dev-latest`，自带 SHA256 校验）：

```powershell
# PowerShell 7 及以上
pwsh tools/fetch-crypto.ps1                     # 全部四平台
pwsh tools/fetch-crypto.ps1 -Only wasm,node-linux-x64
pwsh tools/fetch-crypto.ps1 -Version v0.1.0     # 生产版本（需 -Token）
```

> 本机若只有 Windows PowerShell 5.1（`pwsh` 未安装），脚本同样能跑 ——
> 它内部按版本做了兼容（TLS 1.2、`-UseBasicParsing` 只在 5.1 上传）。
> 在 PowerShell 里执行即可：
>
> ```powershell
> & .\tools\fetch-crypto.ps1
> ```

> ⚠️ **不要从 Actions Artifacts 里拿产物。** 那些需要登录 GitHub 才能下载，
> 且藏在 run 页面最底部、90 天过期。Artifacts 只是构建过程中的中间产物，
> 对外交付统一走 Release —— `ci.yml` 里的 `dev-release` job 就是为此存在的。

### 改代码后怎么验证

推分支 → CI 自动跑单元测试 + 四平台构建 + 端到端冒烟 → 从 PR 的 Checks 页面看结果。
**不需要在本地编译一次。**

---

## PSK 策略

PSK 是构建期写进产物的（`core/build.rs` 读 `TAOTAO_CRYPTO_PSK`）。
两个流水线因此**故意**分开：

| 流水线 | 触发 | PSK | 产物特征 | 可否公开 |
| --- | --- | --- | --- | --- |
| `ci.yml` | push / PR / 手动 | **不注入** | `hasRealPsk() === false` | 可以，用于联调与协议对齐 |
| `release.yml` | 打 `v*` tag | 从 Secrets 注入 | `hasRealPsk() === true` | **不可以** |

两道保险保证生产产物不会漏掉密钥：

1. `psk-guard` job 检查 Secret 非空且是 64 个十六进制字符，否则**直接失败**。
   不设这一关的话，Secret 没配时 `secrets.X` 会安静地求值成空字符串，
   构建照样绿，只是产物退化成占位密钥 —— 症状是「发布出去的客户端全部握不上手」，
   而所有构建日志都是正常的。
2. `node` job 的冒烟测试带 `--expect-real-psk`，实际加载产物断言
   `hasRealPsk() === true`。

配置 Secret：仓库 Settings → Secrets and variables → Actions → New repository secret，
名字必须是 `TAOTAO_CRYPTO_PSK`。

> ⚠️ **关于「加密」这个词的诚实说明**
>
> PSK 在客户端产物里是可提取的。分片混淆（`core/src/psk_blob.rs`）只抬高提取成本，
> 不提供密码学意义上的保密 —— 任何客户端密钥都必然如此，这是 PSK 模型的固有性质，
> 不是实现缺陷。它换来的是「防中间人读取 / 防篡改 / 防重放」，不是「密钥不可知」。
>
> 直接推论：**含真密钥的产物不能公开分发**。这也是为什么 CI 产物用占位密钥。

---

## 构建

### 主路径：GitHub Actions

| 文件 | 作用 |
| --- | --- |
| `.github/workflows/build.yml` | 可复用工作流，四平台构建的唯一实现 |
| `.github/workflows/ci.yml` | push / PR / 手动触发，占位密钥；main 上额外产出 `dev-latest` 预发布 |
| `.github/workflows/release.yml` | 打 tag 触发，注入真密钥并发布正式 Release |

`ci.yml` 与 `release.yml` 的区别**只有**是否注入 PSK —— 构建步骤本身只写一遍。
拆成两个独立文件维护的典型后果是两边悄悄漂移，而日常 CI 一直是绿的。

CI 里几处刻意钉死、不要随手放宽的地方：

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

### 逃生通道：本地构建

需要在本地快速迭代加密层本身时才用。要求 Rust 工具链，Android 目标额外要 NDK。

```powershell
pwsh tools/build.ps1 -Target all        # 工具链不全的目标会跳过并提示，不阻断其它目标
pwsh tools/build.ps1 -Target android    # 需要 Android NDK
pwsh tools/build.ps1 -Target wasm       # 需要 wasm-bindgen-cli（版本必须与 Cargo.lock 一致）
pwsh tools/build.ps1 -Target all -OutDir ..\music\crypto\dist   # 直接输出到主项目
```

> 没有 `pwsh`（只有 Windows PowerShell 5.1）时，把 `pwsh` 换成 `&` 即可：
> `& .\tools\build.ps1 -Target all`。

本地没有 NDK 时 `-Target android` 会给出安装提示后跳过，不会让整条命令失败。

---

## 发布

1. 改 `Cargo.toml` 里 `[workspace.package] version`
2. 提交
3. 打 tag 并推送：`git tag v0.1.0 && git push origin v0.1.0`
4. CI 跑完在 Releases 里拿到 **draft** 版本，检查无误后手动发布

版本号与协议版本是**两件事**：`PROTOCOL_VERSION`（当前为 1）一旦变化就意味着
线上要同时升级服务端和客户端，不能跟着语义化版本一起漂。tag 与
`Cargo.toml` 的 version 不一致时 `version-guard` job 会拦下来。

---

## 测试

```bash
cargo test --workspace --lib
```

当前 **87 项全绿**，全部使用确定性随机源，可复现。覆盖 AEAD 往返与篡改拒绝、
帧头认证、防重放滑窗边界、握手全流程与低阶点、密钥轮换、会话生命周期、
PSK 分片编解码的已知答案向量、以及 Debug 输出不泄露密钥。

`tools/smoke-test.cjs` 是**端到端冒烟测试**：加载编译产物、跑完整握手、
双向加解密、重放拒绝、跨端点重放拒绝、错误 PSK 拒绝。CI 的 node job 会执行它 ——
这是整条流水线里唯一真正「运行」产物的地方，也是唯一能发现
「编译通过但产物加载不了」的环节。

```bash
node tools/smoke-test.cjs dist/node/taotao_crypto.node
node tools/smoke-test.cjs dist/node/taotao_crypto.node --expect-real-psk
```

### 为什么没有 doctest

`cargo test --doc` 在 Windows 上会为每个示例再拉起一个 rustc 进程，稳定撞到
`ERROR_NO_DATA`（"所有的管道范例都在使用中"），让测试套件永远不绿。
文档示例因此写成 `text` 代码块，正确性由等价的单元测试保证。

---

## 目录

```text
├── Cargo.toml            工作区、共享依赖、release 优化配置
├── .cargo/config.toml    Android 链接器与 16KB 页面对齐
├── .github/workflows/    CI（build.yml 是四平台构建的唯一实现）
├── core/                 协议实现（唯一的逻辑来源，无任何绑定依赖）
│   ├── build.rs          构建期把 PSK 编译进产物并做分片混淆
│   └── src/
│       ├── protocol.rs   常量与 AAD 上下文构造
│       ├── kdf.rs        HKDF / HMAC / 随机数源
│       ├── aead.rs       ChaCha20-Poly1305 封装
│       ├── frame.rs      帧编解码 + 防重放滑窗
│       ├── handshake.rs  PSK 认证 + X25519 协商
│       ├── session.rs    会话状态机
│       ├── psk.rs        PSK 装载、轮换、混淆还原
│       └── engine.rs     跨语言门面（状态机只写一遍）
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

`bindings/` 下的三个文件**不在任何构建路径里**，是给接入方复制的参考实现。
它们把各语言的裸绑定包成一致的 camelCase / 惯用 API，并附上接入时必须核对的
豁免路径清单。**它们没有被编译验证过** —— 没有接入环境，接入时要先跑通再依赖。

---

## 不做什么

- 不加密音频流和大文件上传（见 `docs/design.md` 的边界章节）
- 不替代 TLS，是应用层的第二道防线
- 不追求「密钥不可提取」，只抬高提取成本
- **不与 `server/native/kiwi-crypto` 合并**。那是主项目里一套独立的 C++17 +
  OpenSSL 加密模块，面向服务端单机场景；本仓库是跨四平台的传输层。
  两套的算法选型不同（AES-256-GCM-SIV vs ChaCha20-Poly1305），
  接入时不要把它们当成同一层。
