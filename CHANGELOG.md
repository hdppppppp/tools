# 更新日志

版本号规则见 [`docs/versioning.md`](docs/versioning.md)：`MAJOR.MINOR.PATCH`，
**MAJOR 恒等于 `PROTOCOL_VERSION`**。每个正式版由 `vX.Y.Z` tag 触发，
自动发布到仓库 Releases。

## v2.3.0

协议版本不变（仍 `PROTOCOL_VERSION = 2`）。**关键修复**：KDF 的三个协议标签
（`handshake` / `key/c2s` / `key/s2c`）此前经 `obf!` 混淆，而客户端产物（jni/wasm）
开 `obfuscate`、服务端（node）不开——一旦两端运行期解出的标签字节不完全一致，
握手密钥不同、MAC 失配，表现为「同 PSK、同设备号也握不上手」，且 node↔node
测试仍绿，极难定位。改为**明文字节常量**，保证任何构建下派生一致，并加
`kdf_info_labels_are_plaintext_constants` 回归测试钉死标签。标签是固定协议
常量、非秘密，去混淆无安全损失。

- 客户端与服务端务必**同时升级到 ≥ 2.3.0**（旧版标签若真的被混淆改写过，
  与新版互不兼容）。

## v2.2.0

协议版本不变（仍 `PROTOCOL_VERSION = 2`），**向后兼容**。

- 新增「服务端用内嵌 PSK 登记」入口，与客户端 `from_embedded` 对称，构建期注入
  一次即两端通用，服务端无需再从环境变量喂十六进制：
  - `ServerEngine::put_embedded_psk(psk_id)`（core）
  - napi `Server.putEmbeddedPsk(pskId)`（node）
  - jni/wasm 暂不加（服务端主要走 node）。

## v2.1.0

协议版本不变（仍 `PROTOCOL_VERSION = 2`），**向后兼容**：旧客户端 / 服务端无需升级。

- 新增「用内嵌 PSK 构造客户端」入口，密钥不再经宿主语言传递：
  - `ClientEngine::from_embedded(psk_id, device_id)`（core）——取构建期编进产物的 PSK。
  - JNI 导出 `NativeCrypto.clientNewEmbedded(pskId, deviceId)`（jni）——供 Android /
    Windows JVM 客户端使用，避免 APK 自带明文 PSK 十六进制串、抵消产物混淆加固。
  - node / wasm 暂不加（服务端与 Web 不走此路径）。

## v2.0.0

协议版本 `PROTOCOL_VERSION = 2`。**线格式破坏**，服务端与三端客户端必须同批升级。

- 握手密钥绑定设备号：`device_id` 折进 `derive_handshake_key` 的 HKDF info
  （不进 AAD、不进 ClientHello 线格式，随握手 HTTP body 传输）。设备号不匹配则
  握手 MAC 失配，握手被拒。即使协议被逆向，攻击者仍需逐台真机提取硬件设备号
  （Android `ANDROID_ID`、Windows `MachineGuid`）才能冒充。
- `Client::new` / `ClientEngine::new` 增 `device_id` 参数；`Server.accept` /
  `accept_client_hello` 增 `device_id` 参数（四端绑定层同步）。
- 建立版本号规则并固化到 CI：`version-guard` 校验 tag / `Cargo.toml` /
  `PROTOCOL_VERSION` 三方一致；正式 Release 改为 `draft: false` 自动发布。

## v1（历史）

首版协议：PSK + X25519 握手、ChaCha20-Poly1305 AEAD 帧、HKDF-SHA256 派生、
`X-Taotao-Crypto` 头、nonce 缓存 + 序号双重抗重放。彼时包版本停在 `0.1.0`，
未打过正式 tag（仅有 `dev-latest` 滚动构建）。
