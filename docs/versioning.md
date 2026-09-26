# 版本号规则

加密层有**两个**版本，别混为一谈：

| | 是什么 | 在哪 | 谁看 |
| --- | --- | --- | --- |
| **协议版本** `PROTOCOL_VERSION` | 线格式 / 握手报文的兼容标识（`u8`） | `core/src/protocol.rs` | 运行时——写进 `X-Taotao-Crypto` 头，端与端靠它判断能不能通信 |
| **包版本** `MAJOR.MINOR.PATCH` | 这一份**产物**的发布版本（SemVer） | `Cargo.toml` 的 `[workspace.package] version` | 人——tag、Release 名、`fetch-crypto.ps1 -Version` |

## 铁律：MAJOR == PROTOCOL_VERSION

这是整个规则的锚点，也是「避免乱了」的关键。**包版本的 MAJOR 永远等于当前
`PROTOCOL_VERSION`。** 于是看到任何一个版本号（比如 `2.3.1`）就能一眼断定：
它说的是协议 v2，能和所有 `2.x.y` 互通，但和 `1.x.y` / `3.x.y` 握不上手。

当前：`PROTOCOL_VERSION = 2` → 包版本是 `2.x.y`，首个正式版 `v2.0.0`。

`release.yml` 的 `version-guard` 会在每次打 tag 时强制校验，任一不符就拒绝发布：

1. `tag`（去掉 `v`）== `Cargo.toml` 的 `version`
2. `version` 的 MAJOR == `core/src/protocol.rs` 的 `PROTOCOL_VERSION`

所以版本号不可能悄悄漂移——漂了 CI 直接红。

## 三段怎么加

| 段 | 什么时候 +1 | 例子 |
| --- | --- | --- |
| **MAJOR** | 且仅当 `PROTOCOL_VERSION` 变（线格式 / 握手破坏，端**必须**同批升级） | 握手密钥绑定设备号（协议 1→2）→ 包 `1.x` → `2.0.0` |
| **MINOR** | 向后兼容的能力新增（旧客户端仍能通信） | 新增一个可选的绑定层导出函数 |
| **PATCH** | 修复 / 性能 / 混淆 / 安全，**线格式与对外 API 都不变** | `opt-level` 调优、修一个越界、换混淆密钥 |

MAJOR 进位时 MINOR / PATCH 归零（`1.4.2` 协议升级后是 `2.0.0`，不是 `2.4.2`）。

> **为什么不用 0.x？** SemVer 的 0.x 表示「不稳定、随时破坏」，语义上 MAJOR 没意义。
> 但本层的 MAJOR 承载的是真实的协议兼容契约，必须从能对上协议号的 `2` 开始，
> 而不是停在 `0`。这不是 crates.io 发布包（`publish = false`），不受 0.x 惯例约束。

## 发布一个版本

1. 改动落到 `core/` 等处；若动了握手 / 帧 / 头格式，同时把
   `core/src/protocol.rs` 的 `PROTOCOL_VERSION` +1。
2. 按上表把 `Cargo.toml` 的 `version` 改成新号（协议变了就进 MAJOR）。
3. 在 `CHANGELOG.md` 顶部加一条。
4. 提交（走 `tools/sync-repos.ps1` 推到 `tools` 仓库）。
5. 打 tag 并推送：`git tag v2.0.0 && git push tools v2.0.0`
   （tag 推到 `tools` 远端才会触发 `release.yml`）。
6. `release.yml` 自动构建、注入真实 PSK、发布成**正式 Release**
   （`draft: false`），直接出现在仓库 Releases 列表，名字形如
   「加密层 v2.0.0（协议 v2）」。无需再人工点发布。

拉取：`pwsh tools/fetch-crypto.ps1 -Version v2.0.0 -Token <...>`。

## 两条滚动入口不是版本

- `dev-latest`：main 每次 push 的开发构建，**占位密钥**，`prerelease`。联调用，不是版本。
- 正式 `vX.Y.Z`：注入真实 PSK 的发布版，才是「版本」。
