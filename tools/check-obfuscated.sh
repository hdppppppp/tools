#!/usr/bin/env bash
# 断言产物里的字符串混淆确实生效了。
#
# 用法：tools/check-obfuscated.sh <产物路径> [产物路径 ...]
#
# ## 为什么需要这个脚本
#
# core 的 `obfuscate` feature 会把协议标签与错误文案做编译期加密
# （见 core/src/obf.rs）。如果哪天 feature 没被开启、或者有人为了排查问题
# 临时把它关掉，产物会**静默**退回明文 —— 构建、单元测试、上传全都正常，
# 只有真正去 `strings` 的人才会发现。这个脚本就是把「静默」变成「构建失败」。
#
# ## 检查范围是刻意收窄的
#
# 这里只查**确实被混淆覆盖**的串。以下两类**故意不在检查范围**：
#
#   · `core/src/frame.rs` 这类源码路径 —— 来自 `panic!` 的 `Location` 常量，
#     混淆覆盖不到（`strip` 只剥符号表，不剥 Location 字符串）
#   · registry 里的依赖精确版本号与 `/rustc/<commit>` —— 来自编译器，
#     同样覆盖不到
#
# 把它们加进来会让这个检查永远为红，进而被无视 —— 那比没有检查更糟。
# 量化残留条数用 `tools/scan-leaks.py`，它会把每一类分别列出来。
set -euo pipefail

# 这些串必须**不存在**于产物中。挑的都是「泄露信息量最大」的那几条：
# 错误文案直接说明校验逻辑（「时间戳超出允许窗口」= 这里有防重放时间窗），
# 协议标签直接给出 HKDF 的 info 值。
NEEDLES=(
  "帧认证失败"
  "握手认证失败"
  "时间戳超出允许窗口"
  "会话序号空间耗尽"
  "taotao-crypto-v1/handshake"
  "taotao-crypto-v1/key/c2s"
  "taotao-crypto-v1/key/s2c"
  "taotao-crypto-v1/psk/"
)

status=0

for artifact in "$@"; do
  if [ ! -f "$artifact" ]; then
    echo "::error::找不到产物：$artifact"
    status=1
    continue
  fi

  found=0
  for needle in "${NEEDLES[@]}"; do
    # -a 把二进制当文本读（.so/.dll/.wasm 都是二进制），-F 按字面匹配
    # （needle 里有 `/` 和 `-`，不当正则更稳），-q 只关心有没有。
    if grep -qaF -- "$needle" "$artifact"; then
      echo "::error::$(basename "$artifact") 里仍能找到明文串「$needle」"
      found=1
    fi
  done

  if [ "$found" -ne 0 ]; then
    echo "::error::$artifact 的字符串混淆没有生效。"
    echo "::error::检查该 crate 的 Cargo.toml 是否给 taotao-crypto-core 开了 obfuscate feature"
    echo "::error::（客户端 .so/.dll/.wasm 必须开，服务端 .node 必须不开）。"
    status=1
  else
    echo "✅ $(basename "$artifact") 通过字符串混淆检查（${#NEEDLES[@]} 个探针全部未命中）"
  fi
done

exit "$status"
