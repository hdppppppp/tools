"""对编译产物做可读串分类取证，量化「到底混了什么、还剩什么」。

用法：python scan-leaks.py <产物路径> [产物路径 ...]
只读，不修改任何文件。
"""

import re
import sys
from pathlib import Path

# 分类规则：每类一条正则，命中即计入。顺序即报告顺序。
CATEGORIES = [
    ("① 绝对构建路径（CI runner 目录 + registry 哈希）",
     re.compile(rb"(/home/runner|runneradmin|/usr/local/cargo/registry|cargo\\registry)")),
    ("② rustc 自身路径（含精确 commit）",
     re.compile(rb"/rustc/[0-9a-f]{8,}")),
    # 路径分隔符要同时认 / 和 \ —— Windows 产物（.dll / .node）里是反斜杠，
    # 只写 / 会让这一整类漏报为 0 条，从而低估泄露面。
    ("③ 依赖精确版本号",
     re.compile(rb"[a-z0-9_]+-[0-9]+\.[0-9]+\.[0-9]+[/\\]src")),
    ("④ 本项目协议常量",
     re.compile(rb"taotao-crypto-v[0-9]+")),
    ("⑤ 本项目源码文件名",
     re.compile(rb"(core|jni|wasm|node)[/\\]src[/\\][a-z_]+\.rs")),
    ("⑥ 内部 crate 名 / 调试文件",
     re.compile(rb"taotao_crypto_[a-z]+\.(pdb|dll|node|so)")),
]

# 中文串单独扫（错误文案会直接暴露校验逻辑）
CJK = re.compile(rb"[\xe4-\xe9][\x80-\xbf][\x80-\xbf]")


def scan(path: Path) -> None:
    data = path.read_bytes()
    print(f"\n{'=' * 66}")
    print(f"{path.name}  （{len(data):,} 字节）")
    print("=" * 66)

    for label, pat in CATEGORIES:
        hits = sorted({m.group(0).decode("utf-8", "replace") for m in pat.finditer(data)})
        print(f"\n{label}：{len(hits)} 条")
        for h in hits[:8]:
            print(f"    {h}")
        if len(hits) > 8:
            print(f"    … 另有 {len(hits) - 8} 条")

    # 中文串：按可读片段切分
    text = data.decode("utf-8", "ignore")
    frags = set()
    for m in re.finditer(r"[\u4e00-\u9fff][\u4e00-\u9fff\uff0c\uff1a\u3001\uff08\uff09\uff1f0-9 a-zA-Z_\-\.]{2,}", text):
        frags.add(m.group(0).strip())
    print(f"\n⑦ 中文错误文案 / 提示串：{len(frags)} 条")
    for f in sorted(frags)[:14]:
        print(f"    {f}")
    if len(frags) > 14:
        print(f"    … 另有 {len(frags) - 14} 条")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.exists():
            scan(p)
        else:
            print(f"跳过（不存在）：{p}")
