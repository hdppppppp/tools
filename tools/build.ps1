<#
.SYNOPSIS
    构建桃桃音乐加密层的一个或多个目标平台产物。

.DESCRIPTION
    四个目标共用同一份 Rust 源码（`core/`），这里只负责交叉编译与产物落位。
    产物统一落在 `dist/<平台>/`，由调用方决定拷贝到哪里 ——
    加密层刻意不直接写进 androidApp / desktopApp / server 的目录，
    这样「先写好、暂不接入」这个阶段不会在其它模块留下半成品文件。

    ⚠️ 这是**本地逃生通道**，不是主路径。
    主路径是 GitHub Actions（见 `.github/workflows/`）：push 与 PR 由 ci.yml
    用占位密钥构建，打 tag 由 release.yml 注入真密钥并发布 Release。
    本地完全不需要装 NDK / wasm-bindgen 也能拿到产物 —— 从 Release 下载即可。
    保留这个脚本是为了「要改加密层本身、需要在本地快速迭代」的场景。

.PARAMETER Target
    all / android / windows / node / wasm。默认 all。

.PARAMETER Psk
    64 个十六进制字符的 PSK。不传则读取环境变量 TAOTAO_CRYPTO_PSK；
    两者都没有时用占位密钥构建，并在结尾打醒目警告（产物不可用于生产）。

.PARAMETER ObfuscateKey
    字符串混淆密钥。不传则读取环境变量 CRYPTIFY_KEY。
    两者都没有时 cryptify 用它**内置的固定密钥** —— 构建照样成功、产物照样
    可复现，只是攻击者可以拿公开的默认密钥一把梭解开，不必从二进制里挖。
    所以这是**软**依赖，缺了不会像 PSK 那样打红色警告。

.PARAMETER OutDir
    产物输出目录，默认是本仓库的 `dist/`。
    要直接输出到主项目目录时用它，例如：
        pwsh tools/build.ps1 -Target all -OutDir ..\music\crypto\dist

.EXAMPLE
    $env:TAOTAO_CRYPTO_PSK = (Get-Random -Count 32 -InputObject (0..255) | ForEach-Object { '{0:x2}' -f $_ }) -join ''
    pwsh tools/build.ps1 -Target all

.EXAMPLE
    # 只编 Android，并直接落到主项目的产物目录
    pwsh tools/build.ps1 -Target android -OutDir ..\music\crypto\dist

.NOTES
    需要：Rust 工具链、Android NDK（仅 android 目标）、wasm-bindgen-cli（仅 wasm 目标）。
    这三样在 CI 上都已经配好，本地只在需要快速迭代时才需要装。
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'android', 'windows', 'node', 'wasm')]
    [string]$Target = 'all',

    [string]$Psk = $env:TAOTAO_CRYPTO_PSK,

    [string]$ObfuscateKey = $env:CRYPTIFY_KEY,

    [string]$OutDir
)

$ErrorActionPreference = 'Stop'

# 脚本自身在 tools/ 下，仓库根是上一级。
$CryptoRoot = Split-Path -Parent $PSScriptRoot
# 独立仓库后不再有「主仓库」概念，产物默认落本仓库的 dist/。
# 接入方用 -OutDir 指向主项目目录，避免在多处维护两份产物。
$DistRoot = if ([string]::IsNullOrWhiteSpace($OutDir)) {
    Join-Path $CryptoRoot 'dist'
} else {
    $OutDir
}

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Warn([string]$Message) {
    Write-Host "警告：$Message" -ForegroundColor Yellow
}

function Write-Ok([string]$Message) {
    Write-Host "  $Message" -ForegroundColor Green
}

function Assert-Cargo {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw '未找到 cargo。请先安装 Rust 工具链：https://rustup.rs'
    }
}

function Get-PskOrPlaceholder {
    if ([string]::IsNullOrWhiteSpace($Psk)) {
        Write-Warn '未提供 PSK（-Psk 或 TAOTAO_CRYPTO_PSK），本次将使用占位密钥。产物不可用于生产。'
        return $null
    }
    $trimmed = $Psk.Trim()
    if ($trimmed -notmatch '^[0-9a-fA-F]{64}$') {
        throw "PSK 必须是 64 个十六进制字符（32 字节），当前长度 $($trimmed.Length)。"
    }
    return $trimmed
}

<#
.SYNOPSIS
    定位 Android NDK 根目录。

.DESCRIPTION
    按优先级依次尝试 ANDROID_NDK_HOME / ANDROID_NDK_ROOT / SDK 下的 ndk/ 目录。
    找不到时返回 $null，由调用方决定是跳过还是报错 —— 不要在这里 throw，
    因为 -Target all 时安卓工具链缺失不应该阻断其它三个目标。
#>
function Find-AndroidNdk {
    foreach ($envName in @('ANDROID_NDK_HOME', 'ANDROID_NDK_ROOT')) {
        $value = [Environment]::GetEnvironmentVariable($envName)
        if ($value -and (Test-Path $value)) { return $value }
    }

    foreach ($sdkEnv in @('ANDROID_HOME', 'ANDROID_SDK_ROOT')) {
        $sdk = [Environment]::GetEnvironmentVariable($sdkEnv)
        if (-not $sdk) { continue }
        $ndkDir = Join-Path $sdk 'ndk'
        if (-not (Test-Path $ndkDir)) { continue }
        # 有多个版本时取版本号最大的那个。
        $candidates = Get-ChildItem -Path $ndkDir -Directory |
            Sort-Object -Property Name -Descending
        if ($candidates.Count -gt 0) { return $candidates[0].FullName }
    }

    # 最后兜底：从 local.properties 的 sdk.dir 推。
    # 独立仓库里通常没有这个文件（它是 Android 项目的本地配置，不入库），
    # 所以这只是一条便利路径 —— CI 上走的是 ANDROID_NDK_HOME 环境变量。
    $localProps = Join-Path $CryptoRoot 'local.properties'
    if (Test-Path $localProps) {
        $line = Select-String -Path $localProps -Pattern '^sdk\.dir\s*=' | Select-Object -First 1
        if ($line) {
            $sdk = ($line.Line -split '=', 2)[1].Trim().Replace('\\', '\')
            $ndkDir = Join-Path $sdk 'ndk'
            if (Test-Path $ndkDir) {
                $candidates = Get-ChildItem -Path $ndkDir -Directory |
                    Sort-Object -Property Name -Descending
                if ($candidates.Count -gt 0) { return $candidates[0].FullName }
            }
        }
    }

    return $null
}

function Build-Android([string]$ResolvedPsk) {
    Write-Step '构建 Android .so'

    $ndk = Find-AndroidNdk
    if (-not $ndk) {
        Write-Warn '未找到 Android NDK，跳过 Android 目标。'
        Write-Warn '安装方式：Android Studio → SDK Manager → SDK Tools → 勾选 NDK (Side by side)'
        return
    }
    Write-Ok "NDK：$ndk"

    $hostTag = if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'windows-x86_64' } else { 'linux-x86_64' }
    $toolchainBin = Join-Path $ndk "toolchains/llvm/prebuilt/$hostTag/bin"
    if (-not (Test-Path $toolchainBin)) {
        throw "NDK 工具链目录不存在：$toolchainBin"
    }
    # 链接器配置在 .cargo/config.toml 里，它按名字找 clang，所以必须进 PATH。
    $env:PATH = "$toolchainBin;$env:PATH"

    # 每个 ABI 对应一个 Rust 目标三元组。
    # 只装 arm64 + x86_64：armeabi-v7a 的装机占比已经很低，为它多带一份 .so
    # 会让 APK 大 200KB 左右；真要支持再打开这一项即可。
    $abis = @(
        @{ RustTarget = 'aarch64-linux-android';   Abi = 'arm64-v8a';   Strip = 'llvm-strip' }
        @{ RustTarget = 'x86_64-linux-android';    Abi = 'x86_64';      Strip = 'llvm-strip' }
    )

    foreach ($abi in $abis) {
        Write-Ok "目标：$($abi.RustTarget) → jniLibs/$($abi.Abi)"
        & rustup target add $abi.RustTarget 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "无法安装 Rust 目标 $($abi.RustTarget)，跳过。"
            continue
        }

        & cargo build --manifest-path (Join-Path $CryptoRoot 'Cargo.toml') `
            --release --target $abi.RustTarget -p taotao-crypto-jni
        if ($LASTEXITCODE -ne 0) { throw "构建 $($abi.RustTarget) 失败" }

        $src = Join-Path $CryptoRoot "target/$($abi.RustTarget)/release/libtaotao_crypto_jni.so"
        $outDir = Join-Path $DistRoot "android/$($abi.Abi)"
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        Copy-Item -Force $src (Join-Path $outDir 'libtaotao_crypto.so')

        # release profile 已经 strip 过，这里只做一次显式的体积汇报。
        $size = (Get-Item (Join-Path $outDir 'libtaotao_crypto.so')).Length
        Write-Ok ("  产物 {0:N0} 字节" -f $size)
    }
}

function Build-Windows([string]$ResolvedPsk) {
    Write-Step '构建 Windows .dll'

    & rustup target add x86_64-pc-windows-msvc 2>&1 | Out-Null
    & cargo build --manifest-path (Join-Path $CryptoRoot 'Cargo.toml') `
        --release --target x86_64-pc-windows-msvc -p taotao-crypto-jni
    if ($LASTEXITCODE -ne 0) { throw '构建 Windows 目标失败' }

    $src = Join-Path $CryptoRoot 'target/x86_64-pc-windows-msvc/release/taotao_crypto_jni.dll'
    $outDir = Join-Path $DistRoot 'windows'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Copy-Item -Force $src (Join-Path $outDir 'taotao_crypto.dll')

    $size = (Get-Item (Join-Path $outDir 'taotao_crypto.dll')).Length
    Write-Ok ("产物 {0:N0} 字节" -f $size)

    # 验证导出符号还在。`strip = "symbols"` 剥掉的是静态符号表，
    # 但这条断言值得每次构建都跑 —— 一旦配置改错导致动态符号被剥，
    # 表现是「System.loadLibrary 成功，但调方法时 UnsatisfiedLinkError」，
    # 而这个错误在安卓真机上极难定位。
    Write-Step '校验 JNI 导出符号'
    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if ($dumpbin) {
        $exports = & dumpbin /exports (Join-Path $outDir 'taotao_crypto.dll') 2>&1
        $jniCount = ($exports | Select-String -Pattern 'Java_com_taotao_music_crypto_NativeCrypto_').Count
        if ($jniCount -lt 20) {
            throw "JNI 导出符号只有 $jniCount 个，预期 20+。请检查 Cargo.toml 的 strip 配置。"
        }
        Write-Ok "找到 $jniCount 个 JNI 导出符号"
    } else {
        Write-Warn '未找到 dumpbin（需要 VS 开发者命令行），跳过符号校验。'
    }
}

function Build-Node([string]$ResolvedPsk) {
    Write-Step '构建 Node 原生扩展 .node'

    & cargo build --manifest-path (Join-Path $CryptoRoot 'Cargo.toml') `
        --release -p taotao-crypto-node
    if ($LASTEXITCODE -ne 0) { throw '构建 Node 目标失败' }

    # cdylib 在各平台产出不同扩展名，Node 统一要 .node。
    $candidates = @(
        'target/release/taotao_crypto_node.dll'
        'target/release/libtaotao_crypto_node.so'
        'target/release/libtaotao_crypto_node.dylib'
    )
    $src = $null
    foreach ($candidate in $candidates) {
        $full = Join-Path $CryptoRoot $candidate
        if (Test-Path $full) { $src = $full; break }
    }
    if (-not $src) { throw '找不到 Node 扩展的编译产物' }

    $outDir = Join-Path $DistRoot 'node'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Copy-Item -Force $src (Join-Path $outDir 'taotao_crypto.node')

    $size = (Get-Item (Join-Path $outDir 'taotao_crypto.node')).Length
    Write-Ok ("产物 {0:N0} 字节" -f $size)
    Write-Warn '注意：.node 是平台相关的。部署到 Linux 必须在 Linux 上构建，不能复用本机产物。'
}

function Build-Wasm([string]$ResolvedPsk) {
    Write-Step '构建 WebAssembly'

    & rustup target add wasm32-unknown-unknown 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn '无法安装 wasm32-unknown-unknown 目标，跳过。'
        return
    }

    & cargo build --manifest-path (Join-Path $CryptoRoot 'Cargo.toml') `
        --release --target wasm32-unknown-unknown -p taotao-crypto-wasm
    if ($LASTEXITCODE -ne 0) { throw '构建 wasm 目标失败' }

    $wasmPath = Join-Path $CryptoRoot 'target/wasm32-unknown-unknown/release/taotao_crypto_wasm.wasm'
    $outDir = Join-Path $DistRoot 'wasm'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    # wasm-bindgen 的版本必须与 Cargo.lock 里的 wasm-bindgen crate 版本严格一致。
    # 不一致时的表现非常隐蔽：命令返回码是 0、只打一句含糊的 schema 版本警告，
    # **但 dist 目录里一个文件都不产出**。所以这里显式比对版本。
    $lockVersion = (Select-String -Path (Join-Path $CryptoRoot 'Cargo.lock') `
        -Pattern '^name = "wasm-bindgen"$' -Context 0, 2 |
        Select-Object -First 1).Context.PostContext |
        Select-String -Pattern 'version = "([^"]+)"' |
        ForEach-Object { $_.Matches[0].Groups[1].Value }

    $cli = Get-Command wasm-bindgen -ErrorAction SilentlyContinue
    if (-not $cli) {
        Write-Warn "未找到 wasm-bindgen CLI。请安装与 crate 匹配的版本："
        Write-Host "    cargo install wasm-bindgen-cli --version $lockVersion" -ForegroundColor Yellow
        Write-Ok "原始 .wasm 已产出：$wasmPath"
        Copy-Item -Force $wasmPath (Join-Path $outDir 'taotao_crypto.wasm')
        return
    }

    $cliVersion = (& wasm-bindgen --version) -replace '^wasm-bindgen\s+', ''
    if ($cliVersion -ne $lockVersion) {
        Write-Warn "wasm-bindgen CLI 版本不匹配：CLI=$cliVersion，Cargo.lock=$lockVersion"
        Write-Warn "不匹配时命令会「成功」但一个文件都不产出。请执行："
        Write-Host "    cargo install -f wasm-bindgen-cli --version $lockVersion" -ForegroundColor Yellow
        return
    }

    # `--remove-name-section` / `--remove-producers-section`：产物混淆。
    # wasm-bindgen 输出的模块默认带着 `producers` 段（逐字写着
    # `processed-by walrus <版本> wasm-bindgen <版本> (<commit>)`）和 `name` 段。
    # 这两个 flag 只在**输出**上生效，不影响 JS 胶水的导出名。
    # ⚠️ CI 里有一条断言专门盯着这件事（build.yml「校验元数据已剥离」）——
    # 本地改动这里时别把它漏掉，否则 CI 会红。
    & wasm-bindgen --target web --out-dir $outDir --out-name taotao_crypto `
        --remove-name-section --remove-producers-section $wasmPath
    if ($LASTEXITCODE -ne 0) { throw 'wasm-bindgen 后处理失败' }

    $wasmSize = (Get-Item (Join-Path $outDir 'taotao_crypto_bg.wasm')).Length
    Write-Ok ("产物 taotao_crypto_bg.wasm {0:N0} 字节" -f $wasmSize)
    Write-Ok '同目录下的 taotao_crypto.js 是胶水代码，必须与 .wasm 同批部署'
    Write-Ok '惯用的 camelCase API 见 bindings/wasm/index.ts（手写包装层）'
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

Assert-Cargo

$resolvedPsk = Get-PskOrPlaceholder
if ($resolvedPsk) {
    # 用环境变量传给 cargo build，由 core/build.rs 读取。
    $env:TAOTAO_CRYPTO_PSK = $resolvedPsk
    Write-Ok "已注入 PSK（指纹：$($resolvedPsk.Substring(0, 8))...）"
}

# 字符串混淆密钥同理走环境变量，由 cryptify 这个 proc-macro 读取。
# 只在客户端产物上起作用（.so/.dll/.wasm），服务端 .node 不开 obfuscate。
if (-not [string]::IsNullOrWhiteSpace($ObfuscateKey)) {
    $env:CRYPTIFY_KEY = $ObfuscateKey
    Write-Ok "已注入字符串混淆密钥（长度 $($ObfuscateKey.Length) 字符）"
}
else {
    Write-Warn '未提供 CRYPTIFY_KEY，字符串混淆将使用 cryptify 的内置默认密钥（仍可复现，但更易被解开）'
}

Push-Location $CryptoRoot
try {
    if ($Target -in @('all', 'android')) { Build-Android $resolvedPsk }
    if ($Target -in @('all', 'windows')) { Build-Windows $resolvedPsk }
    if ($Target -in @('all', 'node'))    { Build-Node $resolvedPsk }
    if ($Target -in @('all', 'wasm'))    { Build-Wasm $resolvedPsk }
}
finally {
    Pop-Location
}

# 客户端产物的字符串混淆属于「配置对了才生效」的那类：feature 没接上时
# 构建、测试、拷贝全都正常，产物却悄悄退回明文。所以本地也断言一次，
# 而不是只在 CI 上查 —— 本地迭代恰恰是最容易临时关掉 feature 的场景。
if ($Target -ne 'node') {
    $obfTargets = @()
    foreach ($pattern in @('android\**\*.so', 'windows\*.dll', 'wasm\*.wasm')) {
        $obfTargets += @(Get-ChildItem -Path (Join-Path $DistRoot $pattern) `
                -File -ErrorAction SilentlyContinue)
    }
    if ($obfTargets.Count -gt 0) {
        Write-Step '校验字符串混淆'
        $bash = Get-Command bash -ErrorAction SilentlyContinue
        if ($bash) {
            # 交给 shell 的路径必须转成正斜杠：Git Bash 会把反斜杠当转义符。
            $paths = $obfTargets | ForEach-Object { $_.FullName.Replace('\', '/') }
            & $bash.Source (Join-Path $PSScriptRoot 'check-obfuscated.sh') @paths
            if ($LASTEXITCODE -ne 0) { throw '字符串混淆校验未通过' }
        }
        else {
            Write-Warn '未找到 bash，跳过字符串混淆校验（CI 上仍会执行）'
        }
    }
}

Write-Step '完成'
Get-ChildItem -Path $DistRoot -Recurse -File -ErrorAction SilentlyContinue |
    ForEach-Object {
        $relative = $_.FullName.Substring($DistRoot.Length + 1)
        Write-Host ("  {0,-48} {1,10:N0} 字节" -f $relative, $_.Length)
    }

if (-not $resolvedPsk) {
    Write-Host ""
    Write-Host '!! 本次构建使用占位密钥，产物不可用于生产 !!' -ForegroundColor Red
    Write-Host '   重新构建时设置 TAOTAO_CRYPTO_PSK（64 个十六进制字符）。' -ForegroundColor Red
}
