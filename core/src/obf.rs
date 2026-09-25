//! 字符串字面量混淆。
//!
//! 客户端产物（Android `.so`、Windows `.dll`、Web `.wasm`）开启 `obfuscate`
//! feature，协议标签与错误文案不再以明文出现在二进制里；服务端（`.node`）
//! **不开启** —— 它不对外分发，混淆只会白付运行时开销。
//!
//! ## 为什么选 `cryptify`
//!
//! 它是 **MIT** 许可的编译期字符串加密宏（不像 `goldberg` 那样是 GPL，
//! 链接进产物不会污染整个 App 的许可），并且**支持固定密钥**：密钥取自
//! `CRYPTIFY_KEY` 环境变量，缺省用内置固定值。
//!
//! 「固定密钥」是硬要求。若密钥每次构建随机，同一份源码产出的二进制就会
//! 逐字节不同，而更新链路是**按 sha256 寻址**的（见 `docs/design.md` 与
//! `README.md` 第六节），会直接失效。实测（wasm32-unknown-unknown，连编
//! 两次比对 sha256）确认 `cryptify` 满足可复现构建。
//!
//! ## 为什么两个分支都返回 `String`
//!
//! `cryptify::encrypt_string!` 返回 `String`（模板在运行期解出来）。如果关闭
//! feature 时退回 `&'static str`，调用点的类型就会随 feature 变化，同一份代码
//! 在开与不开两种配置下编译结果不同 —— 这类问题只在 CI 的某一种配置里暴露，
//! 很难查。所以两个分支统一返回 `String`，代价是关闭 feature 时多一次分配，
//! 而这些调用点全部落在握手/错误处理这类冷路径上。
//!
//! ## 覆盖边界（务必如实理解）
//!
//! 本模块**只**能隐藏我们自己写的字面量。以下两类泄露来自编译器而非源码，
//! 混淆覆盖不到，需要另外的手段：
//!
//! - `panic!` 的 `Location` 常量里的**本项目源码路径**（`core/src/frame.rs` 等）
//! - 预编译 std 带来的 `/rustc/<commit>/...` 与 registry 依赖的精确版本号
//!
//! 用 `tools/scan-leaks.py` 可以对任意产物量化这两类的残留条数。

/// 混淆一个字符串字面量。
///
/// 开启 `obfuscate` 时走编译期加密，关闭时退化为普通 `String`。
/// 两种模式返回**同一个类型**，理由见模块文档。
///
/// ```ignore
/// let label = obf!("taotao-crypto-v1/handshake");
/// ```
///
/// 用 `pub(crate) use` 而不是 `#[macro_export]`：这个宏只在 core 内部用，
/// 而 `#[macro_export]` 会把 `::cryptify` 这样的绝对路径固化进展开结果 ——
/// 那样一旦有别的 crate 调用它，就会因为「调用方没有把 cryptify 列为直接
/// 依赖」而编译失败，且报错指向宏展开处，极难定位。
#[cfg(feature = "obfuscate")]
pub(crate) use cryptify::encrypt_string as obf;

/// 见开启 `obfuscate` 时的同名宏。
#[cfg(not(feature = "obfuscate"))]
macro_rules! obf {
    ($s:literal) => {
        ::std::string::String::from($s)
    };
}
#[cfg(not(feature = "obfuscate"))]
pub(crate) use obf;

/// 用混淆模板格式化，按顺序填充 `{}`。
///
/// ```ignore
/// obf_fmt!(f, "时间戳超出允许窗口：偏差 {} ms，上限 {} ms", skew_ms, limit_ms)
/// ```
///
/// 一般只在手写 `Display` 时用得到 —— `#[error("...")]` 那种属性位置塞不进宏，
/// 所以 `error.rs` 放弃了 `thiserror` 派生，改成手写 `Display` 配合本宏。
macro_rules! obf_fmt {
    ($f:expr, $tpl:literal $(, $arg:expr)* $(,)?) => {
        $crate::obf::write_obf(
            $f,
            &$crate::obf::obf!($tpl),
            &[$(&$arg as &dyn ::core::fmt::Display),*],
        )
    };
}
pub(crate) use obf_fmt;

/// 把混淆模板写进 [`core::fmt::Formatter`]，按顺序填充 `{}` 占位符。
///
/// 一般不直接调用，用 [`crate::obf_fmt!`] 更顺手。
///
/// 之所以不直接用 `write!`：`write!` 的模板必须是**编译期字面量**，而混淆后的
/// 模板是运行期才解出来的 `String`。这里只支持 `{}`，不支持 `{:?}`、命名参数、
/// 宽度与对齐 —— 错误文案只用得到顺序 `{}`，而支持全部语法等于重写一个格式化
/// 引擎，不值得。
///
/// 参数比占位符多时，多出来的会被忽略（不 panic）；占位符比参数多时，多出来的
/// 占位符原样留在输出里。两种都是调用方的 bug，靠 `#[cfg(debug_assertions)]`
/// 下的 [`debug_check_obf`] 在测试里拦下。
pub fn write_obf(
    f: &mut core::fmt::Formatter<'_>,
    tpl: &str,
    args: &[&dyn core::fmt::Display],
) -> core::fmt::Result {
    let mut segs = tpl.split("{}");
    if let Some(head) = segs.next() {
        f.write_str(head)?;
    }
    for arg in args {
        f.write_fmt(format_args!("{arg}"))?;
        if let Some(seg) = segs.next() {
            f.write_str(seg)?;
        }
    }
    debug_check_obf(tpl, args.len());
    Ok(())
}

/// 开发构建下的自检：模板里的 `{}` 个数必须与传参个数一致。
///
/// 只在 `debug_assertions` 下存在 —— release 产物里连这个符号都不该有，
/// 否则 `obf.rs` 这个文件名会白送给逆向者。
#[cfg(debug_assertions)]
#[inline]
fn debug_check_obf(tpl: &str, arg_count: usize) {
    let placeholders = tpl.matches("{}").count();
    debug_assert_eq!(
        placeholders, arg_count,
        "混淆模板的占位符个数（{placeholders}）与传参个数（{arg_count}）不一致：{tpl}"
    );
}

/// 见 [`debug_check_obf`] 的 release 版本。
#[cfg(not(debug_assertions))]
#[inline(always)]
fn debug_check_obf(_tpl: &str, _arg_count: usize) {}

/// 同 [`write_obf`]，但返回 `String` 而不是写进 `Formatter`。
///
/// 给「需要把消息存进结构体」的调用点用 —— 典型是
/// [`CryptoError::PskNotConfigured`](crate::CryptoError::PskNotConfigured)
/// 这类带 `String` 明细的变体，它们没法直接写 `Formatter`。
///
/// 和 [`write_obf`] 一样只支持顺序 `{}`。
pub fn format_obf(tpl: &str, args: &[&dyn core::fmt::Display]) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(tpl.len() + 16);
    let mut segs = tpl.split("{}");
    if let Some(head) = segs.next() {
        out.push_str(head);
    }
    for arg in args {
        let _ = write!(out, "{arg}");
        if let Some(seg) = segs.next() {
            out.push_str(seg);
        }
    }
    debug_check_obf(tpl, args.len());
    out
}

/// 用混淆模板格式化，返回 `String`。见 [`format_obf`]。
///
/// ```ignore
/// obf_string!("psk_id 长度 {} 超过上限 {}", id.len(), MAX_PSK_ID_LEN)
/// ```
macro_rules! obf_string {
    ($tpl:literal $(, $arg:expr)* $(,)?) => {
        $crate::obf::format_obf(
            &$crate::obf::obf!($tpl),
            &[$(&$arg as &dyn ::core::fmt::Display),*],
        )
    };
}
pub(crate) use obf_string;
