//! 构建脚本：napi-rs 需要它来生成模块注册代码。
//!
//! 少了这一行，编译能过、`require()` 也不会报错，但导出对象是空的 ——
//! 所有 `client.handshake(...)` 都会是 `undefined is not a function`。

fn main() {
    napi_build::setup();
}
