//! 加密层性能与分配基准。
//!
//! 这个基准刻意回答两个问题，而不是一个：
//!
//! 1. **每次操作花多少时间** —— 在移动端直接换算成 CPU 占用和耗电。
//! 2. **每次操作分配几次堆内存** —— Android 上每次分配都要过系统分配器，
//!    并给 GC 制造压力。分配次数比耗时更稳定，也更能证明「优化确实生效了」，
//!    因为耗时会被 CPU 频率、缓存状态和后台负载干扰，分配次数不会。
//!
//! 用 `harness = false` 手写而不是引入 criterion：本项目刻意不增加仅供测试的
//! 重型依赖（同 `totp.ts` 自实现而非引第三方库的理由），这里只需要均值，
//! 不需要统计显著性。
//!
//! 运行：`cargo bench -p taotao-crypto-core`
//!
//! ⚠️ 基准必须用 `--release` 跑才有意义。默认的 `cargo bench` 会用
//! `[profile.release]`，而它设的是 `opt-level = "z"`（优先体积）——
//! 也就是说**基准跑出来的就是线上产物的真实性能**，不是理想值。

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use taotao_crypto_core::frame::{open_frame, seal_frame};
use taotao_crypto_core::kdf::{random_array, KEY_LEN};
use taotao_crypto_core::protocol::aad_context;
use taotao_crypto_core::{
    accept_client_hello, build_psk_or_placeholder, ClientHandshake, HelloReplayCache, OsRandom,
    PskStore,
};

// ---------------------------------------------------------------------------
// 分配计数器
// ---------------------------------------------------------------------------

/// 只统计分配次数与字节数，行为完全委托给系统分配器。
///
/// 这是**仅基准使用**的代码：它只存在于 `benches/` 这个独立 crate 里，
/// 不会被链进任何交付产物（`.so` / `.dll` / `.node` / `.wasm` 都不含它）。
struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

// ---------------------------------------------------------------------------
// 测量框架
// ---------------------------------------------------------------------------

struct Measurement {
    ns_per_op: f64,
    allocs_per_op: f64,
    bytes_per_op: f64,
}

/// 跑 `iters` 次 `f`，返回单次耗时与单次分配。
///
/// 先热身再清零计数，避免把首次调用的惰性初始化算进来。
fn measure<F: FnMut()>(iters: usize, mut f: F) -> Measurement {
    for _ in 0..(iters / 10).max(1) {
        f();
    }

    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);

    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();

    let allocs = ALLOC_COUNT.load(Ordering::Relaxed);
    let bytes = ALLOC_BYTES.load(Ordering::Relaxed);

    Measurement {
        ns_per_op: elapsed.as_nanos() as f64 / iters as f64,
        allocs_per_op: allocs as f64 / iters as f64,
        bytes_per_op: bytes as f64 / iters as f64,
    }
}

/// 报文越大迭代次数越少，否则基准本身要跑几分钟。
fn iters_for(len: usize) -> usize {
    match len {
        0..=64 => 200_000,
        65..=1024 => 100_000,
        1025..=16_384 => 20_000,
        _ => 3_000,
    }
}

fn print_header(title: &str) {
    println!("\n=== {title} ===");
    println!(
        "{:<26} {:>12} {:>14} {:>12} {:>12}",
        "场景", "单次耗时", "吞吐", "分配次数", "分配字节"
    );
}

fn print_row(label: &str, len: usize, m: &Measurement) {
    // 字节/秒 = len / (ns × 1e-9) = len / ns × 1e9
    let throughput = if len > 0 && m.ns_per_op > 0.0 {
        format!(
            "{:.0} MB/s",
            len as f64 / m.ns_per_op * 1e9 / 1024.0 / 1024.0
        )
    } else {
        "-".to_string()
    };
    let time = if m.ns_per_op >= 1_000.0 {
        format!("{:.2} us", m.ns_per_op / 1_000.0)
    } else {
        format!("{:.0} ns", m.ns_per_op)
    };
    println!(
        "{:<26} {:>12} {:>14} {:>12.2} {:>12.0}",
        label, time, throughput, m.allocs_per_op, m.bytes_per_op
    );
}

// ---------------------------------------------------------------------------
// 场景
// ---------------------------------------------------------------------------

/// HTTP 报文的真实尺寸分布：小 JSON、普通列表响应、较大的歌单。
const SIZES: [usize; 5] = [0, 256, 1024, 8192, 65_536];

const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const SID: [u8; 16] = [0x11; 16];
const NOW: u64 = 1_700_000_000_000;

fn bench_random_source() {
    print_header("随机源（每帧取 AEAD nonce 用）");
    let m = measure(200_000, || {
        black_box(random_array::<12>().unwrap());
    });
    print_row("OsRandom 取 12 字节", 0, &m);
    println!("  注：这是**系统调用**，不是普通函数调用。");
}

fn bench_seal() {
    print_header("封装（seal_frame，AAD 上下文预先算好）");
    for len in SIZES {
        let plaintext = vec![0xA5u8; len];
        let ctx = b"POST /api/v1/favorites";
        let iters = iters_for(len);
        let m = measure(iters, || {
            black_box(seal_frame(&KEY, &SID, 1, NOW, ctx, &plaintext).unwrap());
        });
        print_row(&format!("seal_frame {len} B"), len, &m);
    }
}

fn bench_seal_with_context() {
    print_header("封装（含调用方构造 AAD 上下文）");
    for len in SIZES {
        let plaintext = vec![0xA5u8; len];
        let iters = iters_for(len);
        let m = measure(iters, || {
            let ctx = aad_context("POST", "/api/v1/favorites");
            black_box(seal_frame(&KEY, &SID, 1, NOW, &ctx, &plaintext).unwrap());
        });
        print_row(&format!("aad_context + seal {len} B"), len, &m);
    }
}

fn bench_open() {
    print_header("解封（open_frame）");
    for len in SIZES {
        let plaintext = vec![0xA5u8; len];
        let ctx = b"POST /api/v1/favorites";
        let frame = seal_frame(&KEY, &SID, 1, NOW, ctx, &plaintext).unwrap();
        let iters = iters_for(len);
        let m = measure(iters, || {
            black_box(open_frame(&KEY, &SID, ctx, &frame).unwrap());
        });
        print_row(&format!("open_frame {len} B"), len, &m);
    }
}

fn bench_session_roundtrip() {
    print_header("会话层往返（Session::seal + Session::open，含防重放滑窗）");

    let (psk, _) = build_psk_or_placeholder("bench").unwrap();
    let mut rng = OsRandom;
    let (handshake, hello) = ClientHandshake::start(psk.clone(), b"bench-device", NOW, &mut rng).unwrap();
    let mut store = PskStore::new();
    store.insert(psk);
    let mut cache = HelloReplayCache::new();
    let accepted = accept_client_hello(&store, &hello, b"bench-device", NOW, &mut cache, &mut rng).unwrap();
    let mut client = handshake.finish(&accepted.response, NOW).unwrap();
    let mut server = accepted.session;

    let ctx = b"POST /api/v1/favorites";
    let payload = vec![0xA5u8; 1024];

    // 会话会因帧数/序号耗尽而失效，所以每 N 轮重建一次。
    const REBUILD_EVERY: usize = 4096;
    let mut n = 0usize;
    let m = measure(20_000, || {
        if n % REBUILD_EVERY == 0 {
            let (h, hello) =
                ClientHandshake::start(build_psk_or_placeholder("bench").unwrap().0, b"bench-device", NOW, &mut rng)
                    .unwrap();
            let mut cache = HelloReplayCache::new();
            let acc = accept_client_hello(&store, &hello, b"bench-device", NOW, &mut cache, &mut rng).unwrap();
            client = h.finish(&acc.response, NOW).unwrap();
            server = acc.session;
        }
        n += 1;

        let sealed = client.seal(ctx, &payload, NOW).unwrap();
        black_box(server.open(ctx, &sealed.bytes, NOW).unwrap());
    });
    print_row("seal + open 1024 B", 1024, &m);
}

fn bench_handshake() {
    print_header("握手（每次新建会话付一次）");

    let (psk, _) = build_psk_or_placeholder("bench").unwrap();
    let mut store = PskStore::new();
    store.insert(psk);
    let mut rng = OsRandom;

    let m = measure(5_000, || {
        let (h, hello) =
            ClientHandshake::start(build_psk_or_placeholder("bench").unwrap().0, b"bench-device", NOW, &mut rng)
                .unwrap();
        let mut cache = HelloReplayCache::new();
        let acc = accept_client_hello(&store, &hello, b"bench-device", NOW, &mut cache, &mut rng).unwrap();
        black_box(h.finish(&acc.response, NOW).unwrap());
    });
    print_row("ClientHello + ServerHello", 0, &m);
}

fn main() {
    println!("桃桃音乐加密层基准（{}-bit 指针）", usize::BITS);
    println!("耗时列越小越好；分配次数列是 Android 上真正决定 GC 压力的指标。");
    println!("⚠️ 换 `opt-level` 之后必须重跑：本仓库实测它能让握手差 29 倍。");

    bench_random_source();
    bench_seal();
    bench_seal_with_context();
    bench_open();
    bench_session_roundtrip();
    bench_handshake();

    println!();
}
