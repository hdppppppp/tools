#!/usr/bin/env node
// 端到端冒烟测试：验证编译产物真的能跑，而不只是「编译通过」。
//
// 为什么值得单独做这一步：`cargo build` 成功和 `.node` 能被 dlopen 是两件事。
// 常见的「构建绿、运行炸」有三种，全都不会被 cargo 发现：
//   ① strip 配置改错导致动态符号表被剥 —— `require()` 直接抛
//      「不是有效的 Win32 应用程序」或符号找不到；
//   ② 交叉编译工具链用错（比如用 host 的 linker）—— 加载即崩；
//   ③ PSK 构建期注入路径断了 —— 加载成功，但 hasRealPsk() 悄悄变成 false。
//
// 这个脚本对任意一份 `.node` 产物都能跑，CI 与本地共用同一份断言，
// 避免「CI 测的和本地跑的不是一套」。
//
// 用法：
//   node tools/smoke-test.cjs <taotao_crypto.node 路径> [--expect-real-psk]
//
// 退出码：0 通过，1 断言失败，2 用法错误。

'use strict';

const path = require('node:path');
const assert = require('node:assert/strict');

const args = process.argv.slice(2);
const modulePath = args.find((a) => !a.startsWith('--'));
const expectRealPsk = args.includes('--expect-real-psk');

if (!modulePath) {
  console.error('用法：node tools/smoke-test.cjs <taotao_crypto.node 路径> [--expect-real-psk]');
  process.exit(2);
}

const checks = [];
function check(name, fn) {
  try {
    fn();
    checks.push({ name, ok: true });
  } catch (err) {
    checks.push({ name, ok: false, message: err.message });
  }
}

// ---------------------------------------------------------------------------
// 加载产物
// ---------------------------------------------------------------------------
let m;
try {
  m = require(path.resolve(modulePath));
} catch (err) {
  console.error(`无法加载 ${modulePath}`);
  console.error(`  ${err.message}`);
  console.error('');
  console.error('最可能的原因：strip 配置把动态符号表剥掉了。');
  console.error('检查 Cargo.toml 的 [profile.release] strip 应为 "symbols" 而不是 "debuginfo"');
  console.error('以外的值（"symbols" 只剥静态符号表，动态符号表保留）。');
  process.exit(1);
}

// 冒烟测试用**运行时传入**的固定 PSK，与构建期注入的那份互不影响。
// 这样无论产物里有没有真密钥，功能断言都能跑。
const PSK_ID = 'ci-smoke';
const PSK_HEX = 'a1'.repeat(32);
// 设备号：协议 v2 起客户端与服务端必须用同一个，握手才成立。
const DEVICE_ID = 'ci-smoke-device';

// ---------------------------------------------------------------------------
// 1. 协议版本与构建期 PSK 状态
// ---------------------------------------------------------------------------
check('协议版本为 1', () => {
  assert.equal(m.protocolVersion(), 1);
});

check('hasRealPsk() 返回布尔值', () => {
  assert.equal(typeof m.hasRealPsk(), 'boolean');
});

if (expectRealPsk) {
  check('构建期已注入真实 PSK', () => {
    assert.equal(
      m.hasRealPsk(),
      true,
      '产物不含真实 PSK。构建时 TAOTAO_CRYPTO_PSK 为空或未传到 cargo。',
    );
  });
}

// ---------------------------------------------------------------------------
// 2. 握手
// ---------------------------------------------------------------------------
const client = new m.Client(PSK_ID, PSK_HEX, DEVICE_ID);
const server = new m.Server();
server.putPsk(PSK_ID, PSK_HEX);

const now = Date.now();
const hello = client.handshake(now);

check('ClientHello 非空', () => {
  assert.ok(hello && hello.length > 0);
});

const serverHello = server.accept(hello, DEVICE_ID, now);
client.finish(serverHello, now);

const sessionId = client.sessionId;

check('握手后客户端有会话 ID', () => {
  assert.match(sessionId, /^[0-9a-f]{32}$/, `实际值：${JSON.stringify(sessionId)}`);
});

check('服务端登记了 1 条会话', () => {
  assert.equal(server.sessionCount, 1);
});

check('客户端报告会话可用', () => {
  assert.equal(client.hasSession(now), true);
});

// ---------------------------------------------------------------------------
// 3. 双向加解密（含非 ASCII，验证 UTF-8 在 Buffer 往返里没被截断）
// ---------------------------------------------------------------------------
const reqAad = m.aadContext('POST', '/api/v1/ci-smoke');
const reqPlain = Buffer.from(JSON.stringify({ name: '夜跑', n: 42 }), 'utf8');
const reqFrame = client.seal(reqAad, reqPlain, now);

check('请求方向：客户端加密 → 服务端解密', () => {
  const out = server.open(sessionId, reqAad, reqFrame, now);
  assert.equal(out.toString('utf8'), reqPlain.toString('utf8'));
});

check('从帧反推出的头值格式正确', () => {
  assert.match(client.headerForFrame(reqFrame), /^v\d+\.[0-9a-f]+\.[0-9]+$/);
});

const respAad = m.aadContext('200', '/api/v1/ci-smoke');
const respFrame = server.seal(sessionId, respAad, Buffer.from('ok', 'utf8'), now);

check('响应方向：服务端加密 → 客户端解密', () => {
  const out = client.open(respAad, respFrame, now);
  assert.equal(out.toString('utf8'), 'ok');
});

// ---------------------------------------------------------------------------
// 4. 防重放：同一帧不能消费两次
// ---------------------------------------------------------------------------
check('重放被拒绝', () => {
  assert.throws(
    () => server.open(sessionId, reqAad, reqFrame, now),
    '同一个帧被解密了两次，防重放滑窗没生效',
  );
});

// ---------------------------------------------------------------------------
// 5. AAD 端点绑定：换个 AAD 就不能解同一帧
// ---------------------------------------------------------------------------
check('跨端点重放被拒绝（AAD 绑定生效）', () => {
  const frame = client.seal(reqAad, reqPlain, now);
  const otherAad = m.aadContext('DELETE', '/api/v1/ci-smoke');
  assert.throws(
    () => server.open(sessionId, otherAad, frame, now),
    '换掉 AAD 后仍能解密，说明 AAD 没有真正参与认证',
  );
});

// ---------------------------------------------------------------------------
// 6. 错误 PSK 无法握手，且「id 不认识」与「密钥不对」必须不可区分
// ---------------------------------------------------------------------------
function acceptErrorMessage(hello) {
  try {
    server.accept(hello, DEVICE_ID, now);
    return null;
  } catch (err) {
    return err.message;
  }
}

check('错误 PSK 握手被拒绝', () => {
  const badClient = new m.Client(PSK_ID, 'b2'.repeat(32), DEVICE_ID);
  const badHello = badClient.handshake(now);
  assert.throws(
    () => server.accept(badHello, DEVICE_ID, now),
    '错误 PSK 也能握手成功，PSK 认证形同虚设',
  );
});

check('未知 psk_id 与错误密钥返回同一种失败', () => {
  // 两者必须不可区分，否则攻击者可以拿不同的 id 反复握手，靠错误消息把
  // 服务端配置了哪些 psk_id 枚举出来 —— 一旦确认 id，他就省掉了猜 id 这一步。
  const wrongKey = acceptErrorMessage(
    new m.Client(PSK_ID, 'b2'.repeat(32), DEVICE_ID).handshake(now),
  );
  const unknownId = acceptErrorMessage(
    new m.Client('no-such-psk-id', 'b2'.repeat(32), DEVICE_ID).handshake(now),
  );
  assert.ok(wrongKey, '错误密钥居然握手成功了');
  assert.ok(unknownId, '未知 psk_id 居然握手成功了');
  assert.equal(
    wrongKey,
    unknownId,
    `两种失败的消息必须一致，否则可以枚举 psk_id：\n` +
      `    错误密钥 → ${wrongKey}\n` +
      `    未知 id  → ${unknownId}`,
  );
});

// ---------------------------------------------------------------------------
// 7. 头值解析
// ---------------------------------------------------------------------------
check('parseHeader 能解析自己产出的头值', () => {
  const parsed = m.parseHeader(client.headerForFrame(reqFrame));
  assert.ok(parsed, '合法头值被解析成 null');
  assert.equal(parsed[0], sessionId);
});

check('parseHeader 对非法输入返回 null', () => {
  assert.equal(m.parseHeader('garbage'), null);
});

// ---------------------------------------------------------------------------
// 汇报
// ---------------------------------------------------------------------------
const failed = checks.filter((c) => !c.ok);
for (const c of checks) {
  console.log(`${c.ok ? '  通过' : '  失败'}  ${c.name}`);
  if (!c.ok) console.log(`        ${c.message}`);
}
console.log('');
console.log(`冒烟测试：${checks.length - failed.length}/${checks.length} 项通过`);
console.log(`构建期 PSK 状态：hasRealPsk() = ${m.hasRealPsk()}`);

process.exit(failed.length === 0 ? 0 : 1);
