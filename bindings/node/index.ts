/**
 * 桃桃音乐加密层 —— Node / TypeScript 侧参考绑定。
 *
 * 这个文件**不在构建路径里**，是给接入方复制的参考实现。接入时放到
 * `server/src/native/` 下即可。
 *
 * `.node` 是平台相关的二进制。CI 必须为部署目标平台构建 ——
 * 把 Windows 上编的 `.node` 推到 Linux 容器里，`require()` 会抛
 * `invalid ELF header`，而错误信息完全不会提到「平台不匹配」。
 */

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** napi-rs 生成的模块接口。 */
interface NativeModule {
  Client: new (pskId: string, pskHex: string) => NativeClient;
  Server: new () => NativeServer;
  protocolVersion(): number;
  hasRealPsk(): boolean;
  aadContext(method: string, pathAndQuery: string): Buffer;
  parseHeader(value: string): [string, string] | null;
}

interface NativeClient {
  handshake(nowMs: number): Buffer;
  finish(serverHello: Buffer, nowMs: number): void;
  seal(aad: Buffer, plaintext: Buffer, nowMs: number): Buffer;
  open(aad: Buffer, frame: Buffer, nowMs: number): Buffer;
  headerForFrame(frame: Buffer): string;
  readonly sessionId: string;
  needsRekey(nowMs: number): boolean;
  hasSession(nowMs: number): boolean;
  sessionRemainingMs(nowMs: number): number;
}

interface NativeServer {
  putPsk(pskId: string, pskHex: string): void;
  removePsk(pskId: string): boolean;
  accept(clientHello: Buffer, nowMs: number): Buffer;
  seal(sessionIdHex: string, aad: Buffer, plaintext: Buffer, nowMs: number): Buffer;
  open(sessionIdHex: string, aad: Buffer, frame: Buffer, nowMs: number): Buffer;
  hasSession(sessionIdHex: string, nowMs: number): boolean;
  dropSession(sessionIdHex: string): boolean;
  sweepExpired(nowMs: number): number;
  readonly sessionCount: number;
  readonly pskCount: number;
}

let native: NativeModule | null = null;

/**
 * 惰性加载原生模块。
 *
 * 用 `createRequire` 而不是直接 `import`：ESM 里没法 `import` 一个 `.node`
 * 二进制，而 ts-node / tsc 的输出格式取决于 tsconfig，不能假设。
 */
function load(): NativeModule {
  if (native) return native;
  const require = createRequire(import.meta.url);
  const here = dirname(fileURLToPath(import.meta.url));
  // 产物名固定为 taotao_crypto.node，构建脚本会放到这个相对位置。
  native = require(join(here, "taotao_crypto.node")) as NativeModule;
  return native;
}

/** HTTP 头名。 */
export const CRYPTO_HEADER = "X-Taotao-Crypto";

/** 加密层异常。 */
export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

/** 协议版本。 */
export function protocolVersion(): number {
  return load().protocolVersion();
}

/**
 * 当前二进制里是否注入了真实 PSK。
 *
 * **生产环境必须在启动时检查这个值并拒绝启动。** 返回 false 说明构建时没设
 * `TAOTAO_CRYPTO_PSK`，用的是源码里的占位密钥 —— 而占位密钥写在公开源码里，
 * 任何人都能算出来。
 */
export function hasRealPsk(): boolean {
  return load().hasRealPsk();
}

/**
 * 构造 AAD 上下文。
 *
 * 必须含**方法和完整的 path + query**。只传 path 的话，攻击者可以把
 * `GET /playlists/1` 的密文改发成 `DELETE /playlists/1`；
 * 不含 query 的话，攻击者可以保留密文只改 `page` 参数来遍历数据。
 */
export function aadContext(method: string, pathAndQuery: string): Buffer {
  return load().aadContext(method, pathAndQuery);
}

/** 解析 `X-Taotao-Crypto` 头值。格式非法返回 null。 */
export function parseCryptoHeader(value: string): { sessionId: string; seq: number } | null {
  const parsed = load().parseHeader(value);
  if (!parsed) return null;
  return { sessionId: parsed[0], seq: Number(parsed[1]) };
}

/** 客户端加密通道。 */
export class TaotaoCryptoClient {
  private readonly inner: NativeClient;

  constructor(pskId: string, pskHex: string) {
    this.inner = new (load().Client)(pskId, pskHex);
  }

  get sessionId(): string {
    return this.inner.sessionId;
  }

  needsRekey(nowMs: number = Date.now()): boolean {
    return this.inner.needsRekey(nowMs);
  }

  hasSession(nowMs: number = Date.now()): boolean {
    return this.inner.hasSession(nowMs);
  }

  sessionRemainingMs(nowMs: number = Date.now()): number {
    return this.inner.sessionRemainingMs(nowMs);
  }

  /** 发起握手，返回 ClientHello。 */
  handshake(nowMs: number = Date.now()): Buffer {
    return this.inner.handshake(nowMs);
  }

  /** 处理 ServerHello，建立会话。 */
  finish(serverHello: Buffer, nowMs: number = Date.now()): void {
    this.inner.finish(serverHello, nowMs);
  }

  seal(aad: Buffer, plaintext: Buffer, nowMs: number = Date.now()): Buffer {
    return this.inner.seal(aad, plaintext, nowMs);
  }

  open(aad: Buffer, frame: Buffer, nowMs: number = Date.now()): Buffer {
    return this.inner.open(aad, frame, nowMs);
  }

  headerForFrame(frame: Buffer): string {
    return this.inner.headerForFrame(frame);
  }
}

/**
 * 服务端加密通道。
 *
 * 一个进程内**只需要一个实例**：它内部维护了 PSK 表和会话表。
 * 每次请求 new 一个的话，会话表永远是空的，所有请求都会「会话不存在」。
 */
export class TaotaoCryptoTokens {
  private readonly inner: NativeServer;

  constructor() {
    this.inner = new (load().Server)();
  }

  /** 加入 / 更新一条 PSK。轮换期可以同时持有多条。 */
  putPsk(pskId: string, pskHex: string): void {
    this.inner.putPsk(pskId, pskHex);
  }

  /** 移除一条 PSK。 */
  removePsk(pskId: string): boolean {
    return this.inner.removePsk(pskId);
  }

  /** 处理 ClientHello，返回 ServerHello。 */
  accept(clientHello: Buffer, nowMs: number = Date.now()): Buffer {
    return this.inner.accept(clientHello, nowMs);
  }

  seal(
    sessionIdHex: string,
    aad: Buffer,
    plaintext: Buffer,
    nowMs: number = Date.now(),
  ): Buffer {
    return this.inner.seal(sessionIdHex, aad, plaintext, nowMs);
  }

  open(sessionIdHex: string, aad: Buffer, frame: Buffer, nowMs: number = Date.now()): Buffer {
    return this.inner.open(sessionIdHex, aad, frame, nowMs);
  }

  hasSession(sessionIdHex: string, nowMs: number = Date.now()): boolean {
    return this.inner.hasSession(sessionIdHex, nowMs);
  }

  dropSession(sessionIdHex: string): boolean {
    return this.inner.dropSession(sessionIdHex);
  }

  sweepExpired(nowMs: number = Date.now()): number {
    return this.inner.sweepExpired(nowMs);
  }

  get sessionCount(): number {
    return this.inner.sessionCount;
  }

  get pskCount(): number {
    return this.inner.pskCount;
  }
}

/**
 * 必须豁免加密的路径。
 *
 * 漏一条的表现是「某个功能静默失效」，而且不会有任何报错：
 * - `/search` 是裸 NDJSON，要逐行 flush，整体加密会直接让它搜不到东西
 * - 歌词是 `text/plain` 裸文本，旧客户端把响应体直接当歌词展示
 * - 二进制上传（APK / jar / 补丁）走的是原始字节流
 * - `coverUrl` / `apkUrl` 是客户端直接交给图片库和下载器的，不带鉴权头
 * - 静态资源与健康检查
 *
 * 完整清单与逐条理由见 `docs/design.md` 的「与现有契约的边界」章节。
 */
export const ENCRYPTION_EXEMPT_PATTERNS: readonly RegExp[] = [
  /^\/health$/,
  /^\/api\/v1\/search/,
  /^\/api\/v1\/songs\/[^/]+\/(lyric|play)/,
  /^\/api\/v1\/app\/admin\/(releases|patches)/,
  /^\/api\/v1\/desktop\/admin\/(jars|patches|artifacts)/,
  /^\/admin(\/|$)/,
  /^\/share(\/|$)/,
  /^\/s\/[A-Za-z0-9_-]+$/,
];

/** 判断某个路径是否应当豁免加密。 */
export function isExemptFromEncryption(pathname: string): boolean {
  return ENCRYPTION_EXEMPT_PATTERNS.some((pattern) => pattern.test(pathname));
}
