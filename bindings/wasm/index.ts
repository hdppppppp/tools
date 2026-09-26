/**
 * 桃桃音乐加密层 —— Web / TypeScript 包装层。
 *
 * 这一层把 wasm-bindgen 生成的 snake_case 底层接口包成惯用的 camelCase API，
 * 与 Kotlin（`bindings/kotlin/NativeCrypto.kt`）和 Node（`bindings/node/index.ts`）
 * 两个包装层保持一致的调用体验。
 *
 * ## 用法
 *
 * ```ts
 * import init, { TaotaoCryptoClient } from "./taotao_crypto.js";
 * await init();                       // 加载并实例化 .wasm
 * const client = new TaotaoCryptoClient("prod-v1", pskHex, "");  // Web 无设备号，传空串
 * ```
 *
 * ## ⚠️ Web 端不该内嵌 PSK
 *
 * 分享页 `s/{token}` 是**公开**的：代码可以随便读、wasm 可以随便下。
 * 把服务端 PSK 编进 wasm 等于公开它。分享页只需要调公开接口，不需要握手。
 *
 * 真要给分享页加密，应该用「匿名会话 + 短时效令牌」：
 * 服务端给每个访问者签发一个一次性的、只在本次浏览有效的会话，
 * 而不是让所有人共享一条长期密钥。
 */

/** wasm-bindgen 生成的底层模块形状（`wasm-bindgen --target web` 的产物）。 */
export interface WasmModule {
  default: () => Promise<unknown>;
  Client: new (psk_id: string, psk_hex: string, device_id: string) => WasmClient;
  Server: new () => WasmServer;
  protocol_version(): number;
  has_real_psk(): boolean;
  aad_context(method: string, path_and_query: string): Uint8Array;
  parse_header(value: string): string[] | undefined;
}

interface WasmClient {
  handshake(now_ms: number): Uint8Array;
  finish(server_hello: Uint8Array, now_ms: number): void;
  seal(aad: Uint8Array, plaintext: Uint8Array, now_ms: number): Uint8Array;
  open(aad: Uint8Array, frame: Uint8Array, now_ms: number): Uint8Array;
  header_for_frame(frame: Uint8Array): string;
  readonly session_id: string;
  needs_rekey(now_ms: number): boolean;
  has_session(now_ms: number): boolean;
  session_remaining_ms(now_ms: number): number;
  free(): void;
}

interface WasmServer {
  put_psk(psk_id: string, psk_hex: string): void;
  remove_psk(psk_id: string): boolean;
  accept(client_hello: Uint8Array, device_id: string, now_ms: number): Uint8Array;
  seal(session_id_hex: string, aad: Uint8Array, plaintext: Uint8Array, now_ms: number): Uint8Array;
  open(session_id_hex: string, aad: Uint8Array, frame: Uint8Array, now_ms: number): Uint8Array;
  has_session(session_id_hex: string, now_ms: number): boolean;
  drop_session(session_id_hex: string): boolean;
  sweep_expired(now_ms: number): number;
  readonly session_count: number;
  free(): void;
}

/** HTTP 头名。 */
export const CRYPTO_HEADER = "X-Taotao-Crypto";

/** 协议版本（需先 `await initCrypto()`）。 */
export function protocolVersion(): number {
  return module.protocol_version();
}

/**
 * 当前 wasm 模块是否内嵌了真实 PSK。
 *
 * Web 端正常情况下**应该**是 false。返回 true 说明构建时误把服务端密钥
 * 编进了公开产物 —— 那是一个必须立刻修掉的安全问题。
 */
export function hasRealPsk(): boolean {
  return module.has_real_psk();
}

/**
 * 构造 AAD 上下文。
 *
 * 必须传**方法和完整的 path + query**。只传 path 的话，攻击者可以把
 * `GET /playlists/1` 的密文改发成 `DELETE /playlists/1`；
 * 不含 query 的话，攻击者可以保留密文只改 `page` 参数来遍历数据。
 */
export function aadContext(method: string, pathAndQuery: string): Uint8Array {
  return module.aad_context(method, pathAndQuery);
}

/** 解析 `X-Taotao-Crypto` 头值。格式非法返回 null。 */
export function parseCryptoHeader(value: string): { sessionId: string; seq: number } | null {
  const parsed = module.parse_header(value);
  if (!parsed) return null;
  return { sessionId: parsed[0], seq: Number(parsed[1]) };
}

let module: WasmModule;
let ready: Promise<void> | null = null;

/**
 * 加载并实例化 wasm 模块。
 *
 * 必须在构造任何客户端之前调用一次。重复调用是幂等的 ——
 * 分享页可能在多个组件里各自触发初始化，不做幂等会重复下载 wasm。
 */
export function initCrypto(loader: () => Promise<unknown> = defaultLoader): Promise<void> {
  if (!ready) {
    ready = (async () => {
      const mod = (await loader()) as WasmModule;
      await mod.default();
      module = mod;
    })();
  }
  return ready;
}

/**
 * 默认加载器。
 *
 * 路径由调用方按自己的部署结构覆盖 —— 分享页把资源挂在
 * `/share/v/<指纹>/` 下（见 `share-player-assets.ts`），
 * 而加密层是独立的 wasm，路径不一定和播放器一致。
 */
async function defaultLoader(): Promise<unknown> {
  return import("./taotao_crypto.js");
}

/**
 * 客户端加密通道。
 *
 * **必须调用 `dispose()`**：wasm 的内存不受 JS GC 管理，
 * 不释放会一直占着线性内存。浏览器里长时间停留的页面尤其明显。
 */
export class TaotaoCryptoClient implements Disposable {
  private readonly inner: WasmClient;

  constructor(pskId: string, pskHex: string, deviceId: string) {
    assertReady();
    this.inner = new module.Client(pskId, pskHex, deviceId);
  }

  get sessionId(): string {
    return this.inner.session_id;
  }

  hasSession(nowMs: number = Date.now()): boolean {
    return this.inner.has_session(nowMs);
  }

  needsRekey(nowMs: number = Date.now()): boolean {
    return this.inner.needs_rekey(nowMs);
  }

  sessionRemainingMs(nowMs: number = Date.now()): number {
    return this.inner.session_remaining_ms(nowMs);
  }

  handshake(nowMs: number = Date.now()): Uint8Array {
    return this.inner.handshake(nowMs);
  }

  finish(serverHello: Uint8Array, nowMs: number = Date.now()): void {
    this.inner.finish(serverHello, nowMs);
  }

  seal(aad: Uint8Array, plaintext: Uint8Array, nowMs: number = Date.now()): Uint8Array {
    return this.inner.seal(aad, plaintext, nowMs);
  }

  open(aad: Uint8Array, frame: Uint8Array, nowMs: number = Date.now()): Uint8Array {
    return this.inner.open(aad, frame, nowMs);
  }

  headerForFrame(frame: Uint8Array): string {
    return this.inner.header_for_frame(frame);
  }

  dispose(): void {
    this.inner.free();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

/** 服务端加密通道。仅在 wasm 后端（如 Cloudflare Workers）场景下有用。 */
export class TaotaoCryptoTokens implements Disposable {
  private readonly inner: WasmServer;

  constructor() {
    assertReady();
    this.inner = new module.Server();
  }

  putPsk(pskId: string, pskHex: string): void {
    this.inner.put_psk(pskId, pskHex);
  }

  removePsk(pskId: string): boolean {
    return this.inner.remove_psk(pskId);
  }

  accept(clientHello: Uint8Array, deviceId: string, nowMs: number = Date.now()): Uint8Array {
    return this.inner.accept(clientHello, deviceId, nowMs);
  }

  seal(
    sessionIdHex: string,
    aad: Uint8Array,
    plaintext: Uint8Array,
    nowMs: number = Date.now(),
  ): Uint8Array {
    return this.inner.seal(sessionIdHex, aad, plaintext, nowMs);
  }

  open(
    sessionIdHex: string,
    aad: Uint8Array,
    frame: Uint8Array,
    nowMs: number = Date.now(),
  ): Uint8Array {
    return this.inner.open(sessionIdHex, aad, frame, nowMs);
  }

  hasSession(sessionIdHex: string, nowMs: number = Date.now()): boolean {
    return this.inner.has_session(sessionIdHex, nowMs);
  }

  dropSession(sessionIdHex: string): boolean {
    return this.inner.drop_session(sessionIdHex);
  }

  sweepExpired(nowMs: number = Date.now()): number {
    return this.inner.sweep_expired(nowMs);
  }

  get sessionCount(): number {
    return this.inner.session_count;
  }

  dispose(): void {
    this.inner.free();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

function assertReady(): void {
  if (!module) {
    throw new Error("加密层尚未初始化：请先 await initCrypto()");
  }
}

/**
 * 必须豁免加密的路径。
 *
 * 与 `bindings/node/index.ts` 里的清单保持一致 —— 两端不一致会导致
 * 「Web 端能用、桌面端不能用」这类只在单一平台上出现的问题。
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
