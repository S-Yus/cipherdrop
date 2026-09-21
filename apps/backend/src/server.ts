/**
 * CipherDrop API サーバー（暗号文の受け取り・保存・1 回限りの取得と即時削除）。
 *
 *   POST /api/payload        暗号文を保存し、ID を発行する
 *   GET  /api/payload/:id    暗号文を返し、返す前にストアから完全に削除する
 *
 * このサーバーが受け取るのは暗号文と IV だけで、復号鍵は URL のハッシュ断片（#key）にしか存在しない。
 * ブラウザはハッシュ断片を HTTP リクエストに含めないので、鍵はここに届かない。
 *
 * ランタイム依存パッケージは 0（node:http / node:crypto のみ）。
 */
import { randomBytes } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { InMemoryPayloadStore, StoreFullError } from './store.ts';
import type { PayloadStore } from './store.ts';

// ---------------------------------------------------------------------------
// API 仕様
// ---------------------------------------------------------------------------

/** 暗号文の IV（base64url、12 バイト）。リクエスト/レスポンス両方で使う。 */
export const HEADER_IV = 'x-cipherdrop-iv';
/** 保持期間（秒）。POST のみ。省略時は既定値。 */
export const HEADER_TTL = 'x-cipherdrop-ttl';

const CREATE_PATH = '/api/payload';
const CONSUME_PATH = /^\/api\/payload\/([A-Za-z0-9_-]{22})$/; // ID は 128bit = base64url 22 文字
const ID_BYTES = 16;
const IV_HEADER_PATTERN = /^[A-Za-z0-9_-]{16}$/; // 12 バイト = base64url 16 文字
const MIN_CIPHERTEXT_BYTES = 16; // AES-GCM の認証タグ長。これ未満は暗号文として成立しない
const MIN_TTL_SECONDS = 60;

export const DEFAULT_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
export const DEFAULT_TTL_SECONDS = 24 * 60 * 60;
export const DEFAULT_MAX_TTL_SECONDS = 7 * 24 * 60 * 60;

/** すべてのレスポンスに付ける。API は HTML を返さないので CSP は全拒否。CORS は意図的に許可しない。 */
const BASE_HEADERS = {
  'Cache-Control': 'no-store', // 暗号文であってもキャッシュさせない（1 回読み切りの前提が崩れる）
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cross-Origin-Resource-Policy': 'same-origin',
} as const;

// ---------------------------------------------------------------------------
// ログ
//
// ログに書けるのは下の LogEvent だけ。URL・クエリ・ヘッダー・ID・リクエスト本文は型として存在せず、
// method もホワイトリスト、route は固定名にしているので、利用者由来の文字列がログに混入する経路がない。
// このファイルでの console.* の使用も tests/security-policy.test.ts が禁止している。
// ---------------------------------------------------------------------------

export type RouteName = 'create' | 'consume' | 'unmatched';

export type LogEvent =
  | { event: 'request'; method: string; route: RouteName; status: number; durationMs: number }
  | { event: 'error'; name: string; code: string | null }
  | { event: 'listening'; host: string; port: number };

const LOGGED_METHODS = new Set(['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

function writeLogLine(event: LogEvent): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

/** エラーは種類（name / code）だけ記録する。message と stack には入力値が含まれ得るので出さない。 */
function describeError(error: unknown): { name: string; code: string | null } {
  const token = /^[A-Za-z0-9_.-]{1,64}$/;
  const name = error instanceof Error && token.test(error.name) ? error.name : 'UnknownError';
  const rawCode = (error as { code?: unknown } | null)?.code;
  const code = typeof rawCode === 'string' && token.test(rawCode) ? rawCode : null;
  return { name, code };
}

// ---------------------------------------------------------------------------
// サーバー
// ---------------------------------------------------------------------------

export interface ServerOptions {
  /** 暗号文の保存先。省略時はインメモリ。 */
  store?: PayloadStore;
  /** 暗号文 1 件の最大バイト数。 */
  maxPayloadBytes?: number;
  defaultTtlSeconds?: number;
  maxTtlSeconds?: number;
  log?: (event: LogEvent) => void;
}

interface Context {
  store: PayloadStore;
  maxPayloadBytes: number;
  defaultTtlSeconds: number;
  maxTtlSeconds: number;
  log: (event: LogEvent) => void;
}

export function createServer(options: ServerOptions = {}): Server {
  const writeLog = options.log ?? writeLogLine;
  const context: Context = {
    store: options.store ?? new InMemoryPayloadStore(),
    maxPayloadBytes: options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES,
    defaultTtlSeconds: options.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS,
    maxTtlSeconds: options.maxTtlSeconds ?? DEFAULT_MAX_TTL_SECONDS,
    // ロギングの失敗でリクエスト処理を止めず、プロセスも落とさない。
    // このサーバーは未読の暗号文をメモリに抱えているため、プロセス停止は未読データの全消失を意味する。
    log: (event) => {
      try {
        writeLog(event);
      } catch {
        // 意図的に無視する
      }
    },
  };
  if (context.defaultTtlSeconds < MIN_TTL_SECONDS || context.defaultTtlSeconds > context.maxTtlSeconds) {
    throw new RangeError('defaultTtlSeconds must be between the minimum TTL and maxTtlSeconds.');
  }

  const server = createHttpServer((req, res) => {
    void handleRequest(req, res, context);
  });

  // Slowloris 対策。リバースプロキシ配下でも、アプリ側で上限を持っておく。
  server.headersTimeout = 15_000;
  server.requestTimeout = 120_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

/** どんな例外もここで受け止める（未処理の例外でプロセスを落とさない）。 */
async function handleRequest(req: IncomingMessage, res: ServerResponse, context: Context): Promise<void> {
  const startedAt = performance.now();
  let route: RouteName = 'unmatched';
  try {
    route = await dispatch(req, res, context);
  } catch (error) {
    context.log({ event: 'error', ...describeError(error) });
    if (res.headersSent) res.destroy();
    else sendError(res, 500, 'internal_error');
  } finally {
    const method = req.method !== undefined && LOGGED_METHODS.has(req.method) ? req.method : 'OTHER';
    context.log({
      event: 'request',
      method,
      route,
      status: res.statusCode,
      durationMs: Math.round(performance.now() - startedAt),
    });
  }
}

async function dispatch(req: IncomingMessage, res: ServerResponse, context: Context): Promise<RouteName> {
  const target = req.url ?? '';

  // このサービスはクエリ文字列を一切使わない。鍵などをうっかりクエリに載せるクライアントの実装ミスを
  // 開発中に即発見できるよう、受け付けずに拒否する（正規化せず生の文字列で判定する）。
  if (target.includes('?')) {
    sendError(res, 400, 'query_not_allowed');
    return 'unmatched';
  }

  if (target === CREATE_PATH) {
    if (req.method !== 'POST') {
      sendError(res, 405, 'method_not_allowed', { Allow: 'POST' });
    } else {
      await createPayload(req, res, context);
    }
    return 'create';
  }

  const id = CONSUME_PATH.exec(target)?.[1];
  if (id !== undefined) {
    // GET だけを受け付ける。HEAD などを GET と同一視すると、プロキシの疎通確認で暗号文が消えてしまう。
    if (req.method !== 'GET') {
      sendError(res, 405, 'method_not_allowed', { Allow: 'GET' });
    } else {
      await consumePayload(res, id, context);
    }
    return 'consume';
  }

  sendError(res, 404, 'not_found');
  return 'unmatched';
}

// ---------------------------------------------------------------------------
// POST /api/payload
// ---------------------------------------------------------------------------

async function createPayload(req: IncomingMessage, res: ServerResponse, context: Context): Promise<void> {
  if (!isOctetStream(req.headers['content-type'])) {
    return sendError(res, 415, 'unsupported_media_type');
  }

  const iv = parseIv(req.headers[HEADER_IV]);
  if (iv === null) return sendError(res, 400, 'invalid_iv');

  const ttlSeconds = parseTtl(req.headers[HEADER_TTL], context);
  if (ttlSeconds === null) return sendError(res, 400, 'invalid_ttl');

  const ciphertext = await readBody(req, context.maxPayloadBytes);
  if (ciphertext === null) return sendError(res, 413, 'payload_too_large', { Connection: 'close' });
  if (ciphertext.byteLength < MIN_CIPHERTEXT_BYTES) return sendError(res, 400, 'invalid_ciphertext');

  const id = randomBytes(ID_BYTES).toString('base64url');
  try {
    const { expiresAt } = await context.store.put(id, { ciphertext, iv }, ttlSeconds);
    sendJson(res, 201, { id, expiresAt: new Date(expiresAt).toISOString() });
  } catch (error) {
    if (error instanceof StoreFullError) return sendError(res, 503, 'storage_full', { 'Retry-After': '60' });
    throw error;
  }
}

function isOctetStream(contentType: string | undefined): boolean {
  return contentType?.split(';')[0]?.trim().toLowerCase() === 'application/octet-stream';
}

function parseIv(header: string | string[] | undefined): Buffer | null {
  if (typeof header !== 'string' || !IV_HEADER_PATTERN.test(header)) return null;
  return Buffer.from(header, 'base64url');
}

function parseTtl(header: string | string[] | undefined, context: Context): number | null {
  if (header === undefined) return context.defaultTtlSeconds;
  if (typeof header !== 'string' || !/^[0-9]{1,9}$/.test(header)) return null;
  const seconds = Number(header);
  return seconds >= MIN_TTL_SECONDS && seconds <= context.maxTtlSeconds ? seconds : null;
}

/** 上限を超えたら読むのを止めて null を返す。宣言サイズ（Content-Length）が上限超過なら 1 バイトも読まない。 */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer | null> {
  const declared = req.headers['content-length'];
  if (declared !== undefined && Number(declared) > limit) return null;

  const chunks: Buffer[] = [];
  let received = 0;
  // destroyOnReturn: false — 途中で抜けても req（＝ソケット）を破棄しない。破棄すると 413 が返せない。
  for await (const chunk of req.iterator({ destroyOnReturn: false }) as AsyncIterable<Buffer>) {
    received += chunk.length;
    if (received > limit) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, received);
}

// ---------------------------------------------------------------------------
// GET /api/payload/:id
// ---------------------------------------------------------------------------

async function consumePayload(res: ServerResponse, id: string, context: Context): Promise<void> {
  // 取得と削除は store.take() の中で不可分に完了する。レスポンスは、その完了後にしか書き出さない。
  // 取得後に通信が切れても暗号文は復元しない（安全側に倒す）。
  const payload = await context.store.take(id);
  if (payload === null) return sendError(res, 404, 'not_found'); // 未発行・取得済み・期限切れを区別しない

  send(res, 200, payload.ciphertext, {
    'Content-Type': 'application/octet-stream',
    [HEADER_IV]: Buffer.from(payload.iv).toString('base64url'),
  });
}

// ---------------------------------------------------------------------------
// レスポンス
// ---------------------------------------------------------------------------

function send(res: ServerResponse, status: number, body: Uint8Array, headers: Record<string, string> = {}): void {
  res.writeHead(status, { ...BASE_HEADERS, 'Content-Length': body.byteLength, ...headers });
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, body: object, headers: Record<string, string> = {}): void {
  send(res, status, Buffer.from(JSON.stringify(body)), { 'Content-Type': 'application/json; charset=utf-8', ...headers });
}

function sendError(res: ServerResponse, status: number, code: string, headers: Record<string, string> = {}): void {
  sendJson(res, status, { error: code }, headers);
}

// ---------------------------------------------------------------------------
// エントリポイント（`node src/server.ts` / `node dist/server.js` で直接実行したときだけ起動）
// ---------------------------------------------------------------------------

function readPort(value: string | undefined): number {
  if (value === undefined) return 8787;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new RangeError('PORT must be an integer between 0 and 65535.');
  }
  return port;
}

if (import.meta.main) {
  // 既定はループバックのみ。公開する場合は TLS 終端するリバースプロキシの背後に置くこと。
  const host = process.env['HOST'] ?? '127.0.0.1';
  const port = readPort(process.env['PORT']);

  const store = new InMemoryPayloadStore();
  const server = createServer({ store });

  server.listen(port, host, () => {
    const address = server.address();
    writeLogLine({ event: 'listening', host, port: typeof address === 'object' && address !== null ? address.port : port });
  });

  const shutdown = (): void => {
    server.close(() => {
      store.close(); // 未読の暗号文もメモリから破棄する
      process.exit(0);
    });
    server.closeIdleConnections();
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
