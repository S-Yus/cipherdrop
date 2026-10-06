/**
 * クライアント単位のレート制限（トークンバケット）。
 *
 * 目的は、ID を知っている第三者による暗号文の「消費」（DoS）や、保存の連打による容量の食い潰しを抑えること。
 * 状態はプロセス内メモリだけに持つ（再起動で消える）。キー数に上限を持ち、溢れたら最も長く使われていないものから捨てる。
 *
 * キーはクライアントの IP アドレスだが、ログにもレスポンスにも出さない。
 */
import { isIP } from 'node:net';
import type { IncomingMessage } from 'node:http';

export interface RateLimitRule {
  /** バケットの容量（連続で受け付けられる回数）。 */
  capacity: number;
  /** 1 秒あたりに回復するトークン数。 */
  refillPerSecond: number;
}

export interface RateLimiterOptions extends RateLimitRule {
  /** 同時に追跡するキーの上限。超えたら最も長く使われていないキーから捨てる。 */
  maxKeys?: number;
  /** 現在時刻（epoch ms）。テストで差し替える。 */
  now?: () => number;
}

export interface RateLimitResult {
  allowed: boolean;
  /** 拒否したとき、次の 1 回が受け付けられるまでの秒数（切り上げ、最小 1）。 */
  retryAfterSeconds: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const DEFAULT_MAX_KEYS = 100_000;

export class RateLimiter {
  readonly #buckets = new Map<string, Bucket>();
  readonly #capacity: number;
  readonly #refillPerMs: number;
  readonly #maxKeys: number;
  readonly #now: () => number;

  constructor(options: RateLimiterOptions) {
    if (!(options.capacity >= 1) || !(options.refillPerSecond > 0)) {
      throw new RangeError('capacity must be >= 1 and refillPerSecond must be > 0.');
    }
    this.#capacity = options.capacity;
    this.#refillPerMs = options.refillPerSecond / 1000;
    this.#maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    this.#now = options.now ?? Date.now;
  }

  /** key の 1 回分を消費する。足りなければ消費せずに拒否する。 */
  take(key: string): RateLimitResult {
    const now = this.#now();
    const bucket = this.#buckets.get(key);
    let tokens = this.#capacity;
    if (bucket !== undefined) {
      tokens = Math.min(this.#capacity, bucket.tokens + (now - bucket.updatedAt) * this.#refillPerMs);
      this.#buckets.delete(key); // Map の挿入順を「最近使った順」として使う
    }

    const allowed = tokens >= 1;
    if (allowed) tokens -= 1;
    this.#buckets.set(key, { tokens, updatedAt: now });

    if (this.#buckets.size > this.#maxKeys) {
      const oldest = this.#buckets.keys().next().value;
      if (oldest !== undefined) this.#buckets.delete(oldest);
    }

    const retryAfterSeconds = allowed ? 0 : Math.max(1, Math.ceil((1 - tokens) / this.#refillPerMs / 1000));
    return { allowed, retryAfterSeconds };
  }

  get size(): number {
    return this.#buckets.size;
  }
}

/**
 * レート制限のキーにするクライアント識別子。
 *
 * trustedHeader を指定した場合だけ、そのヘッダー（例: Cloudflare の cf-connecting-ip）の値を使う。
 * ヘッダーは偽装できるので、アプリに直接届く経路が無い（リバースプロキシ／トンネル経由だけ）ときにしか指定しないこと。
 * IPv6 は /64 単位にまとめる（1 台が /64 を丸ごと持つのが普通なので、アドレスを替えての回避を防ぐ）。
 */
export function clientKey(req: IncomingMessage, trustedHeader?: string): string {
  let address: string | undefined;
  if (trustedHeader !== undefined) {
    const value = req.headers[trustedHeader.toLowerCase()];
    if (typeof value === 'string' && isIP(value.trim()) !== 0) address = value.trim();
  }
  address ??= req.socket.remoteAddress;
  if (address === undefined) return 'unknown';
  return normalizeAddress(address);
}

export function normalizeAddress(address: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (mapped?.[1] !== undefined) return mapped[1];
  if (isIP(address) !== 6) return address;

  const [head = '', tail] = address.toLowerCase().split('::');
  const left = head === '' ? [] : head.split(':');
  const right = tail === undefined || tail === '' ? [] : tail.split(':');
  const groups = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right];
  return `${groups
    .slice(0, 4)
    .map((group) => group.replace(/^0+(?=.)/, ''))
    .join(':')}::/64`;
}
