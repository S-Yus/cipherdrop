/**
 * バックエンド API のクライアント。
 *
 *   createPayload  POST /api/payload              暗号文と IV を保存して ID を得る
 *   getMeta        GET  /api/payload/:id/meta     確認（何も消費しない）。ページ読み込み時に呼ぶ
 *   consume        POST /api/payload/:id/consume  消費（返す前にサーバー側で削除される）。受信者が「開く」を押したときだけ呼ぶ
 *
 * - 復号鍵はこのモジュールの関数に渡せない（引数に存在しない）。ID も形式を検証するので、`#key` や `?key` を
 *   URL に紛れ込ませることもできない。鍵がサーバーへ送られる経路を、型と検証の両方で塞いでいる。
 *   createPayload の keyCheck / PayloadMeta.keyCheck は鍵そのものではなく、鍵から一方向に導出した
 *   短い確認値（crypto.ts の generateKeyCheckTag）。詳細はそちらのコメントを参照。
 * - サーバーは信頼しない相手として扱い、応答はすべて検証する。エラーメッセージは固定文言のみ。
 * - リクエストは Cookie・Referer・キャッシュ・リダイレクトを使わない。
 */
import { ID_PATTERN } from './router.ts';
import { KEY_CHECK_PATTERN, base64UrlDecode, base64UrlEncode } from './crypto.ts';

export const HEADER_IV = 'X-CipherDrop-IV';
export const HEADER_TTL = 'X-CipherDrop-TTL';
export const HEADER_TYPE = 'X-CipherDrop-Type';
/** 鍵確認値（任意）。generateKeyCheckTag（crypto.ts）の出力をそのまま送る。鍵そのものではない。 */
export const HEADER_KEY_CHECK = 'X-CipherDrop-Key-Check';
/** consumeSecret の SHA-256 全体（必須）。generateConsumeSecret（crypto.ts）の verifierHex をそのまま送る。 */
export const HEADER_CONSUME_VERIFIER = 'X-CipherDrop-Consume-Verifier';
/** consumeSecret そのもの（必須）。共有 URL のハッシュ断片から取り出した secretString をそのまま送る。 */
export const HEADER_CONSUME_SECRET = 'X-CipherDrop-Consume-Secret';

export type PayloadType = 'text' | 'file';

export interface PayloadMeta {
  /** サーバーが保持する表示用のヒント。描画・保存の分岐には使わない（復号後の type を使う）。 */
  type: PayloadType;
  /** 暗号文のバイト数。 */
  size: number;
  expiresAt: Date;
  /**
   * 鍵確認値（任意）。無ければキー自体が存在しない（旧データ・送信側が未対応）。
   * 受取画面はこれと、URL の鍵から計算した値を照合する（views/receive.ts）。
   */
  keyCheck?: string;
}

export type ApiErrorCode =
  | 'not_found' // 存在しない・消費済み・期限切れ（区別しない）
  | 'payload_too_large'
  | 'storage_full'
  | 'network' // 接続できない・途中で切れた
  | 'invalid_response' // サーバーの応答が想定と違う
  | 'server';

const MESSAGES: Record<ApiErrorCode, string> = {
  not_found: 'The payload does not exist, was already opened, or has expired.',
  payload_too_large: 'The payload is too large.',
  storage_full: 'The server storage is full.',
  network: 'Could not reach the server.',
  invalid_response: 'The server returned an unexpected response.',
  server: 'The server reported an error.',
};

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number | null;

  constructor(code: ApiErrorCode, status: number | null = null) {
    super(MESSAGES[code]);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

export interface ApiClient {
  createPayload(input: {
    encryptedData: ArrayBuffer;
    iv: Uint8Array;
    type: PayloadType;
    ttlSeconds: number;
    /** 鍵確認値（任意）。省略すると X-CipherDrop-Key-Check ヘッダー自体を送らない。 */
    keyCheck?: string;
    /**
     * consumeSecret（crypto.ts の generateConsumeSecret）の SHA-256 全体（16進 64 桁）。必須。
     * keyCheck と異なり省略できない ―― これが無いと、正当な受信者であっても後で consume できない。
     */
    consumeVerifier: string;
  }): Promise<{ id: string; expiresAt: Date }>;
  getMeta(id: string): Promise<PayloadMeta>;
  /**
   * @param consumeSecret 共有 URL のハッシュ断片から取り出した consumeSecret（crypto.ts の parseShareFragment）。
   *   ID だけを知る第三者が、これを知らずに consume できてしまわないための必須の権限証明。
   */
  consume(id: string, consumeSecret: string): Promise<{ encryptedData: ArrayBuffer; iv: Uint8Array }>;
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export function createApiClient(fetchImpl: FetchLike = (input, init) => fetch(input, init), baseUrl = ''): ApiClient {
  async function request(path: string, init: RequestInit): Promise<Response> {
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        ...init,
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
      });
    } catch {
      throw new ApiError('network');
    }
    if (response.ok) return response;

    if (response.status === 404) throw new ApiError('not_found', 404);
    if (response.status === 413) throw new ApiError('payload_too_large', 413);
    if (response.status === 503) throw new ApiError('storage_full', 503);
    throw new ApiError('server', response.status);
  }

  async function readJson(response: Response): Promise<Record<string, unknown>> {
    try {
      const body: unknown = await response.json();
      if (typeof body === 'object' && body !== null && !Array.isArray(body)) return body as Record<string, unknown>;
    } catch {
      // 下の invalid_response に落とす
    }
    throw new ApiError('invalid_response', response.status);
  }

  return {
    async createPayload({ encryptedData, iv, type, ttlSeconds, keyCheck, consumeVerifier }) {
      const response = await request('/api/payload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          [HEADER_IV]: base64UrlEncode(iv),
          [HEADER_TYPE]: type,
          [HEADER_TTL]: String(ttlSeconds),
          [HEADER_CONSUME_VERIFIER]: consumeVerifier,
          // 任意: 省略すればヘッダー自体を送らない（サーバー側も旧クライアントと同じに扱う）。
          ...(keyCheck === undefined ? {} : { [HEADER_KEY_CHECK]: keyCheck }),
        },
        body: encryptedData,
      });

      const body = await readJson(response);
      const id = body['id'];
      const expiresAt = parseDate(body['expiresAt']);
      if (typeof id !== 'string' || !ID_PATTERN.test(id) || expiresAt === null) {
        throw new ApiError('invalid_response', response.status);
      }
      return { id, expiresAt };
    },

    async getMeta(id) {
      const response = await request(`/api/payload/${assertId(id)}/meta`, { method: 'GET' });

      const body = await readJson(response);
      const { type, size, keyCheck } = body;
      const expiresAt = parseDate(body['expiresAt']);
      if ((type !== 'text' && type !== 'file') || !Number.isSafeInteger(size) || (size as number) < 0 || expiresAt === null) {
        throw new ApiError('invalid_response', response.status);
      }
      // 任意: 無ければ後方互換（旧データ・未対応の送信側）。有れば厳格に形式を検証する（信頼しない入力）。
      if (keyCheck !== undefined && (typeof keyCheck !== 'string' || !KEY_CHECK_PATTERN.test(keyCheck))) {
        throw new ApiError('invalid_response', response.status);
      }
      return keyCheck === undefined
        ? { type, size: size as number, expiresAt }
        : { type, size: size as number, expiresAt, keyCheck: keyCheck as string };
    },

    async consume(id, consumeSecret) {
      const response = await request(`/api/payload/${assertId(id)}/consume`, {
        method: 'POST',
        headers: { [HEADER_CONSUME_SECRET]: consumeSecret },
      });

      const iv = base64UrlDecode(response.headers.get(HEADER_IV) ?? '');
      if (iv === null || iv.byteLength !== 12) throw new ApiError('invalid_response', response.status);

      let encryptedData: ArrayBuffer;
      try {
        encryptedData = await response.arrayBuffer();
      } catch {
        throw new ApiError('network');
      }
      return { encryptedData, iv };
    },
  };
}

/** ID が想定の形式でなければ、リクエストを作る前に失敗させる（`#` `?` `/` 等が URL に入り込む余地を与えない）。 */
function assertId(id: string): string {
  if (typeof id !== 'string' || !ID_PATTERN.test(id)) throw new ApiError('not_found');
  return id;
}

function parseDate(value: unknown): Date | null {
  if (typeof value !== 'string') return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}
