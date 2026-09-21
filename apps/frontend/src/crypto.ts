/**
 * CipherDrop 暗号化コアモジュール（ブラウザ専用）。
 *
 * - 暗号処理は Web Crypto API（crypto.subtle）だけで完結する。外部ライブラリは使わない。
 * - アルゴリズム: AES-GCM 256bit / IV 96bit（呼び出しごとに CSPRNG で生成）/ 認証タグ 128bit。
 * - 鍵は 1 メッセージにつき 1 つ新規生成する。共有 URL のハッシュ断片（#key）にのみ載せ、
 *   サーバーには一切送らない。
 *
 * 平文エンベロープ（暗号化される直前のバイト列）:
 *   [0]     フォーマットタグ  0x01 = UTF-8 テキスト / 0x02 = バイナリ
 *   [1..]   本体
 * タグも AES-GCM の認証対象なので、サーバーが「テキスト ↔ バイナリ」を偽装することはできない。
 * これにより decryptData は encryptData に渡したのと同じ型（string | ArrayBuffer）を返せる。
 */

const KEY_BITS = 256;
const KEY_BYTES = KEY_BITS / 8;
const IV_BYTES = 12;
const TAG_BITS = 128;
/** base64url（パディング無し）で表した 32 バイト鍵の文字数。 */
const KEY_STRING_LENGTH = 43;

const FORMAT_TEXT = 0x01;
const FORMAT_BINARY = 0x02;

export type CryptoErrorCode =
  | 'WEBCRYPTO_UNAVAILABLE'
  | 'INVALID_PAYLOAD'
  | 'INVALID_KEY'
  | 'INVALID_IV'
  | 'DECRYPTION_FAILED'
  | 'UNSUPPORTED_FORMAT';

/**
 * 暗号処理の失敗。message は固定文言のみで、鍵・平文・暗号文の内容は絶対に含めない
 * （クライアント側のエラー収集ツールやコンソール経由の漏洩を防ぐため）。
 */
export class CipherDropCryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = 'CipherDropCryptoError';
    this.code = code;
  }
}

export interface EncryptedPayload {
  /** 暗号文 || GCM 認証タグ（16 バイト）。サーバーへ送るバイナリ。 */
  encryptedData: ArrayBuffer;
  /** 12 バイトの IV。秘密ではなく、暗号文と一緒にサーバーへ送ってよい。 */
  iv: Uint8Array;
  /** base64url の 256bit 鍵。共有 URL の `#` 以降にだけ載せ、サーバーへ送ってはならない。 */
  keyString: string;
}

/**
 * 文字列または ArrayBuffer を暗号化する。呼び出しごとに新しい鍵と IV を生成する。
 *
 * @example
 *   const { encryptedData, iv, keyString } = await encryptData('secret');
 *   const shareUrl = `https://cipherdrop.io/v/${id}#${keyString}`;
 */
export async function encryptData(payload: string | ArrayBuffer): Promise<EncryptedPayload> {
  const subtle = getSubtle();
  const plaintext = toEnvelope(payload);

  const key = await subtle.generateKey({ name: 'AES-GCM', length: KEY_BITS }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: TAG_BITS }, key, plaintext);
  const keyString = base64UrlEncode(new Uint8Array(await subtle.exportKey('raw', key)));

  return { encryptedData, iv, keyString };
}

/**
 * encryptData の出力を復号する。元が string なら string、ArrayBuffer なら ArrayBuffer を返す。
 *
 * @param keyString `location.hash` の先頭 `#` を除いた文字列（`location.hash.slice(1)`）。
 * @throws CipherDropCryptoError 鍵・IV の形式不正、鍵の不一致、暗号文/IV の改ざん、未対応フォーマット。
 *
 * 暗号文と IV はサーバー（＝信頼しない相手）から届く値として扱い、
 * 改ざんは AES-GCM の認証タグで検出する。
 */
export async function decryptData(
  encryptedData: ArrayBuffer,
  iv: Uint8Array,
  keyString: string,
): Promise<string | ArrayBuffer> {
  const subtle = getSubtle();

  if (!(encryptedData instanceof ArrayBuffer)) {
    throw new CipherDropCryptoError('INVALID_PAYLOAD', 'encryptedData must be an ArrayBuffer.');
  }
  if (!(iv instanceof Uint8Array) || iv.byteLength !== IV_BYTES) {
    throw new CipherDropCryptoError('INVALID_IV', `iv must be a Uint8Array of ${IV_BYTES} bytes.`);
  }
  const rawKey = decodeKeyString(keyString);

  // 復号専用・エクスポート不可の鍵として取り込む（最小権限）。
  const key = await subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);

  let plaintext: Uint8Array<ArrayBuffer>;
  try {
    // iv はコピーして渡す（呼び出し側の Uint8Array が共有バッファ上でも安全に扱うため）。
    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv), tagLength: TAG_BITS },
      key,
      encryptedData,
    );
    plaintext = new Uint8Array(decrypted);
  } catch {
    // 鍵違い・改ざん・切り詰めはいずれも同じ失敗として扱い、原因の詳細は外に出さない。
    throw new CipherDropCryptoError('DECRYPTION_FAILED', 'Decryption failed: wrong key or corrupted data.');
  }

  return fromEnvelope(plaintext);
}

/**
 * 復号したテキストを画面に描画する唯一の推奨経路。
 * HTML としては一切解釈されず、常にテキストノードとして挿入する（XSS 対策）。
 * 既存の子要素は置き換える。改行を見せたい場合は CSS の `white-space: pre-wrap` を使うこと。
 *
 * HTML 文字列を DOM に流し込む API（inner-HTML 系・document.write・insertAdjacentHTML など）は
 * このコードベースでは使用禁止で、tests/security-policy.test.ts が機械的に検査している。
 */
export function renderTextSafely(target: Element, text: string): void {
  target.replaceChildren(target.ownerDocument.createTextNode(text));
}

// ---------------------------------------------------------------------------
// 内部実装
// ---------------------------------------------------------------------------

function getSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new CipherDropCryptoError(
      'WEBCRYPTO_UNAVAILABLE',
      'Web Crypto API is unavailable. A secure context (HTTPS or localhost) is required.',
    );
  }
  return subtle;
}

function toEnvelope(payload: string | ArrayBuffer): Uint8Array<ArrayBuffer> {
  let tag: number;
  let body: Uint8Array;
  if (typeof payload === 'string') {
    tag = FORMAT_TEXT;
    body = new TextEncoder().encode(payload);
  } else if (payload instanceof ArrayBuffer) {
    tag = FORMAT_BINARY;
    body = new Uint8Array(payload);
  } else {
    throw new CipherDropCryptoError('INVALID_PAYLOAD', 'payload must be a string or an ArrayBuffer.');
  }

  const envelope = new Uint8Array(1 + body.byteLength);
  envelope[0] = tag;
  envelope.set(body, 1);
  return envelope;
}

function fromEnvelope(plaintext: Uint8Array<ArrayBuffer>): string | ArrayBuffer {
  const body = plaintext.subarray(1);
  switch (plaintext[0]) {
    case FORMAT_TEXT:
      try {
        // fatal: 不正な UTF-8 を U+FFFD に黙って置換しない。ignoreBOM: 先頭の U+FEFF も欠落させない。
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(body);
      } catch {
        throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', 'Decrypted text is not valid UTF-8.');
      }
    case FORMAT_BINARY:
      return body.slice().buffer;
    default:
      throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', 'Unknown payload format.');
  }
}

function decodeKeyString(keyString: string): Uint8Array<ArrayBuffer> {
  const raw = typeof keyString === 'string' && keyString.length === KEY_STRING_LENGTH
    ? base64UrlDecode(keyString)
    : null;
  if (raw === null || raw.byteLength !== KEY_BYTES) {
    throw new CipherDropCryptoError('INVALID_KEY', 'Key must be a base64url string encoding 256 bits.');
  }
  return raw;
}

/** RFC 4648 §5 の base64url（パディング無し）。IV を HTTP ヘッダーで受け渡すときにも使う。 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * 厳密な base64url デコード。base64url 以外の文字（`+` `/` `=` 空白など）や、
 * 非正規表現（余りビットが 0 でない、長さが不正）は例外ではなく null を返す。
 */
export function base64UrlDecode(input: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) return null;

  const standard = input.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(input.length / 4) * 4, '=');
  let binary: string;
  try {
    binary = atob(standard);
  } catch {
    return null;
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return base64UrlEncode(bytes) === input ? bytes : null;
}
