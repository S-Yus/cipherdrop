/**
 * CipherDrop 暗号化コアモジュール（ブラウザ専用）。
 *
 * - 暗号処理は Web Crypto API（crypto.subtle）だけで完結する。外部ライブラリは使わない。
 * - アルゴリズム: AES-GCM 256bit / IV 96bit（呼び出しごとに CSPRNG で生成）/ 認証タグ 128bit。
 * - 鍵は 1 メッセージにつき 1 つ新規生成する。共有 URL のハッシュ断片（#key）にのみ載せ、
 *   サーバーには一切送らない。
 *
 * 平文エンベロープ（暗号化される直前のバイト列）:
 *   [0]     フォーマットタグ
 *             0x01 = UTF-8 テキスト   本体: テキスト
 *             0x02 = バイナリ         本体: バイト列
 *             0x03 = ファイル         本体: [u16 BE 名前のバイト長][名前 UTF-8][ファイルのバイト列]
 *   [1..]   本体
 * タグも AES-GCM の認証対象なので、サーバーが「テキスト ↔ ファイル」を偽装することはできない。
 * ファイル名も暗号文の内側にあり、サーバーには見えない（名前自体が機密であるケースを想定）。
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
const FORMAT_FILE = 0x03;
/** ファイル名（UTF-8）の最大バイト数。送信側・受信側の両方で強制する。 */
const MAX_FILE_NAME_BYTES = 1024;

/** 鍵確認値のドメイン分離文字列。アルゴリズムを変える場合は新しい接頭辞にする（既存の値と衝突させない）。 */
const KEY_CHECK_DOMAIN = 'cipherdrop-key-check-v1:';
/** 鍵確認値の長さ（16進の桁数）。SHA-256 の先頭 32bit。 */
const KEY_CHECK_HEX_DIGITS = 8;

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
  return encryptEnvelope(toEnvelope(payload));
}

/** ファイル名つきのファイル。名前は暗号文の内側に入り、サーバーには送られない。 */
export interface FilePayload {
  name: string;
  data: ArrayBuffer;
}

/**
 * ファイルを名前ごと暗号化する（呼び出しごとに新しい鍵と IV）。
 * 名前は UTF-8 で 1024 バイトまで。受信側で表示・保存する前に必ず無害化すること（sanitizeFileName）。
 */
export async function encryptFile(file: FilePayload): Promise<EncryptedPayload> {
  return encryptEnvelope(toFileEnvelope(file));
}

async function encryptEnvelope(plaintext: Uint8Array<ArrayBuffer>): Promise<EncryptedPayload> {
  const subtle = getSubtle();

  const key = await subtle.generateKey({ name: 'AES-GCM', length: KEY_BITS }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encryptedData = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: TAG_BITS }, key, plaintext);
  const keyString = base64UrlEncode(new Uint8Array(await subtle.exportKey('raw', key)));

  return { encryptedData, iv, keyString };
}

/**
 * encryptData の出力を復号する。元が string なら string、ArrayBuffer なら ArrayBuffer を返す。
 * encryptFile の出力に対しては、ファイル本体のバイト列だけを返す（名前が必要なら decryptPayload）。
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
  const payload = await decryptPayload(encryptedData, iv, keyString);
  return payload.type === 'text' ? payload.text : payload.data;
}

/** 復号結果。type は暗号文の内側（認証済み）のタグで決まり、サーバーが申告した種別ヒントとは無関係。 */
export type DecryptedPayload =
  | { type: 'text'; text: string }
  | { type: 'binary'; data: ArrayBuffer }
  | { type: 'file'; name: string; data: ArrayBuffer };

/**
 * 復号して、種別つきで返す。描画・保存の分岐には、サーバー由来のヒントではなくこの type を使うこと。
 * file の name は送信者が自由に決めた値（信頼できない入力）なので、そのまま保存名や表示に使わない。
 */
export async function decryptPayload(
  encryptedData: ArrayBuffer,
  iv: Uint8Array,
  keyString: string,
): Promise<DecryptedPayload> {
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

function toFileEnvelope(file: FilePayload): Uint8Array<ArrayBuffer> {
  if (typeof file?.name !== 'string' || !(file.data instanceof ArrayBuffer)) {
    throw new CipherDropCryptoError('INVALID_PAYLOAD', 'file must have a string name and an ArrayBuffer data.');
  }
  const name = new TextEncoder().encode(file.name);
  if (name.byteLength > MAX_FILE_NAME_BYTES) {
    throw new CipherDropCryptoError('INVALID_PAYLOAD', `file name must be at most ${MAX_FILE_NAME_BYTES} bytes in UTF-8.`);
  }

  const data = new Uint8Array(file.data);
  const envelope = new Uint8Array(1 + 2 + name.byteLength + data.byteLength);
  envelope[0] = FORMAT_FILE;
  new DataView(envelope.buffer).setUint16(1, name.byteLength); // ビッグエンディアン
  envelope.set(name, 3);
  envelope.set(data, 3 + name.byteLength);
  return envelope;
}

function fromEnvelope(plaintext: Uint8Array<ArrayBuffer>): DecryptedPayload {
  const body = plaintext.subarray(1);
  switch (plaintext[0]) {
    case FORMAT_TEXT:
      return { type: 'text', text: decodeUtf8(body, 'Decrypted text is not valid UTF-8.') };
    case FORMAT_BINARY:
      return { type: 'binary', data: body.slice().buffer };
    case FORMAT_FILE:
      return fromFileBody(body);
    default:
      throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', 'Unknown payload format.');
  }
}

/** 認証は通っていても、中身の構造は信頼しない（送信者が壊れた／悪意ある構造を作れる）。境界を厳密に検査する。 */
function fromFileBody(body: Uint8Array<ArrayBuffer>): DecryptedPayload {
  if (body.byteLength < 2) {
    throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', 'File payload is truncated.');
  }
  const nameLength = new DataView(body.buffer, body.byteOffset, body.byteLength).getUint16(0);
  if (nameLength > MAX_FILE_NAME_BYTES || 2 + nameLength > body.byteLength) {
    throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', 'File payload has an invalid name length.');
  }
  const name = decodeUtf8(body.subarray(2, 2 + nameLength), 'File name is not valid UTF-8.');
  return { type: 'file', name, data: body.slice(2 + nameLength).buffer };
}

/** fatal: 不正な UTF-8 を U+FFFD に黙って置換しない。ignoreBOM: 先頭の U+FEFF も欠落させない。 */
function decodeUtf8(bytes: Uint8Array, failureMessage: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new CipherDropCryptoError('UNSUPPORTED_FORMAT', failureMessage);
  }
}

function parseKeyString(keyString: string): Uint8Array<ArrayBuffer> | null {
  const raw = typeof keyString === 'string' && keyString.length === KEY_STRING_LENGTH
    ? base64UrlDecode(keyString)
    : null;
  return raw !== null && raw.byteLength === KEY_BYTES ? raw : null;
}

/**
 * 鍵の形式（base64url・256bit・正規表現）が正しいかを返す。復号はしない。
 * 受信画面で、暗号文を「消費する前」にリンクの欠け・余分な文字を検出するために使う
 * （形式不正の鍵で消費すると、データだけが失われる）。
 */
export function isValidKeyString(keyString: string): boolean {
  return parseKeyString(keyString) !== null;
}

function decodeKeyString(keyString: string): Uint8Array<ArrayBuffer> {
  const raw = parseKeyString(keyString);
  if (raw === null) {
    throw new CipherDropCryptoError('INVALID_KEY', 'Key must be a base64url string encoding 256 bits.');
  }
  return raw;
}

/** 鍵確認値の形式（SHA-256 の先頭 32bit、16進小文字 8 桁）。api.ts がサーバー応答の検証に使う。 */
export const KEY_CHECK_PATTERN = /^[0-9a-f]{8}$/;

/**
 * 鍵確認値（Key Check Tag）: 共有リンクのコピペミス・途中欠損を、消費する前に検出するための短いタグ。
 * 秘匿のためではない。 `SHA-256(ドメイン分離文字列 + 鍵)` の先頭 32bit（16進小文字 8 桁）。
 *
 * - **一方向性**: この値から鍵は復元できない。32bit まで絞り込んでも、残り 224bit の全数探索は
 *   非現実的なので、鍵の総当たりを実用的に助けることはない。
 * - **ドメイン分離**: 固定の接頭辞（cipherdrop-key-check-v1:）を混ぜているので、この値が他の用途の
 *   ハッシュと衝突・混同しない。
 * - **絶対遵守ルール「復号鍵はサーバーに送らない」への例外ではない**: サーバーへ送るのは鍵そのもの
 *   ではなく、鍵の一方向関数の出力の一部（32bit）だけ。ただし、サーバーが鍵について一切の情報を
 *   持たないという意味の完全なゼロ知識ではなくなる、という点は意図した・限定的なトレードオフ
 *   （README「信頼モデルと既知の制約」参照）。
 *
 * @param keyStr 確認値を計算したい鍵の文字列。形式は検証しない（受取画面では isValidKeyString の後に呼ぶ）。
 */
export async function generateKeyCheckTag(keyStr: string): Promise<string> {
  const subtle = getSubtle();
  const bytes = new TextEncoder().encode(`${KEY_CHECK_DOMAIN}${keyStr}`);
  const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
  return toHex(digest.subarray(0, KEY_CHECK_HEX_DIGITS / 2));
}

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
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
