/**
 * ファイルを暗号化する前に包むエンベロープ。ファイル名と MIME タイプも暗号文の中に入れ、サーバーからは見えないようにする。
 *
 *   [0..4)   マジック "CDF1"
 *   [4..8)   ヘッダー長 N（uint32, big endian）
 *   [8..8+N) ヘッダー（UTF-8 JSON: {"name": string, "type": string}）
 *   [8+N..)  ファイル本体
 *
 * 復号後のヘッダーも送信者が自由に作れる値なので、unpackFile は形式を厳格に検証し、
 * 名前は safeFileName で、MIME タイプは使わずに扱う（同一オリジンで HTML として描画させないため）。
 */

const MAGIC = [0x43, 0x44, 0x46, 0x31]; // "CDF1"
const PREFIX_BYTES = 8;
const MAX_HEADER_BYTES = 4096;
const MAX_NAME_LENGTH = 200;

export interface FileEnvelope {
  name: string;
  type: string;
  bytes: Uint8Array<ArrayBuffer>;
}

export function packFile(name: string, type: string, bytes: Uint8Array): ArrayBuffer {
  const header = new TextEncoder().encode(JSON.stringify({ name: name.slice(0, MAX_NAME_LENGTH), type: type.slice(0, 200) }));
  const out = new Uint8Array(PREFIX_BYTES + header.byteLength + bytes.byteLength);
  out.set(MAGIC, 0);
  new DataView(out.buffer).setUint32(4, header.byteLength);
  out.set(header, PREFIX_BYTES);
  out.set(bytes, PREFIX_BYTES + header.byteLength);
  return out.buffer;
}

/** packFile の出力でなければ null。 */
export function unpackFile(buffer: ArrayBuffer): FileEnvelope | null {
  const data = new Uint8Array(buffer);
  if (data.byteLength < PREFIX_BYTES || MAGIC.some((byte, i) => data[i] !== byte)) return null;

  const headerBytes = new DataView(buffer).getUint32(4);
  if (headerBytes > MAX_HEADER_BYTES || PREFIX_BYTES + headerBytes > data.byteLength) return null;

  let header: unknown;
  try {
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(PREFIX_BYTES, PREFIX_BYTES + headerBytes)));
  } catch {
    return null;
  }
  if (typeof header !== 'object' || header === null) return null;
  const { name, type } = header as { name?: unknown; type?: unknown };
  if (typeof name !== 'string' || typeof type !== 'string') return null;

  return { name, type, bytes: data.slice(PREFIX_BYTES + headerBytes) };
}

/**
 * ダウンロード時のファイル名として安全な形にする。パスは最後の要素だけを残し、制御文字・Windows の予約文字を除き、
 * 先頭のドットや空白を落とし、長さを制限する。空になったら既定名にする。
 */
export function safeFileName(name: string): string {
  const cleaned = (name.split(/[\\/]/).pop() ?? '')
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/^[\s.]+/, '')
    .replace(/[\s.]+$/, '')
    .slice(0, MAX_NAME_LENGTH);
  return cleaned === '' ? 'cipherdrop-file' : cleaned;
}
