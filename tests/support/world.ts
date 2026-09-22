/**
 * E2E の観測用部品。実サーバーを起動し、「サーバーが観測できたもの」をすべて記録する。
 *   - ネットワーク: サーバーが受信した生の TCP バイト列（リクエスト行・ヘッダー・本文のすべて）
 *   - ストレージ:   サーバーが保存した内容と、stat / take の呼び出し
 *   - ログ:         サーバーが出力したログ
 */
import assert from 'node:assert/strict';
import type { AddressInfo, Socket } from 'node:net';
import type { TestContext } from 'node:test';
import { createServer } from '../../apps/backend/src/server.ts';
import type { LogEvent, ServerOptions } from '../../apps/backend/src/server.ts';
import { InMemoryPayloadStore } from '../../apps/backend/src/store.ts';
import type { PayloadMeta, StoredPayload } from '../../apps/backend/src/store.ts';

/** サーバーが保存した内容と、確認（stat）・取得（take）の呼び出しを記録するストア。 */
export class RecordingStore extends InMemoryPayloadStore {
  readonly puts: StoredPayload[] = [];
  readonly stats: string[] = [];
  readonly takes: string[] = [];

  override async put(id: string, payload: StoredPayload, ttlSeconds: number) {
    // keyCheck が無ければキー自体を持たせない（記録が、実際に保存される形をそのまま映す）。
    const recorded: StoredPayload =
      payload.keyCheck === undefined
        ? { ciphertext: new Uint8Array(payload.ciphertext), iv: new Uint8Array(payload.iv), type: payload.type }
        : { ciphertext: new Uint8Array(payload.ciphertext), iv: new Uint8Array(payload.iv), type: payload.type, keyCheck: payload.keyCheck };
    this.puts.push(recorded);
    return super.put(id, payload, ttlSeconds);
  }

  override async stat(id: string): Promise<PayloadMeta | null> {
    this.stats.push(id);
    return super.stat(id);
  }

  override async take(id: string) {
    this.takes.push(id);
    return super.take(id);
  }
}

export async function startWorld<S extends RecordingStore = RecordingStore>(
  t: TestContext,
  createStore?: () => S,
  serverOptions: ServerOptions = {},
) {
  const store = createStore ? createStore() : (new RecordingStore({ sweepIntervalMs: 0 }) as S);
  const logs: LogEvent[] = [];
  const wire: Buffer[] = []; // サーバーが全接続で受信した生バイト列

  const server = createServer({ store, log: (event) => logs.push(event), ...serverOptions });
  server.on('connection', (socket: Socket) => {
    socket.on('data', (chunk: Buffer) => wire.push(chunk));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store.close();
  });

  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { origin, store, logs, observedOnWire: () => Buffer.concat(wire) };
}

export interface ObservedRequest {
  method: string;
  target: string;
  /** リクエスト行 + ヘッダー部（本文を含まない）。 */
  head: string;
  /** ヘッダー名は小文字。 */
  headers: Map<string, string>;
  body: Buffer;
}

/** 記録した生ストリームを HTTP/1.1 リクエストの列として読む（本文は Content-Length で切り出す）。 */
export function parseHttpRequests(stream: Buffer): ObservedRequest[] {
  const requests: ObservedRequest[] = [];
  let offset = 0;
  while (offset < stream.length) {
    const headEnd = stream.indexOf('\r\n\r\n', offset);
    assert.ok(headEnd >= 0, '途中で切れたリクエストが記録されている');

    const head = stream.subarray(offset, headEnd).toString('latin1');
    const [requestLine = '', ...headerLines] = head.split('\r\n');
    const [method = '', target = ''] = requestLine.split(' ');
    const headers = new Map<string, string>();
    for (const line of headerLines) {
      const colon = line.indexOf(':');
      headers.set(line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim());
    }

    const bodyStart = headEnd + 4;
    const bodyLength = Number(headers.get('content-length') ?? 0);
    requests.push({ method, target, head, headers, body: stream.subarray(bodyStart, bodyStart + bodyLength) });
    offset = bodyStart + bodyLength;
  }
  return requests;
}

/** 秘密の値が、よくある符号化のどれかで観測データに含まれていないかを返す。 */
export function leakedForms(observed: Buffer, secret: Buffer, label: string): string[] {
  const forms: Array<[string, Buffer | string]> = [
    [`${label} (raw)`, secret],
    [`${label} (hex)`, secret.toString('hex')],
    [`${label} (base64)`, secret.toString('base64')],
    [`${label} (base64url)`, secret.toString('base64url')],
  ];
  return forms.filter(([, needle]) => observed.includes(needle)).map(([name]) => name);
}
