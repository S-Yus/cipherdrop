import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';
import { describe, it } from 'node:test';
import type { TestContext } from 'node:test';
import { createServer, DEFAULT_TTL_SECONDS, HEADER_IV, HEADER_KEY_CHECK, HEADER_TTL, HEADER_TYPE } from './server.ts';
import type { LogEvent, ServerOptions } from './server.ts';
import { InMemoryPayloadStore } from './store.ts';
import type { InMemoryStoreOptions, PayloadMeta, StoredPayload } from './store.ts';

const T0 = 1_700_000_000_000;
const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

// ---------------------------------------------------------------------------
// テスト用の部品
// ---------------------------------------------------------------------------

/** 保存・確認・取得の呼び出しを記録するストア（サーバーが「何を受け取り、何を保存したか」を検査する）。 */
class RecordingStore extends InMemoryPayloadStore {
  readonly puts: Array<{ id: string; payload: StoredPayload; ttlSeconds: number }> = [];
  readonly stats: string[] = [];
  readonly takes: string[] = [];

  override async put(id: string, payload: StoredPayload, ttlSeconds: number) {
    this.puts.push({ id, payload, ttlSeconds });
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

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** take() で削除を終えた直後に止まるストア。「削除 → 応答」の順序を検査するために使う。 */
class GatedStore extends RecordingStore {
  readonly deleted = deferred();
  readonly release = deferred();

  override async take(id: string) {
    const result = await super.take(id);
    this.deleted.resolve();
    await this.release.promise;
    return result;
  }
}

class FailingStore extends RecordingStore {
  override async put(): Promise<never> {
    throw new Error('SECRET-INTERNAL-DETAIL: user supplied data must never reach logs or responses');
  }
}

interface Harness<S extends RecordingStore> {
  baseUrl: string;
  port: number;
  store: S;
  logs: LogEvent[];
  advanceClock(ms: number): void;
}

async function startHarness<S extends RecordingStore = RecordingStore>(
  t: TestContext,
  config: {
    createStore?: (options: InMemoryStoreOptions) => S;
    storeOptions?: InMemoryStoreOptions;
    server?: ServerOptions;
  } = {},
): Promise<Harness<S>> {
  let now = T0;
  const storeOptions: InMemoryStoreOptions = { now: () => now, sweepIntervalMs: 0, ...config.storeOptions };
  const store = config.createStore ? config.createStore(storeOptions) : (new RecordingStore(storeOptions) as S);
  const logs: LogEvent[] = [];
  const server = createServer({ store, log: (event) => logs.push(event), ...config.server });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store.close();
  });

  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    store,
    logs,
    advanceClock(ms) {
      now += ms;
    },
  };
}

function makeUpload(size = 48) {
  return { ciphertext: new Uint8Array(randomBytes(size)), iv: new Uint8Array(randomBytes(12)) };
}

type Upload = ReturnType<typeof makeUpload>;

/** POST /api/payload。headers に undefined を渡すとそのヘッダーを送らない。種別ヘッダーの既定は text。 */
function postPayload(
  h: Harness<RecordingStore>,
  upload: Upload = makeUpload(),
  headers: Record<string, string | undefined> = {},
  body: Uint8Array = upload.ciphertext,
): Promise<Response> {
  const merged = {
    'content-type': 'application/octet-stream',
    [HEADER_IV]: Buffer.from(upload.iv).toString('base64url'),
    [HEADER_TYPE]: 'text',
    ...headers,
  };
  const defined = Object.entries(merged).filter((entry): entry is [string, string] => entry[1] !== undefined);
  return fetch(`${h.baseUrl}/api/payload`, { method: 'POST', headers: Object.fromEntries(defined), body });
}

async function createSecret(h: Harness<RecordingStore>, headers: Record<string, string | undefined> = {}) {
  const upload = makeUpload();
  const response = await postPayload(h, upload, headers);
  assert.equal(response.status, 201);
  const body = (await response.json()) as { id: string; expiresAt: string };
  return { ...upload, ...body };
}

/** GET /api/payload/:id/meta（確認。何も消費しない）。 */
function getMeta(h: Harness<RecordingStore>, id: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${h.baseUrl}/api/payload/${id}/meta`, init);
}

/** POST /api/payload/:id/consume（消費。暗号文を返し、返す前に削除する）。 */
function consume(h: Harness<RecordingStore>, id: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${h.baseUrl}/api/payload/${id}/consume`, { method: 'POST', ...init });
}

/** 生の TCP で HTTP を送る（fetch では作れない不正なパス・chunked・途中切断などのため）。 */
function rawExchange(port: number, request: string | Buffer): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect(port, '127.0.0.1');
    const chunks: Buffer[] = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', () => {}); // 切断されても、受信できた分で判定する
    socket.on('close', () => resolve(Buffer.concat(chunks).toString('latin1')));
    socket.setTimeout(3000, () => socket.destroy());
    socket.write(request);
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// POST /api/payload
// ---------------------------------------------------------------------------

describe('POST /api/payload', () => {
  it('ID と有効期限を返し、暗号文・IV・種別だけをそのまま保存する', async (t) => {
    const h = await startHarness(t);
    const upload = makeUpload(64);

    const response = await postPayload(h, upload);
    assert.equal(response.status, 201);
    assert.match(response.headers.get('content-type') ?? '', /^application\/json/);
    const body = (await response.json()) as { id: string; expiresAt: string };
    assert.deepEqual(Object.keys(body).sort(), ['expiresAt', 'id']);
    assert.match(body.id, ID_PATTERN);
    assert.equal(body.expiresAt, new Date(T0 + DEFAULT_TTL_SECONDS * 1000).toISOString());

    assert.equal(h.store.puts.length, 1);
    const [stored] = h.store.puts;
    assert.equal(stored?.id, body.id);
    assert.deepEqual(Object.keys(stored?.payload ?? {}).sort(), ['ciphertext', 'iv', 'type'], '保存するのは暗号文・IV・種別ヒントだけ');
    assert.deepEqual(new Uint8Array(stored?.payload.ciphertext ?? []), upload.ciphertext);
    assert.deepEqual(new Uint8Array(stored?.payload.iv ?? []), upload.iv);
    assert.equal(stored?.payload.type, 'text');
  });

  it('種別ヒントは text / file のどちらも受け付けて保存する', async (t) => {
    const h = await startHarness(t);
    await createSecret(h, { [HEADER_TYPE]: 'text' });
    await createSecret(h, { [HEADER_TYPE]: 'file' });
    assert.deepEqual(h.store.puts.map((p) => p.payload.type), ['text', 'file']);
  });

  it('発行される ID は 128bit の乱数で、重複しない', async (t) => {
    const h = await startHarness(t);
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) ids.add((await createSecret(h)).id);
    assert.equal(ids.size, 100);
  });

  describe('有効期限 (X-CipherDrop-TTL)', () => {
    for (const [ttl, expectedSeconds] of [
      [undefined, DEFAULT_TTL_SECONDS],
      ['3600', 3600],
      ['60', 60],
      ['604800', 604800],
    ] as const) {
      it(`TTL=${ttl ?? '(省略)'} → ${expectedSeconds} 秒後に期限切れ`, async (t) => {
        const h = await startHarness(t);
        const secret = await createSecret(h, { [HEADER_TTL]: ttl });
        assert.equal(secret.expiresAt, new Date(T0 + expectedSeconds * 1000).toISOString());
        assert.equal(h.store.puts[0]?.ttlSeconds, expectedSeconds);
      });
    }

    for (const ttl of ['59', '604801', '0', '-60', '60.5', '1e3', 'abc', '', '9999999999']) {
      it(`不正な TTL ${JSON.stringify(ttl)} は 400 invalid_ttl で、保存しない`, async (t) => {
        const h = await startHarness(t);
        const response = await postPayload(h, makeUpload(), { [HEADER_TTL]: ttl });
        assert.equal(response.status, 400);
        assert.deepEqual(await response.json(), { error: 'invalid_ttl' });
        assert.equal(h.store.puts.length, 0);
      });
    }
  });

  describe('入力検証', () => {
    const cases: Array<{
      name: string;
      headers?: Record<string, string | undefined>;
      bodySize?: number;
      status: number;
      error: string;
    }> = [
      { name: 'IV ヘッダーなし', headers: { [HEADER_IV]: undefined }, status: 400, error: 'invalid_iv' },
      { name: 'IV が短い (11 バイト)', headers: { [HEADER_IV]: randomBytes(11).toString('base64url') }, status: 400, error: 'invalid_iv' },
      { name: 'IV が長い (13 バイト)', headers: { [HEADER_IV]: randomBytes(13).toString('base64url') }, status: 400, error: 'invalid_iv' },
      { name: 'IV が標準 base64（+ / =）', headers: { [HEADER_IV]: 'AAAA+/AAAAAAAAA=' }, status: 400, error: 'invalid_iv' },
      { name: 'IV が空', headers: { [HEADER_IV]: '' }, status: 400, error: 'invalid_iv' },
      { name: '種別ヘッダーなし', headers: { [HEADER_TYPE]: undefined }, status: 400, error: 'invalid_type' },
      { name: '種別が未定義の値 (image)', headers: { [HEADER_TYPE]: 'image' }, status: 400, error: 'invalid_type' },
      { name: '種別が大文字 (TEXT)', headers: { [HEADER_TYPE]: 'TEXT' }, status: 400, error: 'invalid_type' },
      { name: '種別が空', headers: { [HEADER_TYPE]: '' }, status: 400, error: 'invalid_type' },
      { name: '種別が複数指定 (text, file)', headers: { [HEADER_TYPE]: 'text, file' }, status: 400, error: 'invalid_type' },
      { name: 'Content-Type なし', headers: { 'content-type': undefined }, status: 415, error: 'unsupported_media_type' },
      { name: 'Content-Type が text/plain', headers: { 'content-type': 'text/plain' }, status: 415, error: 'unsupported_media_type' },
      { name: 'Content-Type が application/json', headers: { 'content-type': 'application/json' }, status: 415, error: 'unsupported_media_type' },
      { name: '本文が空', bodySize: 0, status: 400, error: 'invalid_ciphertext' },
      { name: '本文が GCM タグ長 (16 バイト) 未満', bodySize: 15, status: 400, error: 'invalid_ciphertext' },
    ];

    for (const { name, headers, bodySize, status, error } of cases) {
      it(`${name} → ${status} ${error}（保存しない）`, async (t) => {
        const h = await startHarness(t);
        const upload = makeUpload(bodySize ?? 48);
        const response = await postPayload(h, upload, headers);
        assert.equal(response.status, status);
        assert.deepEqual(await response.json(), { error });
        assert.equal(h.store.puts.length, 0);
      });
    }

    it('最小長 (16 バイト) の本文と、charset 付き・大文字の Content-Type は受け付ける', async (t) => {
      const h = await startHarness(t);
      assert.equal((await postPayload(h, makeUpload(16))).status, 201);
      assert.equal((await postPayload(h, makeUpload(), { 'content-type': 'Application/Octet-Stream; charset=binary' })).status, 201);
    });

    it('クエリ文字列は 400 で拒否する（鍵などをクエリに載せる実装ミスを即発見できるように）', async (t) => {
      const h = await startHarness(t);
      const response = await fetch(`${h.baseUrl}/api/payload?ttl=60&key=SECRETKEY`, {
        method: 'POST',
        headers: {
          'content-type': 'application/octet-stream',
          [HEADER_IV]: Buffer.alloc(12).toString('base64url'),
          [HEADER_TYPE]: 'text',
        },
        body: new Uint8Array(32),
      });
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { error: 'query_not_allowed' });
      assert.equal(h.store.puts.length, 0);
    });

    it('POST 以外のメソッドは 405（Allow: POST）', async (t) => {
      const h = await startHarness(t);
      for (const method of ['GET', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
        const response = await fetch(`${h.baseUrl}/api/payload`, { method });
        assert.equal(response.status, 405, method);
        assert.equal(response.headers.get('allow'), 'POST');
      }
    });
  });

  describe('サイズ上限・容量上限・切断', () => {
    it('宣言サイズ (Content-Length) が上限超過なら 413 で保存しない。ちょうど上限は受け付ける', async (t) => {
      const h = await startHarness(t, { server: { maxPayloadBytes: 1024 } });

      const tooLarge = await postPayload(h, makeUpload(1025));
      assert.equal(tooLarge.status, 413);
      assert.deepEqual(await tooLarge.json(), { error: 'payload_too_large' });
      assert.equal(h.store.puts.length, 0);

      assert.equal((await postPayload(h, makeUpload(1024))).status, 201);
    });

    it('Content-Length を持たない chunked 送信でも、上限を超えた時点で 413 にして保存しない', async (t) => {
      const h = await startHarness(t, { server: { maxPayloadBytes: 1024 } });
      const iv = Buffer.alloc(12, 1).toString('base64url');
      const chunk = Buffer.alloc(2048, 0x41);
      const request = Buffer.concat([
        Buffer.from(
          `POST /api/payload HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n` +
            `${HEADER_IV}: ${iv}\r\n${HEADER_TYPE}: file\r\nTransfer-Encoding: chunked\r\n\r\n${chunk.length.toString(16)}\r\n`,
        ),
        chunk,
        Buffer.from('\r\n0\r\n\r\n'),
      ]);

      const response = await rawExchange(h.port, request);
      assert.match(response, /^HTTP\/1\.1 413 /);
      assert.equal(h.store.puts.length, 0);
    });

    it('保存容量が上限に達すると 503 storage_full。消費して空きができれば再び保存できる', async (t) => {
      const h = await startHarness(t, { storeOptions: { maxTotalBytes: 100 } });
      const first = await createSecret(h); // 48 + 12 = 60 バイト

      const rejected = await postPayload(h);
      assert.equal(rejected.status, 503);
      assert.equal(rejected.headers.get('retry-after'), '60');
      assert.deepEqual(await rejected.json(), { error: 'storage_full' });

      assert.equal((await consume(h, first.id)).status, 200);
      assert.equal((await postPayload(h)).status, 201);
    });

    it('アップロード途中でクライアントが切断しても、サーバーは落ちず何も保存しない', async (t) => {
      const h = await startHarness(t);
      const iv = Buffer.alloc(12, 2).toString('base64url');
      const socket = connect(h.port, '127.0.0.1');
      socket.on('error', () => {});
      await new Promise<void>((resolve) => socket.once('connect', resolve));
      // Content-Length: 1000 と宣言しながら 10 バイトだけ送り、残りを送らずに切断する
      socket.write(
        `POST /api/payload HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n${HEADER_IV}: ${iv}\r\n` +
          `${HEADER_TYPE}: text\r\nContent-Length: 1000\r\n\r\n0123456789`,
      );
      await sleep(30);
      socket.destroy();
      await sleep(50);

      assert.equal(h.store.puts.length, 0);
      assert.equal((await postPayload(h)).status, 201, '切断の後も通常のリクエストを処理できる');
    });

    it('ロガーが例外を投げても、リクエストは成功しサーバーは落ちない（プロセス停止は未読データの全消失になる）', async (t) => {
      const h = await startHarness(t, {
        server: {
          log: () => {
            throw new Error('log sink is broken');
          },
        },
      });

      const secret = await createSecret(h);
      await sleep(50); // 未処理の reject があれば、この間にテストランナーが検出する
      assert.equal((await consume(h, secret.id)).status, 200);
      assert.equal((await consume(h, secret.id)).status, 404);
    });

    it('想定外の例外は 500 internal_error だけを返し、内部情報・入力値をレスポンスにもログにも出さない', async (t) => {
      const h = await startHarness(t, { createStore: (options) => new FailingStore(options) });
      const response = await postPayload(h);

      assert.equal(response.status, 500);
      assert.equal(await response.text(), '{"error":"internal_error"}');
      assert.deepEqual(h.logs.filter((e) => e.event === 'error'), [{ event: 'error', name: 'Error', code: null }]);
      assert.equal(JSON.stringify(h.logs).includes('SECRET-INTERNAL-DETAIL'), false);
    });
  });
});

describe('POST /api/payload: 鍵確認値（X-CipherDrop-Key-Check、任意）', () => {
  it('付けて作成すると、そのまま保存され、meta のレスポンスにも現れる', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h, { [HEADER_KEY_CHECK]: 'deadbeef' });

    assert.equal(h.store.puts[0]?.payload.keyCheck, 'deadbeef');
    const body = (await (await getMeta(h, secret.id)).json()) as { keyCheck?: string };
    assert.equal(body.keyCheck, 'deadbeef');
  });

  it('付けずに作成すると、meta のレスポンス JSON に "keyCheck" キー自体が現れない（後方互換）', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    assert.equal(h.store.puts[0]?.payload.keyCheck, undefined);
    const text = await (await getMeta(h, secret.id)).text();
    assert.deepEqual(Object.keys(JSON.parse(text)).sort(), ['expiresAt', 'size', 'type']);
  });

  for (const bad of ['short', 'toolonghexvalue', 'DEADBEEF', 'not-hex!', '1234567', '123456789', '']) {
    it(`形式が不正 (${JSON.stringify(bad)}) な値は無視される。作成自体は成功し、keyCheck は保存されない`, async (t) => {
      const h = await startHarness(t);
      const response = await postPayload(h, makeUpload(), { [HEADER_KEY_CHECK]: bad });

      assert.equal(response.status, 201, '任意のヒントなので、不正でもリクエスト全体は失敗させない');
      assert.equal(h.store.puts[0]?.payload.keyCheck, undefined);
    });
  }
});

// ---------------------------------------------------------------------------
// GET /api/payload/:id/meta  （確認: 何も消費しない）
// ---------------------------------------------------------------------------

describe('GET /api/payload/:id/meta', () => {
  it('種別・サイズ・有効期限だけを返す。暗号文・IV・ID は含まれない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h, { [HEADER_TYPE]: 'file', [HEADER_TTL]: '3600' });

    const response = await getMeta(h, secret.id);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /^application\/json/);

    const text = await response.text();
    assert.deepEqual(JSON.parse(text), {
      type: 'file',
      size: secret.ciphertext.byteLength,
      expiresAt: new Date(T0 + 3600 * 1000).toISOString(),
    });
    for (const leaked of [
      secret.id,
      Buffer.from(secret.ciphertext).toString('base64'),
      Buffer.from(secret.ciphertext).toString('base64url'),
      Buffer.from(secret.ciphertext).toString('hex'),
      Buffer.from(secret.iv).toString('base64url'),
      Buffer.from(secret.iv).toString('hex'),
    ]) {
      assert.equal(text.includes(leaked), false);
    }
  });

  it('何度呼んでも何も消費しない。メタ確認を 50 回しても、その後の consume は成功する', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const responses = await Promise.all(Array.from({ length: 50 }, () => getMeta(h, secret.id)));
    assert.ok(responses.every((r) => r.status === 200));
    assert.equal(h.store.takes.length, 0, 'meta は take() を呼ばない');
    assert.equal(h.store.size, 1, '暗号文はストアに残っている');

    const consumed = await consume(h, secret.id);
    assert.equal(consumed.status, 200);
    assert.deepEqual(new Uint8Array(await consumed.arrayBuffer()), secret.ciphertext);
  });

  it('有効期限を延ばさない（何度呼んでも expiresAt は変わらない）', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h, { [HEADER_TTL]: '60' });

    const before = (await (await getMeta(h, secret.id)).json()) as { expiresAt: string };
    h.advanceClock(30_000);
    const after = (await (await getMeta(h, secret.id)).json()) as { expiresAt: string };
    assert.equal(after.expiresAt, before.expiresAt);
    assert.equal(after.expiresAt, secret.expiresAt);
  });

  it('未発行・消費済み・期限切れは、すべて同じ 404 not_found', async (t) => {
    const h = await startHarness(t);
    const consumed = await createSecret(h);
    await consume(h, consumed.id);
    const expired = await createSecret(h, { [HEADER_TTL]: '60' });
    h.advanceClock(61_000);

    const responses = [
      await getMeta(h, consumed.id),
      await getMeta(h, expired.id),
      await getMeta(h, randomBytes(16).toString('base64url')),
    ];
    for (const response of responses) {
      assert.equal(response.status, 404);
      assert.deepEqual(await response.json(), { error: 'not_found' });
    }
  });

  it('meta は期限切れでも削除しない（副作用なし）。削除は consume / 掃除の役目', async (t) => {
    const h = await startHarness(t);
    const expired = await createSecret(h, { [HEADER_TTL]: '60' });
    h.advanceClock(61_000);

    assert.equal((await getMeta(h, expired.id)).status, 404);
    assert.equal(h.store.size, 1, 'meta では消えない');
    assert.equal(h.store.takes.length, 0);
  });

  it('クエリ付きは 400 で拒否する', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const response = await fetch(`${h.baseUrl}/api/payload/${secret.id}/meta?key=SECRETKEY`);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'query_not_allowed' });
    assert.equal(h.store.stats.length, 0);
  });

  it('GET 以外のメソッドは 405（Allow: GET）で、ストアに触れない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    for (const method of ['POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const response = await getMeta(h, secret.id, { method });
      assert.equal(response.status, 405, method);
      assert.equal(response.headers.get('allow'), 'GET');
    }
    assert.equal(h.store.stats.length, 0);
    assert.equal(h.store.takes.length, 0);
  });
});

// ---------------------------------------------------------------------------
// POST /api/payload/:id/consume  （消費: 1 回読み切り・即時削除）
// ---------------------------------------------------------------------------

describe('POST /api/payload/:id/consume', () => {
  it('暗号文と IV をそのまま返す。取得した時点でストアからは削除済み', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);
    assert.equal(h.store.size, 1);

    const response = await consume(h, secret.id);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'application/octet-stream');
    assert.equal(response.headers.get(HEADER_IV), Buffer.from(secret.iv).toString('base64url'));
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secret.ciphertext);

    assert.equal(h.store.size, 0, 'DELETE 済み');
    assert.equal(h.store.totalBytes, 0);
  });

  it('通常フロー: meta で確認 → consume で取得 → 以降は meta も consume も 404', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h, { [HEADER_TYPE]: 'file' });

    assert.equal((await getMeta(h, secret.id)).status, 200);
    assert.equal((await consume(h, secret.id)).status, 200);
    assert.equal((await getMeta(h, secret.id)).status, 404, '消費後は meta でも存在しない');
    assert.equal((await consume(h, secret.id)).status, 404);
  });

  it('2 回目は 404。一度も発行されていない ID と全く同じレスポンスで、区別できない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);
    await consume(h, secret.id);

    const consumed = await consume(h, secret.id);
    const neverIssued = await consume(h, randomBytes(16).toString('base64url'));

    for (const response of [consumed, neverIssued]) {
      assert.equal(response.status, 404);
      assert.deepEqual(await response.clone().json(), { error: 'not_found' });
    }
    const comparable = (r: Response) => [r.status, r.headers.get('content-length'), r.headers.get('content-type'), r.headers.get('cache-control')];
    assert.deepEqual(comparable(consumed), comparable(neverIssued));
  });

  it('ストアからの削除は、レスポンスを返し始める前に完了している', async (t) => {
    const h = await startHarness(t, { createStore: (options) => new GatedStore(options) });
    const secret = await createSecret(h);

    let responded = false;
    const pending = consume(h, secret.id).then((response) => {
      responded = true;
      return response;
    });

    await h.store.deleted.promise; // take() が削除を終えた
    assert.equal(h.store.size, 0, 'この時点で既に削除済み');
    await sleep(50);
    assert.equal(responded, false, '削除が終わっても、take() が返るまではレスポンスを書き出さない');

    h.store.release.resolve();
    const response = await pending;
    assert.equal(response.status, 200);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), secret.ciphertext);
  });

  it('50 件同時に consume しても、成功するのは 1 回だけ', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const responses = await Promise.all(Array.from({ length: 50 }, () => consume(h, secret.id)));
    const statuses = responses.map((r) => r.status);
    assert.equal(statuses.filter((s) => s === 200).length, 1);
    assert.equal(statuses.filter((s) => s === 404).length, 49);

    const winner = responses.find((r) => r.status === 200);
    assert.deepEqual(new Uint8Array(await (winner as Response).arrayBuffer()), secret.ciphertext);
  });

  it('期限切れは 404 で、暗号文もストアから削除される', async (t) => {
    const h = await startHarness(t);
    const expired = await createSecret(h, { [HEADER_TTL]: '60' });
    const alive = await createSecret(h, { [HEADER_TTL]: '3600' });

    h.advanceClock(61_000);
    assert.equal((await consume(h, expired.id)).status, 404);
    assert.equal(h.store.size, 1, '期限切れ分は consume の試行でも削除される');
    assert.equal((await consume(h, alive.id)).status, 200);
  });

  it('クエリ付きのリクエストは 400 で拒否し、暗号文は消費しない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const response = await fetch(`${h.baseUrl}/api/payload/${secret.id}/consume?key=SECRETKEY`, { method: 'POST' });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'query_not_allowed' });
    assert.equal(h.store.takes.length, 0);

    assert.equal((await consume(h, secret.id)).status, 200, '正しいリクエストではまだ取得できる');
  });

  it('POST 以外のメソッド（GET・HEAD・PUT・DELETE・PATCH・OPTIONS）は 405 で、暗号文を消費しない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const response = await consume(h, secret.id, { method });
      assert.equal(response.status, 405, method);
      assert.equal(response.headers.get('allow'), 'POST');
      assert.notEqual(response.headers.get('content-type'), 'application/octet-stream', '本体は返らない');
    }
    assert.equal(h.store.takes.length, 0, 'ストアには一切触れていない');
    assert.equal((await consume(h, secret.id)).status, 200);
  });
});

// ---------------------------------------------------------------------------
// 2 段階仕様の要: 受信者が開く前に消えない
// ---------------------------------------------------------------------------

describe('リンクプレビュー・クローラー・疎通確認が何を叩いても、受信者が開く前にデータは消えない', () => {
  it('GET / HEAD / OPTIONS / DELETE を旧 URL・meta・consume に浴びせた後でも、POST consume で 1 回だけ取得できる', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);
    const item = `${h.baseUrl}/api/payload/${secret.id}`;

    // 実在のボットが行いそうなアクセスをすべて試す（旧仕様の GET /api/payload/:id を含む）。
    // 期待するのは「GET /meta だけが 200（メタ情報）で、それ以外は本体を返さない 404 / 405」。
    const botRequests: Array<{ method: string; suffix: string; expected: number }> = [];
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'DELETE', 'PUT', 'PATCH', 'POST']) {
      botRequests.push({ method, suffix: '', expected: 404 }); // 旧 URL は廃止
    }
    for (const method of ['GET', 'HEAD', 'OPTIONS', 'DELETE', 'PUT', 'PATCH']) {
      botRequests.push({ method, suffix: '/meta', expected: method === 'GET' ? 200 : 405 });
      botRequests.push({ method, suffix: '/consume', expected: 405 }); // POST 以外は消費しない
    }
    for (const { method, suffix, expected } of botRequests) {
      const response = await fetch(`${item}${suffix}`, { method });
      assert.equal(response.status, expected, `${method} ${suffix || '(旧 URL)'}`);
      assert.notEqual(response.headers.get('content-type'), 'application/octet-stream', '暗号文は返らない');
      await response.arrayBuffer();
    }
    assert.equal(h.store.takes.length, 0, 'GET 系・HEAD 等では一度も take() が呼ばれていない');
    assert.equal(h.store.size, 1);

    // 受信者が明示的に開いたとき（POST consume）だけ取得できる
    const consumed = await consume(h, secret.id);
    assert.equal(consumed.status, 200);
    assert.deepEqual(new Uint8Array(await consumed.arrayBuffer()), secret.ciphertext);
    assert.equal(h.store.takes.length, 1);
    assert.equal((await consume(h, secret.id)).status, 404);
  });

  it('旧仕様の GET /api/payload/:id は廃止されており、どのメソッドでも 404 で本体を返さない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    for (const method of ['GET', 'HEAD', 'POST', 'DELETE']) {
      const response = await fetch(`${h.baseUrl}/api/payload/${secret.id}`, { method });
      assert.equal(response.status, 404, method);
      assert.notEqual(response.headers.get('content-type'), 'application/octet-stream');
    }
    assert.equal(h.store.takes.length, 0);
    assert.equal(h.store.stats.length, 0);
  });

  it('GET /consume は本体を返さず 405（メタ確認だけなら GET /meta を使う）', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const response = await fetch(`${h.baseUrl}/api/payload/${secret.id}/consume`);
    assert.equal(response.status, 405);
    assert.deepEqual(await response.json(), { error: 'method_not_allowed' });
    assert.equal(h.store.size, 1);
  });
});

// ---------------------------------------------------------------------------
// ID・パスの厳格な検証
// ---------------------------------------------------------------------------

describe('ID・パスの検証', () => {
  it('形式の正しくない ID・パスは、ストアに触れず 404（または 400）', async (t) => {
    const h = await startHarness(t);
    const valid = randomBytes(16).toString('base64url');

    const viaFetch = [
      valid.slice(0, 21), // 短い
      `${valid}A`, // 長い
      `${valid.slice(0, 21)}.`,
      `${valid.slice(0, 21)}+`,
      'abc',
    ];
    for (const id of viaFetch) {
      assert.equal((await getMeta(h, id)).status, 404, `meta ${id}`);
      assert.equal((await consume(h, id)).status, 404, `consume ${id}`);
    }

    // fetch は URL を正規化してしまうため、生の TCP で送る
    const rawTargets: Array<[string, string]> = [
      ['GET', '/api/payload/../payload/meta'],
      ['GET', '/api/payload/%2e%2e/x/meta'],
      ['POST', `/api/payload/%41${valid.slice(3)}/consume`],
      ['GET', `/api/payload//${valid}/meta`],
      ['GET', `/api/payload/${valid}/meta#fragment`],
      ['GET', `/api/payload/${valid}/META`], // 大文字は別ルート（存在しない）
      ['GET', `/api/payload/${valid}/meta/`], // 末尾スラッシュ
      ['POST', `/api/payload/${valid}/consume/extra`],
      ['POST', `/api/payload/${valid}/`],
      ['GET', `http://evil.example/api/payload/${valid}/meta`],
      ['GET', '/'],
      ['GET', '/api'],
    ];
    for (const [method, target] of rawTargets) {
      const response = await rawExchange(h.port, `${method} ${target} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
      assert.match(response, /^HTTP\/1\.1 (404|400) /, `${method} ${target}`);
    }
    assert.equal(h.store.takes.length, 0);
    assert.equal(h.store.stats.length, 0);
  });
});

// ---------------------------------------------------------------------------
// セキュリティヘッダー・ログ
// ---------------------------------------------------------------------------

describe('レスポンスヘッダー', () => {
  it('成功・失敗を問わず、キャッシュ禁止などのセキュリティヘッダーを付け、CORS は許可しない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h);

    const responses = [
      await postPayload(h), // 201
      await postPayload(h, makeUpload(), { 'content-type': 'text/plain' }), // 415
      await getMeta(h, secret.id), // 200（JSON）
      await consume(h, secret.id), // 200（バイナリ）
      await consume(h, secret.id), // 404
      await getMeta(h, secret.id), // 404
      await fetch(`${h.baseUrl}/nope`), // 404
      await fetch(`${h.baseUrl}/api/payload`, { method: 'OPTIONS', headers: { origin: 'https://evil.example' } }), // 405
    ];
    for (const response of responses) {
      assert.equal(response.headers.get('cache-control'), 'no-store', `${response.status}`);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(response.headers.get('content-security-policy'), "default-src 'none'; frame-ancestors 'none'");
      assert.equal(response.headers.get('cross-origin-resource-policy'), 'same-origin');
      assert.equal(response.headers.get('access-control-allow-origin'), null, 'CORS は許可しない（同一オリジン運用）');
      await response.arrayBuffer();
    }
  });
});

describe('ログ', () => {
  it('固定スキーマのイベントだけを出し、ID・IV・暗号文・URL・クエリを一切含まない', async (t) => {
    const h = await startHarness(t);
    const secret = await createSecret(h, { [HEADER_TYPE]: 'file' });
    await getMeta(h, secret.id);
    await consume(h, secret.id);
    await consume(h, secret.id); // 404
    await getMeta(h, secret.id); // 404
    await fetch(`${h.baseUrl}/api/payload/${secret.id}/meta?key=QUERYSECRET`); // 400
    await fetch(`${h.baseUrl}/no/such/path`);
    await rawExchange(h.port, 'BREW /api/payload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');

    const requestEvents = h.logs.filter((e) => e.event === 'request');
    assert.deepEqual(
      requestEvents.map((e) => `${e.method} ${e.route} ${e.status}`),
      [
        'POST create 201',
        'GET meta 200',
        'POST consume 200',
        'POST consume 404',
        'GET meta 404',
        'GET unmatched 400',
        'GET unmatched 404',
      ],
    );

    const allowedKeys = ['durationMs', 'event', 'method', 'route', 'status'];
    for (const event of requestEvents) {
      assert.deepEqual(Object.keys(event).sort(), allowedKeys);
    }

    const serialized = JSON.stringify(h.logs);
    const forbidden = [
      secret.id,
      Buffer.from(secret.iv).toString('base64url'),
      Buffer.from(secret.iv).toString('hex'),
      Buffer.from(secret.ciphertext).toString('base64'),
      Buffer.from(secret.ciphertext).toString('base64url'),
      Buffer.from(secret.ciphertext).toString('hex'),
      '/api/payload',
      'QUERYSECRET',
      'key=',
      '?',
      'file', // 種別ヒントもログに残さない
    ];
    for (const value of forbidden) {
      assert.equal(serialized.includes(value), false, `ログに "${value}" が含まれている`);
    }
  });
});
