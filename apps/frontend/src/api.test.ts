import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ApiError, createApiClient } from './api.ts';
import type { ApiErrorCode } from './api.ts';
import { base64UrlEncode } from './crypto.ts';

const ID = 'abcdefghijklmnopqrstuv';
const IV = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
/** consumeVerifier(必須ヘッダー)のテスト用ダミー値。SHA-256 全体・16進小文字 64 桁の形式だけを満たす。 */
const CONSUME_VERIFIER = 'a'.repeat(64);
/** consumeSecret(必須ヘッダー)のテスト用ダミー値。鍵と同じ base64url・256bit(43 文字)の形式だけを満たす。 */
const CONSUME_SECRET = 'b'.repeat(43);

interface Recorded {
  input: string;
  init: RequestInit;
}

/** 呼び出しを記録し、用意した応答を返す偽の fetch。 */
function fakeFetch(respond: (request: Recorded) => Response | Promise<Response>) {
  const requests: Recorded[] = [];
  const fetchImpl = async (input: string, init: RequestInit) => {
    const request = { input, init };
    requests.push(request);
    return respond(request);
  };
  return { requests, client: createApiClient(fetchImpl, 'https://api.test') };
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

async function errorOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ApiError, `ApiError であること（実際: ${String(error)}）`);
    return error;
  }
  assert.fail('例外が投げられなかった');
}

describe('createApiClient: リクエストの形', () => {
  it('createPayload: POST /api/payload に、暗号文・IV・種別・TTL・consumeVerifier をヘッダー/本文で送る', async () => {
    const { client, requests } = fakeFetch(() => json({ id: ID, expiresAt: '2026-09-23T00:00:00.000Z' }, 201));
    const encryptedData = new Uint8Array([1, 2, 3, 4]).buffer;

    const result = await client.createPayload({ encryptedData, iv: IV, type: 'file', ttlSeconds: 3600, consumeVerifier: CONSUME_VERIFIER });

    assert.deepEqual(result, { id: ID, expiresAt: new Date('2026-09-23T00:00:00.000Z') });
    const [request] = requests;
    assert.ok(request);
    assert.equal(request.input, 'https://api.test/api/payload');
    assert.equal(request.init.method, 'POST');
    assert.equal(request.init.body, encryptedData);
    assert.deepEqual(request.init.headers, {
      'Content-Type': 'application/octet-stream',
      'X-CipherDrop-IV': base64UrlEncode(IV),
      'X-CipherDrop-Type': 'file',
      'X-CipherDrop-TTL': '3600',
      'X-CipherDrop-Consume-Verifier': CONSUME_VERIFIER,
    });
  });

  it('getMeta は GET …/meta、consume は POST …/consume(consumeSecret ヘッダーのみ、本文なし)', async () => {
    const { client, requests } = fakeFetch((request) =>
      request.input.endsWith('/meta')
        ? json({ type: 'text', size: 21, expiresAt: '2026-09-23T00:00:00.000Z' })
        : new Response(new Uint8Array([9, 8, 7]), { status: 200, headers: { 'X-CipherDrop-IV': base64UrlEncode(IV) } }),
    );

    assert.deepEqual(await client.getMeta(ID), { type: 'text', size: 21, expiresAt: new Date('2026-09-23T00:00:00.000Z') });
    const consumed = await client.consume(ID, CONSUME_SECRET);
    assert.deepEqual(new Uint8Array(consumed.encryptedData), Uint8Array.from([9, 8, 7]));
    assert.deepEqual(consumed.iv, IV);

    assert.deepEqual(requests.map((r) => `${r.init.method} ${r.input}`), [`GET https://api.test/api/payload/${ID}/meta`, `POST https://api.test/api/payload/${ID}/consume`]);
    assert.equal(requests[1]?.init.body, undefined);
    assert.deepEqual(requests[1]?.init.headers, { 'X-CipherDrop-Consume-Secret': CONSUME_SECRET });
  });

  it('すべてのリクエストで、Cookie・Referer・キャッシュ・リダイレクトを使わない', async () => {
    const { client, requests } = fakeFetch(() => json({ type: 'text', size: 1, expiresAt: '2026-09-23T00:00:00.000Z' }));
    await client.getMeta(ID);
    assert.equal(requests[0]?.init.cache, 'no-store');
    assert.equal(requests[0]?.init.credentials, 'omit');
    assert.equal(requests[0]?.init.referrerPolicy, 'no-referrer');
    assert.equal(requests[0]?.init.redirect, 'error');
  });
});

describe('createApiClient: 鍵が URL に入り込まない', () => {
  it('形式の正しくない ID（# ? / . を含む・長さ違い）は、リクエストを作る前に拒否する', async () => {
    const { client, requests } = fakeFetch(() => json({}));
    const bad = [`${ID}#KEY`, `${ID}?key=KEY`, `${ID}/../x`, '../etc/passwd', ID.slice(1), `${ID}x`, '', 'a b', `${ID.slice(0, 21)}%`];
    for (const id of bad) {
      assert.equal((await errorOf(client.getMeta(id))).code, 'not_found', id);
      assert.equal((await errorOf(client.consume(id, CONSUME_SECRET))).code, 'not_found', id);
    }
    assert.equal(requests.length, 0, 'fetch は一度も呼ばれない');
  });
});

describe('createApiClient: エラーの分類', () => {
  const statuses: Array<[number, ApiErrorCode]> = [
    [404, 'not_found'],
    [413, 'payload_too_large'],
    [503, 'storage_full'],
    [500, 'server'],
    [400, 'server'],
    [429, 'server'],
  ];
  for (const [status, code] of statuses) {
    it(`HTTP ${status} → ${code}`, async () => {
      const { client } = fakeFetch(() => json({ error: 'x' }, status));
      const error = await errorOf(client.getMeta(ID));
      assert.equal(error.code, code);
      assert.equal(error.status, status);
    });
  }

  it('接続できない（fetch が reject）は network。メッセージは固定で、URL・ID を含まない', async () => {
    const client = createApiClient(async () => {
      throw new TypeError(`fetch failed for /api/payload/${ID}`);
    });
    const error = await errorOf(client.consume(ID, CONSUME_SECRET));
    assert.equal(error.code, 'network');
    assert.equal(error.message.includes(ID), false);
    assert.equal(error.message.includes('/api'), false);
  });

  it('consume の本文の読み取りが途中で失敗したら network', async () => {
    const broken = new Response(new ReadableStream({ start: (controller) => controller.error(new Error('reset')) }), {
      status: 200,
      headers: { 'X-CipherDrop-IV': base64UrlEncode(IV) },
    });
    const { client } = fakeFetch(() => broken);
    assert.equal((await errorOf(client.consume(ID, CONSUME_SECRET))).code, 'network');
  });
});

describe('createApiClient: サーバーの応答は信頼せず検証する', () => {
  const badCreate: unknown[] = [null, [], 'text', {}, { id: ID }, { expiresAt: '2026-09-23T00:00:00.000Z' }, { id: 'short', expiresAt: '2026-09-23T00:00:00.000Z' }, { id: `${ID}#x`, expiresAt: '2026-09-23T00:00:00.000Z' }, { id: ID, expiresAt: 'not a date' }, { id: ID, expiresAt: 123 }];
  for (const [index, body] of badCreate.entries()) {
    it(`作成の応答が不正（${index}）: ${JSON.stringify(body)} → invalid_response`, async () => {
      const { client } = fakeFetch(() => json(body, 201));
      const error = await errorOf(
        client.createPayload({ encryptedData: new ArrayBuffer(20), iv: IV, type: 'text', ttlSeconds: 3600, consumeVerifier: CONSUME_VERIFIER }),
      );
      assert.equal(error.code, 'invalid_response');
    });
  }

  const goodDate = '2026-09-23T00:00:00.000Z';
  const badMeta: unknown[] = [
    null,
    [],
    {},
    { type: 'image', size: 1, expiresAt: goodDate },
    { type: 'text', size: -1, expiresAt: goodDate },
    { type: 'text', size: 1.5, expiresAt: goodDate },
    { type: 'text', size: '10', expiresAt: goodDate },
    { type: 'text', size: 1e30, expiresAt: goodDate },
    { type: 'text', size: 1, expiresAt: 'x' },
    { type: 'text', size: 1 },
  ];
  for (const [index, body] of badMeta.entries()) {
    it(`meta の応答が不正（${index}）: ${JSON.stringify(body)} → invalid_response`, async () => {
      const { client } = fakeFetch(() => json(body));
      assert.equal((await errorOf(client.getMeta(ID))).code, 'invalid_response');
    });
  }

  it('meta の本文が JSON でなければ invalid_response', async () => {
    const { client } = fakeFetch(() => new Response('<html>oops</html>', { status: 200 }));
    assert.equal((await errorOf(client.getMeta(ID))).code, 'invalid_response');
  });

  it('consume の IV ヘッダーが無い・不正・12 バイトでない場合は invalid_response', async () => {
    const wrongLength = base64UrlEncode(new Uint8Array(11));
    for (const iv of [null, '', '@@@@', 'AAAA+/AAAAAAAAA=', wrongLength]) {
      const headers = iv === null ? {} : { 'X-CipherDrop-IV': iv };
      const { client } = fakeFetch(() => new Response(new Uint8Array(20), { status: 200, headers }));
      assert.equal((await errorOf(client.consume(ID, CONSUME_SECRET))).code, 'invalid_response', String(iv));
    }
  });
});

describe('createApiClient: 鍵確認値（keyCheck、任意）', () => {
  it('createPayload: keyCheck を渡すと X-CipherDrop-Key-Check ヘッダーで送る。渡さなければヘッダー自体を付けない', async () => {
    const { client, requests } = fakeFetch(() => json({ id: ID, expiresAt: '2026-09-23T00:00:00.000Z' }, 201));
    const encryptedData = new ArrayBuffer(4);

    await client.createPayload({ encryptedData, iv: IV, type: 'text', ttlSeconds: 3600, keyCheck: 'deadbeef', consumeVerifier: CONSUME_VERIFIER });
    assert.deepEqual(requests[0]?.init.headers, {
      'Content-Type': 'application/octet-stream',
      'X-CipherDrop-IV': base64UrlEncode(IV),
      'X-CipherDrop-Type': 'text',
      'X-CipherDrop-TTL': '3600',
      'X-CipherDrop-Consume-Verifier': CONSUME_VERIFIER,
      'X-CipherDrop-Key-Check': 'deadbeef',
    });

    await client.createPayload({ encryptedData, iv: IV, type: 'text', ttlSeconds: 3600, consumeVerifier: CONSUME_VERIFIER });
    assert.equal('X-CipherDrop-Key-Check' in (requests[1]?.init.headers as Record<string, string>), false, 'keyCheck を渡さなければヘッダー自体が無い');
  });

  it('getMeta: レスポンスに keyCheck があれば結果に含める。無ければ結果にキー自体を含めない', async () => {
    const { client } = fakeFetch(() => json({ type: 'text', size: 1, expiresAt: '2026-09-23T00:00:00.000Z', keyCheck: 'deadbeef' }));
    assert.deepEqual(await client.getMeta(ID), { type: 'text', size: 1, expiresAt: new Date('2026-09-23T00:00:00.000Z'), keyCheck: 'deadbeef' });

    const { client: withoutKeyCheck } = fakeFetch(() => json({ type: 'text', size: 1, expiresAt: '2026-09-23T00:00:00.000Z' }));
    assert.deepEqual(await withoutKeyCheck.getMeta(ID), { type: 'text', size: 1, expiresAt: new Date('2026-09-23T00:00:00.000Z') });
  });

  it('getMeta: keyCheck の形式が不正（大文字・非16進・長さ違い・非文字列）なら invalid_response', async () => {
    for (const bad of ['DEADBEEF', 'nothexch', 'short', 'deadbeefff', 123, null, '']) {
      const { client } = fakeFetch(() => json({ type: 'text', size: 1, expiresAt: '2026-09-23T00:00:00.000Z', keyCheck: bad }));
      assert.equal((await errorOf(client.getMeta(ID))).code, 'invalid_response', JSON.stringify(bad));
    }
  });
});

describe('createApiClient: 消費用秘密鍵(consumeVerifier / consumeSecret、必須。keyCheck と違い省略できない)', () => {
  it('createPayload: consumeVerifier を X-CipherDrop-Consume-Verifier ヘッダーで必ず送る', async () => {
    const { client, requests } = fakeFetch(() => json({ id: ID, expiresAt: '2026-09-23T00:00:00.000Z' }, 201));
    await client.createPayload({ encryptedData: new ArrayBuffer(4), iv: IV, type: 'text', ttlSeconds: 3600, consumeVerifier: CONSUME_VERIFIER });
    assert.equal((requests[0]?.init.headers as Record<string, string>)['X-CipherDrop-Consume-Verifier'], CONSUME_VERIFIER);
  });

  it('consume: consumeSecret を X-CipherDrop-Consume-Secret ヘッダーで必ず送る', async () => {
    const { client, requests } = fakeFetch(() => new Response(new Uint8Array([1]), { status: 200, headers: { 'X-CipherDrop-IV': base64UrlEncode(IV) } }));
    await client.consume(ID, CONSUME_SECRET);
    assert.deepEqual(requests[0]?.init.headers, { 'X-CipherDrop-Consume-Secret': CONSUME_SECRET });
  });
});
