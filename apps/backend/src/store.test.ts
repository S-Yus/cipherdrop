import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { InMemoryPayloadStore, StoreFullError } from './store.ts';
import type { PayloadType } from './store.ts';

const T0 = 1_700_000_000_000;

function createClock() {
  let now = T0;
  return {
    now: () => now,
    advance(ms: number) {
      now += ms;
    },
  };
}

/** consumeSecret（32 バイト）から consumeVerifier（SHA-256、32 バイトの生ダイジェスト）を導出する。 */
function verifierOf(secret: Uint8Array): Uint8Array {
  return createHash('sha256').update(secret).digest();
}

/** テスト全体で使い回す既定の consumeSecret と、それとは一致しない別の秘密鍵。 */
const DEFAULT_CONSUME_SECRET = new Uint8Array(32).fill(1);
const WRONG_CONSUME_SECRET = new Uint8Array(32).fill(2);
/** 長さそのものが違う秘密鍵（timingSafeEqual の長さ不一致例外を踏まないことの確認用）。 */
const SHORT_CONSUME_SECRET = new Uint8Array(16).fill(1);

function payload(size = 32, fill = 7, type: PayloadType = 'text', consumeSecret: Uint8Array = DEFAULT_CONSUME_SECRET) {
  return { ciphertext: new Uint8Array(size).fill(fill), iv: new Uint8Array(12).fill(9), type, consumeVerifier: verifierOf(consumeSecret) };
}

describe('InMemoryPayloadStore', () => {
  it('put した内容を take で取得でき、取得した時点でストアから消えている（2 回目は null）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    const original = payload(48);
    await store.put('id-1', original, 3600);
    assert.equal(store.size, 1);
    assert.equal(store.totalBytes, 48 + 12);

    const first = await store.take('id-1', DEFAULT_CONSUME_SECRET);
    assert.deepEqual(first?.ciphertext, original.ciphertext);
    assert.deepEqual(first?.iv, original.iv);
    assert.equal(first?.type, 'text');
    assert.equal(store.size, 0, '取得後は 0 件');
    assert.equal(store.totalBytes, 0);

    assert.equal(await store.take('id-1', DEFAULT_CONSUME_SECRET), null);
  });

  it('存在しない ID は null', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    assert.equal(await store.take('missing', DEFAULT_CONSUME_SECRET), null);
  });

  it('同時に take しても成功するのは 1 回だけ', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('race', payload(), 3600);

    const results = await Promise.all(Array.from({ length: 200 }, () => store.take('race', DEFAULT_CONSUME_SECRET)));
    assert.equal(results.filter((r) => r !== null).length, 1);
  });

  it('有効期限: expiresAt の 1ms 前までは取得でき、expiresAt に達したら取得できない', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    const a = await store.put('a', payload(), 60);
    await store.put('b', payload(), 60);
    assert.equal(a.expiresAt, T0 + 60_000);

    clock.advance(59_999);
    assert.notEqual(await store.take('a', DEFAULT_CONSUME_SECRET), null);
    clock.advance(1);
    assert.equal(await store.take('b', DEFAULT_CONSUME_SECRET), null);
  });

  it('期限切れのエントリは take されたときにも削除される', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('old', payload(), 60);
    clock.advance(61_000);

    assert.equal(await store.take('old', DEFAULT_CONSUME_SECRET), null);
    assert.equal(store.size, 0);
    assert.equal(store.totalBytes, 0);
  });

  it('purgeExpired は期限切れだけを削除し、件数と容量を更新する', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('short-1', payload(10), 60);
    await store.put('short-2', payload(10), 60);
    await store.put('long', payload(10), 3600);

    clock.advance(120_000);
    assert.equal(store.purgeExpired(), 2);
    assert.equal(store.size, 1);
    assert.equal(store.totalBytes, 10 + 12);
    assert.notEqual(await store.take('long', DEFAULT_CONSUME_SECRET), null);
  });

  it('容量上限を超える保存は StoreFullError。take すると空きが戻り、期限切れは回収してから判定する', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, maxTotalBytes: 100, sweepIntervalMs: 0 });

    await store.put('a', payload(50), 60); // 62 バイト
    await assert.rejects(store.put('b', payload(50), 60), StoreFullError);
    assert.equal(store.size, 1, '失敗した保存は残らない');

    clock.advance(61_000); // a が期限切れ → 回収されて b が入る
    await store.put('b', payload(50), 3600);
    assert.equal(store.size, 1);

    await assert.rejects(store.put('c', payload(50), 60), StoreFullError);
    await store.take('b', DEFAULT_CONSUME_SECRET);
    await store.put('c', payload(50), 60);
  });

  it('同じ ID への put は上書きせず失敗する（元の内容は無傷）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('dup', payload(16, 1), 3600);
    await assert.rejects(store.put('dup', payload(16, 2), 3600), /collision/);

    const stored = await store.take('dup', DEFAULT_CONSUME_SECRET);
    assert.deepEqual(stored?.ciphertext, new Uint8Array(16).fill(1));
  });

  it('掃除タイマーが一定間隔で期限切れを削除する（未取得でもメモリに残さない）', async (t) => {
    t.mock.timers.enable({ apis: ['setInterval'] });
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 1000 });
    await store.put('never-read', payload(), 60);

    clock.advance(61_000);
    assert.equal(store.size, 1, '掃除が走るまでは残っている');
    t.mock.timers.tick(1000);
    assert.equal(store.size, 0);

    store.close();
  });

  it('close() で保持データをすべて破棄し、掃除タイマーも止める', async (t) => {
    t.mock.timers.enable({ apis: ['setInterval'] });
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 1000 });
    await store.put('x', payload(), 3600);

    store.close();
    assert.equal(store.size, 0);
    assert.equal(store.totalBytes, 0);
    assert.equal(await store.take('x', DEFAULT_CONSUME_SECRET), null);
    assert.equal(await store.stat('x'), null);
  });
});

describe('InMemoryPayloadStore.stat（確認用: 何も消費しない）', () => {
  it('種別・暗号文サイズ・有効期限だけを返す。暗号文と IV は戻り値に含まれない', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('text-1', payload(48, 1, 'text'), 3600);
    await store.put('file-1', payload(100, 2, 'file'), 60);

    const text = await store.stat('text-1');
    const file = await store.stat('file-1');
    assert.deepEqual(text, { type: 'text', size: 48, expiresAt: T0 + 3600_000 });
    assert.deepEqual(file, { type: 'file', size: 100, expiresAt: T0 + 60_000 });
    for (const meta of [text, file]) {
      assert.deepEqual(Object.keys(meta ?? {}).sort(), ['expiresAt', 'size', 'type']);
    }
  });

  it('何度呼んでも状態が変わらず、その後の take は 1 回だけ成功する', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    const original = payload(64, 5, 'file');
    await store.put('id', original, 3600);

    const results = await Promise.all(Array.from({ length: 100 }, () => store.stat('id')));
    assert.ok(results.every((meta) => meta?.size === 64), '100 回とも同じメタ情報');
    assert.equal(store.size, 1, 'stat では削除されない');
    assert.equal(store.totalBytes, 64 + 12);

    const taken = await store.take('id', DEFAULT_CONSUME_SECRET);
    assert.deepEqual(taken?.ciphertext, original.ciphertext, '暗号文は無傷');
    assert.equal(taken?.type, 'file');
    assert.equal(await store.take('id', DEFAULT_CONSUME_SECRET), null);
  });

  it('stat と take が同時に走っても、take が成功するのは 1 回だけ', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('race', payload(), 3600);

    const operations = Array.from({ length: 100 }, (_, i) => (i % 2 === 0 ? store.stat('race') : store.take('race', DEFAULT_CONSUME_SECRET)));
    const results = await Promise.all(operations);
    const takes = results.filter((_, i) => i % 2 === 1);
    assert.equal(takes.filter((r) => r !== null).length, 1);
  });

  it('取得済み・存在しない ID は null（区別しない）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('gone', payload(), 3600);
    await store.take('gone', DEFAULT_CONSUME_SECRET);

    assert.equal(await store.stat('gone'), null);
    assert.equal(await store.stat('never-existed'), null);
  });

  it('有効期限を延ばさず、期限切れなら null。ただし stat 自身は削除しない（副作用なし）', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('short', payload(), 60);

    clock.advance(30_000);
    assert.equal((await store.stat('short'))?.expiresAt, T0 + 60_000, '呼んでも有効期限は変わらない');
    clock.advance(30_000); // ちょうど期限
    assert.equal(await store.stat('short'), null);
    assert.equal(store.size, 1, 'stat は期限切れでも削除しない（掃除は take / purgeExpired の役目）');

    assert.equal(store.purgeExpired(), 1);
    assert.equal(store.size, 0);
  });
});

describe('InMemoryPayloadStore: 鍵確認値（keyCheck、任意）', () => {
  it('put に含めれば、stat・take のどちらの戻り値にも、そのまま現れる', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', { ...payload(), keyCheck: 'deadbeef' }, 3600);

    assert.equal((await store.stat('id'))?.keyCheck, 'deadbeef');
    assert.equal((await store.take('id', DEFAULT_CONSUME_SECRET))?.keyCheck, 'deadbeef');
  });

  it('含めなければ、stat の戻り値に "keyCheck" キー自体が現れない（type/size/expiresAt の 3 つだけ）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(), 3600);

    const meta = await store.stat('id');
    assert.deepEqual(Object.keys(meta ?? {}).sort(), ['expiresAt', 'size', 'type']);
    assert.equal(meta?.keyCheck, undefined);
  });
});

describe('InMemoryPayloadStore: consumeVerifier（消費権限の検証。ID だけでは take できないことの保証）', () => {
  it('正しい consumeSecret なら take できる（SHA-256 が一致）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(32, 7, 'text', DEFAULT_CONSUME_SECRET), 3600);

    assert.notEqual(await store.take('id', DEFAULT_CONSUME_SECRET), null);
  });

  it('誤った consumeSecret では取得できず、エントリも削除されない（正しい鍵で改めて取得できる）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(32, 7, 'text', DEFAULT_CONSUME_SECRET), 3600);

    assert.equal(await store.take('id', WRONG_CONSUME_SECRET), null, '誤った鍵では null');
    assert.equal(store.size, 1, '削除されていない（誤った鍵で破棄できてはならない）');

    const retried = await store.take('id', DEFAULT_CONSUME_SECRET);
    assert.notEqual(retried, null, '正しい鍵なら、その後もまだ取得できる');
    assert.equal(store.size, 0);
  });

  it('consumeSecret の長さが違っても例外を投げず null を返す（timingSafeEqual の長さ不一致対策）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(32, 7, 'text', DEFAULT_CONSUME_SECRET), 3600);

    await assert.doesNotReject(async () => {
      assert.equal(await store.take('id', SHORT_CONSUME_SECRET), null);
    });
    assert.equal(store.size, 1, '長さが違う鍵でも削除されない');
  });

  it('存在しない ID には、秘密鍵の正誤に関わらず null（ID だけでは「何かがある」ことすら分からない）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    assert.equal(await store.take('never-existed', WRONG_CONSUME_SECRET), null);
    assert.equal(await store.take('never-existed', DEFAULT_CONSUME_SECRET), null);
  });

  it('期限切れのエントリでも、秘密鍵の検証自体は行ってから null を返す（誤り鍵と期限切れを区別する応答時間差を減らす）', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('id', payload(32, 7, 'text', DEFAULT_CONSUME_SECRET), 60);
    clock.advance(61_000);

    // 誤った鍵・正しい鍵のどちらでも、期限切れである以上、結果は null で変わらない。
    assert.equal(await store.take('id', WRONG_CONSUME_SECRET), null);
    assert.equal(await store.take('id', DEFAULT_CONSUME_SECRET), null);
  });

  it('stat() の戻り値には consumeVerifier が一切含まれない', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(), 3600);

    const meta = await store.stat('id');
    assert.deepEqual(Object.keys(meta ?? {}).sort(), ['expiresAt', 'size', 'type']);
  });
});

describe('InMemoryPayloadStore: reserve/release（本文を読む前の容量予約）', () => {
  it('容量が足りる間は true。使い切ると false になり、release すると再び予約できる', () => {
    const store = new InMemoryPayloadStore({ maxTotalBytes: 100, sweepIntervalMs: 0 });
    assert.equal(store.reserve(60), true);
    assert.equal(store.reserve(60), false, '60+60=120 > 100 のため 2 つ目は失敗');
    store.release(60);
    assert.equal(store.reserve(60), true, '解放した分は再び予約できる');
  });

  it('reserve だけでは #totalBytes / size は変化しない（予約と確定は別カウンタ）', () => {
    const store = new InMemoryPayloadStore({ maxTotalBytes: 100, sweepIntervalMs: 0 });
    store.reserve(50);
    assert.equal(store.totalBytes, 0);
    assert.equal(store.size, 0);
  });

  it('put() は確定済みバイト数だけで判定する（他リクエストの reserve 中の分に妨げられない）', async () => {
    const store = new InMemoryPayloadStore({ maxTotalBytes: 100, sweepIntervalMs: 0 });
    assert.equal(store.reserve(90), true, '90 バイトぶん予約（まだ put していない）');

    // reserve は「本文を読む前に、どのみち入らないなら読まない」ための事前チェックにすぎない。
    // 実際にストアへの計上（#totalBytes）が増えるのは put() のときだけなので、
    // 予約中でも、確定済みバイト数だけで見て入る保存は成功する。
    await store.put('a', payload(50), 3600); // 50 + 12(iv) = 62 <= 100
    assert.equal(store.size, 1);
    assert.equal(store.totalBytes, 62);
  });

  it('件数上限（maxEntries）は reserve にも put にも及ぶ（バイト容量が十分でも件数で弾かれる）', async () => {
    const store = new InMemoryPayloadStore({ maxTotalBytes: 1024 * 1024, maxEntries: 2, sweepIntervalMs: 0 });
    await store.put('a', payload(8), 3600);
    await store.put('b', payload(8), 3600);
    await assert.rejects(store.put('c', payload(8), 3600), StoreFullError, '件数が 2 件に達しているため 3 件目は失敗');

    assert.equal(store.reserve(8), false, 'reserve も同じ件数上限を見る');
  });

  it('maxEntries に達していても、期限切れを回収すれば reserve/put は再び成功する', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, maxEntries: 1, sweepIntervalMs: 0 });
    await store.put('a', payload(8), 60);
    assert.equal(store.reserve(8), false);

    clock.advance(61_000); // a が期限切れ
    assert.equal(store.reserve(8), true, '期限切れの a を回収してから予約できる');
    store.release(8);
    await store.put('b', payload(8), 3600);
    assert.equal(store.size, 1);
  });

  it('release は reserve した回数・バイト数を超えて呼んでも 0 未満にならない（上限を無効化しない）', () => {
    const store = new InMemoryPayloadStore({ maxTotalBytes: 100, maxEntries: 1, sweepIntervalMs: 0 });
    store.release(1000); // 対応する reserve を呼んでいない状態で release しても例外にならない
    // 0 未満に振れていれば #fits の不等式が常に true になり、上限が実質無効化されてしまう。
    // その場合でも myEntries=1 の上限自体は健在であることを確認する。
    assert.equal(store.reserve(1), true);
    assert.equal(store.reserve(1), false, '件数上限 1 はクランプ後も正しく効いている');
  });
});
