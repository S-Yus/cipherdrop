import assert from 'node:assert/strict';
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

function payload(size = 32, fill = 7, type: PayloadType = 'text') {
  return { ciphertext: new Uint8Array(size).fill(fill), iv: new Uint8Array(12).fill(9), type };
}

describe('InMemoryPayloadStore', () => {
  it('put した内容を take で取得でき、取得した時点でストアから消えている（2 回目は null）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    const original = payload(48);
    await store.put('id-1', original, 3600);
    assert.equal(store.size, 1);
    assert.equal(store.totalBytes, 48 + 12);

    const first = await store.take('id-1');
    assert.deepEqual(first?.ciphertext, original.ciphertext);
    assert.deepEqual(first?.iv, original.iv);
    assert.equal(first?.type, 'text');
    assert.equal(store.size, 0, '取得後は 0 件');
    assert.equal(store.totalBytes, 0);

    assert.equal(await store.take('id-1'), null);
  });

  it('存在しない ID は null', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    assert.equal(await store.take('missing'), null);
  });

  it('同時に take しても成功するのは 1 回だけ', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('race', payload(), 3600);

    const results = await Promise.all(Array.from({ length: 200 }, () => store.take('race')));
    assert.equal(results.filter((r) => r !== null).length, 1);
  });

  it('有効期限: expiresAt の 1ms 前までは取得でき、expiresAt に達したら取得できない', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    const a = await store.put('a', payload(), 60);
    await store.put('b', payload(), 60);
    assert.equal(a.expiresAt, T0 + 60_000);

    clock.advance(59_999);
    assert.notEqual(await store.take('a'), null);
    clock.advance(1);
    assert.equal(await store.take('b'), null);
  });

  it('期限切れのエントリは take されたときにも削除される', async () => {
    const clock = createClock();
    const store = new InMemoryPayloadStore({ now: clock.now, sweepIntervalMs: 0 });
    await store.put('old', payload(), 60);
    clock.advance(61_000);

    assert.equal(await store.take('old'), null);
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
    assert.notEqual(await store.take('long'), null);
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
    await store.take('b');
    await store.put('c', payload(50), 60);
  });

  it('同じ ID への put は上書きせず失敗する（元の内容は無傷）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('dup', payload(16, 1), 3600);
    await assert.rejects(store.put('dup', payload(16, 2), 3600), /collision/);

    const stored = await store.take('dup');
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
    assert.equal(await store.take('x'), null);
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

    const taken = await store.take('id');
    assert.deepEqual(taken?.ciphertext, original.ciphertext, '暗号文は無傷');
    assert.equal(taken?.type, 'file');
    assert.equal(await store.take('id'), null);
  });

  it('stat と take が同時に走っても、take が成功するのは 1 回だけ', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('race', payload(), 3600);

    const operations = Array.from({ length: 100 }, (_, i) => (i % 2 === 0 ? store.stat('race') : store.take('race')));
    const results = await Promise.all(operations);
    const takes = results.filter((_, i) => i % 2 === 1);
    assert.equal(takes.filter((r) => r !== null).length, 1);
  });

  it('取得済み・存在しない ID は null（区別しない）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('gone', payload(), 3600);
    await store.take('gone');

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
    assert.equal((await store.take('id'))?.keyCheck, 'deadbeef');
  });

  it('含めなければ、stat の戻り値に "keyCheck" キー自体が現れない（type/size/expiresAt の 3 つだけ）', async () => {
    const store = new InMemoryPayloadStore({ sweepIntervalMs: 0 });
    await store.put('id', payload(), 3600);

    const meta = await store.stat('id');
    assert.deepEqual(Object.keys(meta ?? {}).sort(), ['expiresAt', 'size', 'type']);
    assert.equal(meta?.keyCheck, undefined);
  });
});
