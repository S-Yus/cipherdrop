import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeAddress, RateLimiter } from './ratelimit.ts';

describe('RateLimiter', () => {
  it('容量まで受け付け、以後は回復した分だけ受け付ける', () => {
    let now = 0;
    const limiter = new RateLimiter({ capacity: 2, refillPerSecond: 0.5, now: () => now });
    assert.equal(limiter.take('a').allowed, true);
    assert.equal(limiter.take('a').allowed, true);
    assert.deepEqual(limiter.take('a'), { allowed: false, retryAfterSeconds: 2 });

    now += 1000;
    assert.deepEqual(limiter.take('a'), { allowed: false, retryAfterSeconds: 1 });
    now += 1000;
    assert.equal(limiter.take('a').allowed, true);
    assert.equal(limiter.take('a').allowed, false);
  });

  it('拒否したリクエストはトークンを消費しない。回復は容量を超えない', () => {
    let now = 0;
    const limiter = new RateLimiter({ capacity: 1, refillPerSecond: 1, now: () => now });
    limiter.take('a');
    for (let i = 0; i < 10; i++) limiter.take('a');
    now += 1000;
    assert.equal(limiter.take('a').allowed, true);

    now += 60_000;
    assert.equal(limiter.take('a').allowed, true);
    assert.equal(limiter.take('a').allowed, false);
  });

  it('キーごとに独立して数える', () => {
    const limiter = new RateLimiter({ capacity: 1, refillPerSecond: 1, now: () => 0 });
    assert.equal(limiter.take('a').allowed, true);
    assert.equal(limiter.take('b').allowed, true);
    assert.equal(limiter.take('a').allowed, false);
  });

  it('キー数の上限を超えたら、最も長く使われていないキーを捨てる（メモリを使い切らない）', () => {
    const limiter = new RateLimiter({ capacity: 1, refillPerSecond: 0.001, maxKeys: 2, now: () => 0 });
    limiter.take('a');
    limiter.take('b');
    limiter.take('a'); // a を最近使ったことにする
    limiter.take('c'); // b が捨てられる
    assert.equal(limiter.size, 2);
    assert.equal(limiter.take('a').allowed, false); // a は残っている
    assert.equal(limiter.take('b').allowed, true); // b は捨てられていたので新しいバケット
  });

  it('不正な設定は拒否する', () => {
    assert.throws(() => new RateLimiter({ capacity: 0, refillPerSecond: 1 }), RangeError);
    assert.throws(() => new RateLimiter({ capacity: 1, refillPerSecond: 0 }), RangeError);
  });
});

describe('normalizeAddress', () => {
  const cases: Array<[string, string]> = [
    ['203.0.113.7', '203.0.113.7'],
    ['::ffff:203.0.113.7', '203.0.113.7'],
    ['2001:db8:1:2::1', '2001:db8:1:2::/64'],
    ['2001:0db8:0001:0002:ffff:0:0:9', '2001:db8:1:2::/64'],
    ['2001:DB8::1', '2001:db8:0:0::/64'],
    ['::1', '0:0:0:0::/64'],
    ['fe80::', 'fe80:0:0:0::/64'],
  ];
  for (const [input, expected] of cases) {
    it(`${input} → ${expected}`, () => assert.equal(normalizeAddress(input), expected));
  }
});
