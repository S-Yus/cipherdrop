import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { formatBytes, formatDateTime, formatRemaining } from './format.ts';

describe('formatBytes（1024 換算）', () => {
  const cases: Array<[number, string]> = [
    [0, '0 B'],
    [1, '1 B'],
    [1023, '1023 B'],
    [1024, '1 KB'],
    [1536, '1.5 KB'],
    [10 * 1024, '10 KB'],
    [1024 * 1024, '1 MB'],
    [10 * 1024 * 1024, '10 MB'],
    [10 * 1024 * 1024 - 4096, '10 MB'], // 送信上限（画面の「最大 10 MB」）
    [123 * 1024 * 1024, '123 MB'],
    [5 * 1024 ** 3, '5 GB'],
    [5000 * 1024 ** 3, '5000 GB'],
  ];
  for (const [bytes, expected] of cases) {
    it(`${bytes} → ${expected}`, () => assert.equal(formatBytes(bytes), expected));
  }

  it('不正な値（負数・NaN・Infinity）は「—」', () => {
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) assert.equal(formatBytes(bad), '—');
  });
});

describe('formatRemaining', () => {
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  const cases: Array<[number, string]> = [
    [0, '期限切れ'],
    [-5000, '期限切れ'],
    [59_999, '1分未満'],
    [minute, '1分'],
    [45 * minute, '45分'],
    [hour, '1時間'],
    [hour + 30 * minute, '1時間 30分'],
    [23 * hour + 59 * minute, '23時間 59分'],
    [day, '1日'],
    [6 * day + 23 * hour, '6日 23時間'],
    [7 * day, '7日'],
  ];
  for (const [ms, expected] of cases) {
    it(`${ms}ms → ${expected}`, () => assert.equal(formatRemaining(ms), expected));
  }
});

describe('formatDateTime', () => {
  it('指定したタイムゾーンで「YYYY/MM/DD HH:mm」に整形する', () => {
    const date = new Date(Date.UTC(2026, 8, 22, 13, 5));
    assert.equal(formatDateTime(date, 'UTC'), '2026/09/22 13:05');
    assert.equal(formatDateTime(date, 'Asia/Tokyo'), '2026/09/22 22:05');
  });
});
