import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { JSDOM } from 'jsdom';
import { THEME_STORAGE_KEY, applyTheme, effectiveTheme, readStoredTheme, storeTheme } from './theme.ts';

function memoryStorage(initial: Record<string, string> = {}) {
  const map = new Map(Object.entries(initial));
  return { map, getItem: (key: string) => map.get(key) ?? null, setItem: (key: string, value: string) => void map.set(key, value) };
}

const throwingStorage = {
  getItem: () => {
    throw new Error('SecurityError');
  },
  setItem: () => {
    throw new Error('QuotaExceededError');
  },
};

describe('テーマ', () => {
  it('保存済みの light / dark だけを読み取る。それ以外・未保存・storage なしは null', () => {
    assert.equal(readStoredTheme(memoryStorage({ [THEME_STORAGE_KEY]: 'dark' })), 'dark');
    assert.equal(readStoredTheme(memoryStorage({ [THEME_STORAGE_KEY]: 'light' })), 'light');
    for (const bad of ['', 'auto', 'DARK', '<script>']) assert.equal(readStoredTheme(memoryStorage({ [THEME_STORAGE_KEY]: bad })), null);
    assert.equal(readStoredTheme(memoryStorage()), null);
    assert.equal(readStoredTheme(null), null);
  });

  it('localStorage が使えない環境（例外を投げる）でも落ちない', () => {
    assert.equal(readStoredTheme(throwingStorage), null);
    assert.doesNotThrow(() => storeTheme(throwingStorage, 'dark'));
    assert.doesNotThrow(() => storeTheme(null, 'dark'));
  });

  it('storeTheme は選択を保存する', () => {
    const storage = memoryStorage();
    storeTheme(storage, 'dark');
    assert.equal(storage.map.get(THEME_STORAGE_KEY), 'dark');
  });

  it('effectiveTheme: 明示選択（data-theme）があればそれ、なければ OS の設定', () => {
    const doc = new JSDOM('<!doctype html><html></html>').window.document;
    assert.equal(effectiveTheme(doc, () => false), 'light');
    assert.equal(effectiveTheme(doc, () => true), 'dark');

    applyTheme(doc, 'light');
    assert.equal(effectiveTheme(doc, () => true), 'light', '明示選択が OS の設定に勝つ');
    applyTheme(doc, 'dark');
    assert.equal(doc.documentElement.dataset['theme'], 'dark');
    assert.equal(effectiveTheme(doc, () => false), 'dark');
  });
});
