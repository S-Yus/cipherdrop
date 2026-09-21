import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mountApp } from './app.ts';
import { SAMPLE_ID, click, createTestEnv, has, query } from './testing/env.ts';
import type { TestEnvOptions } from './testing/env.ts';
import { THEME_STORAGE_KEY } from './theme.ts';

function open(options: TestEnvOptions = {}) {
  const t = createTestEnv(options);
  const app = mountApp(t.env);
  return { ...t, app };
}

const themeToggle = (t: { doc: Document }) => query<HTMLButtonElement>(t.doc, '[data-action="toggle-theme"]');

describe('mountApp: 画面の振り分け', () => {
  it('/ は送信画面', () => {
    const t = open({ url: 'https://cipherdrop.io/' });
    assert.match(t.main.textContent ?? '', /大切な情報を、一度だけ、安全に。/);
    assert.match(t.doc.title, /一度だけ開ける、安全な共有/);
    assert.equal(t.calls.length, 0);
  });

  it('/v/{id}#key は受取画面（読み込み時に meta を呼ぶ）', () => {
    const t = open({ url: `https://cipherdrop.io/v/${SAMPLE_ID}#${'A'.repeat(43)}` });
    assert.match(t.doc.title, /共有データを受け取る/);
    assert.deepEqual(t.calls.map((call) => call.method), ['getMeta']);
  });

  it('存在しないパスは 404 画面で、トップへ戻るリンクがある。API は呼ばない', () => {
    const t = open({ url: 'https://cipherdrop.io/no/such/page' });
    assert.match(t.main.textContent ?? '', /ページが見つかりません/);
    assert.match(t.doc.title, /ページが見つかりません/);
    assert.equal(query(t.main, 'a').getAttribute('href'), '/');
    assert.equal(t.calls.length, 0);
  });

  it('画面を破棄すると DOM は空になる', () => {
    const t = open();
    t.app.destroy();
    assert.equal(t.root.childNodes.length, 0);
  });
});

describe('mountApp: レイアウトとアクセシビリティ', () => {
  it('ヘッダー（ロゴ・テーマ切替）・本文（#main）・フッターと、本文へのスキップリンクがある', () => {
    const t = open();
    assert.ok(has(t.doc, 'header a[href="/"]'));
    assert.ok(has(t.doc, 'main#main'));
    assert.ok(has(t.doc, 'footer'));
    assert.equal(query(t.doc, 'a[href="#main"]').textContent, '本文へスキップ');
    assert.match(query(t.doc, 'footer').textContent ?? '', /サーバーは内容も鍵も保持しません/);
  });

  it('すべてのリンクは、同一オリジンのパスかページ内リンクだけ（外部への遷移がない）', () => {
    for (const url of ['https://cipherdrop.io/', `https://cipherdrop.io/v/${SAMPLE_ID}`, 'https://cipherdrop.io/nope']) {
      const t = open({ url });
      for (const anchor of t.doc.querySelectorAll('a')) {
        assert.match(anchor.getAttribute('href') ?? '', /^(\/(?!\/)|#)/, `${url}: ${anchor.outerHTML}`);
      }
    }
  });

  it('外部リソースを読み込む要素（img / script / iframe / link / form）を一切持たない', () => {
    const t = open();
    assert.equal(t.doc.querySelectorAll('img, script, iframe, object, embed, link, form[action]').length, 0);
  });

  it('装飾のアイコンは支援技術に読み上げさせない（aria-hidden）', () => {
    const t = open();
    const icons = [...t.doc.querySelectorAll('svg')];
    assert.ok(icons.length > 0);
    assert.ok(icons.every((icon) => icon.getAttribute('aria-hidden') === 'true'));
  });
});

describe('mountApp: テーマ切替', () => {
  it('OS がライトなら「ダークモードに切り替える」。押すとダークになり、選択が保存され、ボタンとフォーカスが更新される', () => {
    const t = open({ prefersDark: false });
    assert.equal(themeToggle(t).getAttribute('aria-label'), 'ダークモードに切り替える');
    assert.equal(t.doc.documentElement.dataset['theme'], undefined, '未選択の間は OS の設定に従う（CSS）');

    click(themeToggle(t));
    assert.equal(t.doc.documentElement.dataset['theme'], 'dark');
    assert.equal(t.storageMap.get(THEME_STORAGE_KEY), 'dark');
    assert.equal(themeToggle(t).getAttribute('aria-label'), 'ライトモードに切り替える');
    assert.equal(t.doc.activeElement, themeToggle(t), '切替後もボタンにフォーカスが残る');

    click(themeToggle(t));
    assert.equal(t.doc.documentElement.dataset['theme'], 'light');
    assert.equal(t.storageMap.get(THEME_STORAGE_KEY), 'light');
  });

  it('OS がダークなら最初から「ライトモードに切り替える」。押すとライトになる', () => {
    const t = open({ prefersDark: true });
    assert.equal(themeToggle(t).getAttribute('aria-label'), 'ライトモードに切り替える');
    click(themeToggle(t));
    assert.equal(t.doc.documentElement.dataset['theme'], 'light');
  });

  it('localStorage が使えない環境でも切り替えられる（保存だけ諦める）', () => {
    const t = open({ noStorage: true });
    assert.doesNotThrow(() => click(themeToggle(t)));
    assert.equal(t.doc.documentElement.dataset['theme'], 'dark');
  });
});
