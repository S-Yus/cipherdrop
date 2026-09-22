import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { mountApp } from './app.ts';
import { SAMPLE_ID, click, createTestEnv, has, query, typeInto, waitFor } from './testing/env.ts';
import type { TestEnvOptions } from './testing/env.ts';

function open(options: TestEnvOptions = {}) {
  const t = createTestEnv(options);
  const app = mountApp(t.env);
  return { ...t, app };
}

describe('mountApp: 画面の振り分け', () => {
  it('/ は送信画面（タイトルは CipherDrop）', () => {
    const t = open({ url: 'https://cipherdrop.io/' });
    assert.equal(query(t.main, 'h1').textContent, '新規共有');
    assert.equal(t.doc.title, 'CipherDrop');
    assert.equal(t.calls.length, 0);
  });

  it('/v/{id}#key.consumeSecret は受取画面（読み込み時に meta を呼ぶ）', () => {
    const t = open({ url: `https://cipherdrop.io/v/${SAMPLE_ID}#${'A'.repeat(43)}.${'A'.repeat(43)}` });
    assert.equal(t.doc.title, '受信データ — CipherDrop');
    assert.deepEqual(t.calls.map((call) => call.method), ['getMeta']);
  });

  it('存在しないパスは 404 画面。API は呼ばない', () => {
    const t = open({ url: 'https://cipherdrop.io/no/such/page' });
    assert.equal(query(t.main, 'h1').textContent, 'ページが見つかりません');
    assert.match(t.doc.title, /ページが見つかりません/);
    assert.equal(t.calls.length, 0);
  });

  it('画面を破棄すると DOM は空になる', () => {
    const t = open();
    t.app.destroy();
    assert.equal(t.root.childNodes.length, 0);
  });
});

describe('mountApp: ヘッダーと構造', () => {
  it('ヘッダーはワードマーク（CipherDrop）だけ。送信画面には「新規共有」リンクを置かない', () => {
    const t = open({ url: 'https://cipherdrop.io/' });
    assert.equal(query(t.doc, 'header a[href="/"]').textContent, 'CipherDrop');
    assert.equal(t.doc.querySelectorAll('header a').length, 1);
    assert.equal(t.doc.querySelectorAll('header button').length, 0, 'テーマ切替などのボタンは置かない');
  });

  it('受取・404 画面のヘッダーには、新しい共有を始める「新規共有」リンクが 1 つだけある', () => {
    for (const url of [`https://cipherdrop.io/v/${SAMPLE_ID}#${'A'.repeat(43)}.${'A'.repeat(43)}`, 'https://cipherdrop.io/nope']) {
      const t = open({ url });
      const links = [...t.doc.querySelectorAll('header a')].map((a) => `${a.textContent}→${a.getAttribute('href')}`);
      assert.deepEqual(links, ['CipherDrop→/', '新規共有→/'], url);
    }
  });

  it('本文（main#main）と、本文へのスキップリンクがある。フッターは置かない', () => {
    const t = open();
    assert.ok(has(t.doc, 'main#main'));
    assert.equal(query(t.doc, 'a[href="#main"]').textContent, '本文へスキップ');
    assert.equal(t.doc.querySelectorAll('footer').length, 0);
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

describe('mountApp: ダーク固定・ブラウザに何も保存しない', () => {
  it('テーマ切替・ライトモードの仕組みを持たない（data-theme を設定しない）', () => {
    const t = open();
    assert.equal(t.doc.documentElement.dataset['theme'], undefined);
    assert.equal(has(t.doc, '[data-action="toggle-theme"]'), false);
  });

  it('送信の一連の操作（入力 → リンク生成 → コピー）で、localStorage・sessionStorage・Cookie に何も書かれない', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '保存されてはいけない本文');
    click(query(t.main, '[data-action="submit"]'));
    await waitFor(() => has(t.main, '[data-testid="share-link"]'));
    click(query(t.main, '[data-action="copy"]'));
    await waitFor(() => t.clipboardWrites.length === 1);

    assert.equal(t.window.localStorage.length, 0);
    assert.equal(t.window.sessionStorage.length, 0);
    assert.equal(t.window.document.cookie, '');
  });
});
