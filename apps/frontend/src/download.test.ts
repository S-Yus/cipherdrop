import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { JSDOM } from 'jsdom';
import { saveFile } from './download.ts';
import type { DownloadEnv } from './download.ts';

function setup(options: { objectUrl?: string } = {}) {
  const { window } = new JSDOM('<!doctype html><html><body></body></html>');
  const anchors: Array<{ href: string; download: string; hidden: boolean; rel: string; attached: boolean }> = [];
  // jsdom の a.click() は「未実装のナビゲーション」を出すので、クリックを記録するだけの実装に差し替える
  window.HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
    anchors.push({ href: this.href, download: this.download, hidden: this.hidden === true, rel: this.rel, attached: this.isConnected });
  };

  const blobs: Blob[] = [];
  const revoked: string[] = [];
  const scheduled: Array<{ handler: () => void; ms: number }> = [];
  const env: DownloadEnv = {
    doc: window.document,
    createObjectURL(blob) {
      blobs.push(blob);
      return options.objectUrl ?? `blob:https://cipherdrop.io/${blobs.length}`;
    },
    revokeObjectURL: (url) => void revoked.push(url),
    setTimeout(handler, ms) {
      scheduled.push({ handler, ms });
      return scheduled.length;
    },
  };
  return { window, env, anchors, blobs, revoked, scheduled };
}

describe('saveFile', () => {
  it('無害化した名前で、非表示のリンクをクリックしてダウンロードし、終わったらリンクを取り除く', () => {
    const { window, env, anchors, revoked } = setup();
    saveFile(env, '../../evil\u202Efdp.exe', new Uint8Array([1, 2, 3]).buffer);

    assert.equal(anchors.length, 1);
    const [anchor] = anchors;
    assert.ok(anchor);
    assert.equal(anchor.download, '_.._evilfdp.exe', '名前は無害化される');
    assert.equal(anchor.hidden, true);
    assert.equal(anchor.attached, true, 'クリック時は文書に接続されている');
    assert.match(anchor.rel, /noopener/);
    assert.equal(anchor.href, 'blob:https://cipherdrop.io/1');
    assert.equal(window.document.body.children.length, 0, 'クリック後にリンクは取り除かれる');
    assert.deepEqual(revoked, [], 'オブジェクト URL はまだ解放しない（ダウンロード開始を待つ）');
  });

  it('Blob の種別は常に application/octet-stream で、中身は元のバイト列（名前や送信者の申告で変わらない）', async () => {
    const { env, blobs } = setup();
    for (const name of ['page.html', 'image.svg', 'script.js', 'x.pdf']) saveFile(env, name, new Uint8Array([7, 7]).buffer);

    assert.equal(blobs.length, 4);
    for (const blob of blobs) {
      assert.equal(blob.type, 'application/octet-stream');
      assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), Uint8Array.from([7, 7]));
    }
  });

  it('オブジェクト URL は 30 秒後に解放する', () => {
    const { env, revoked, scheduled } = setup();
    saveFile(env, 'a.txt', new ArrayBuffer(1));

    assert.equal(scheduled.length, 1);
    assert.equal(scheduled[0]?.ms, 30_000);
    scheduled[0]?.handler();
    assert.deepEqual(revoked, ['blob:https://cipherdrop.io/1']);
  });

  it('blob: 以外の URL が返ってきたら、ダウンロードせずに即解放して失敗する', () => {
    const { env, anchors, revoked } = setup({ objectUrl: 'https://evil.example/x' });
    assert.throws(() => saveFile(env, 'a.txt', new ArrayBuffer(1)), /unexpected object URL/);
    assert.equal(anchors.length, 0);
    assert.deepEqual(revoked, ['https://evil.example/x']);
  });

  it('空の名前でも既定の名前で保存できる', () => {
    const { env, anchors } = setup();
    saveFile(env, '', new ArrayBuffer(1));
    assert.equal(anchors[0]?.download, 'cipherdrop-file');
  });
});
