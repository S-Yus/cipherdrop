/**
 * UI 経由の E2E。実バックエンド（HTTP）+ 本物の画面コード（jsdom 上）+ 本物の暗号で、
 * 送信者と受信者のブラウザ操作（入力・クリック・ドロップ）から通しで検証する。
 *
 * サーバーが受信した生の TCP バイト列を記録し、UI が鍵・平文・ファイル名をサーバーへ送っていないことも確認する。
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_MAX_TTL_SECONDS, DEFAULT_TTL_SECONDS, HEADER_IV, HEADER_TTL, HEADER_TYPE } from '../apps/backend/src/server.ts';
import { HEADER_IV as CLIENT_HEADER_IV, HEADER_TTL as CLIENT_HEADER_TTL, HEADER_TYPE as CLIENT_HEADER_TYPE, createApiClient } from '../apps/frontend/src/api.ts';
import { mountApp } from '../apps/frontend/src/app.ts';
import { DEFAULT_TTL_SECONDS as UI_DEFAULT_TTL, MAX_UPLOAD_BYTES, TTL_OPTIONS } from '../apps/frontend/src/limits.ts';
import { click, createTestEnv, dropFiles, has, makeFile, query, typeInto, waitFor } from '../apps/frontend/src/testing/env.ts';
import { RecordingStore, leakedForms, parseHttpRequests, startWorld } from './support/world.ts';

type World = Awaited<ReturnType<typeof startWorld>>;

/** ブラウザ 1 枚分: 指定 URL のページに画面を表示する。API は実サーバーへ向ける。 */
function browse(world: World, url: string) {
  const client = createApiClient((input, init) => fetch(input, init), world.origin);
  const t = createTestEnv({
    url,
    api: {
      createPayload: (input) => client.createPayload(input),
      getMeta: (id) => client.getMeta(id),
      consume: (id) => client.consume(id),
    },
  });
  mountApp(t.env);
  return t;
}

type Browser = ReturnType<typeof browse>;

const HOME = 'https://cipherdrop.io/';

async function shareText(world: World, text: string): Promise<string> {
  const sender = browse(world, HOME);
  typeInto(query<HTMLTextAreaElement>(sender.main, '#message'), text);
  click(query(sender.main, '[data-action="submit"]'));
  const block = await waitFor(() => sender.main.querySelector('[data-testid="share-link"]'));
  return block.textContent ?? '';
}

const awaitConfirm = (b: Browser) => waitFor(() => has(b.main, '[data-action="open"]'));
const clickOpen = (b: Browser) => click(query(b.main, '[data-action="open"]'));

describe('UI E2E: テキストの共有', () => {
  const secret = 'マイナンバー 123456789012 / 口座 0123-4567 / top-secret-passphrase <img src=x onerror=alert(1)>';

  it('送信 → 確認画面 → 開く → 復号表示 まで通しで動き、消費されるのは「開く」を押した時だけ', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, secret);
    assert.match(link, /^https:\/\/cipherdrop\.io\/v\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);
    assert.equal(world.store.size, 1);

    const receiver = browse(world, link);
    await awaitConfirm(receiver);
    assert.match(receiver.main.textContent ?? '', /このデータは一度開くとサーバーから永久削除されます/);
    assert.equal(world.store.takes.length, 0, '確認画面の表示では消費されない');
    assert.equal(world.store.size, 1);

    clickOpen(receiver);
    const output = await waitFor(() => receiver.main.querySelector('[data-testid="decrypted-text"]'));
    assert.equal(output.textContent, secret);
    assert.equal(output.children.length, 0, 'HTML として解釈されていない');
    assert.equal(receiver.window.location.hash, '', '消費後は、アドレスバーから鍵が消える');
    assert.equal(world.store.size, 0, 'サーバーには何も残らない');
    assert.equal(world.store.takes.length, 1);
  });

  it('サーバーが受け取った生の通信・保存・ログのどこにも、鍵・平文は現れない（UI が送っていない）', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, secret);
    const keyString = link.split('#')[1] ?? '';
    const id = new URL(link).pathname.split('/').pop() ?? '';

    const receiver = browse(world, link);
    await awaitConfirm(receiver);
    clickOpen(receiver);
    await waitFor(() => has(receiver.main, '[data-testid="decrypted-text"]'));

    const observed = world.observedOnWire();
    const requests = parseHttpRequests(observed);
    assert.deepEqual(
      requests.map((r) => `${r.method} ${r.target.replace(id, ':id')}`),
      ['POST /api/payload', 'GET /api/payload/:id/meta', 'POST /api/payload/:id/consume'],
      'UI が送ったリクエストは、この 3 本だけ',
    );

    const [upload] = requests;
    const stored = world.store.puts[0];
    assert.ok(upload && stored);
    assert.deepEqual(new Uint8Array(upload.body), stored.ciphertext, 'アップロード本文は暗号文そのもの');
    assert.equal(upload.headers.get(HEADER_TYPE), 'text');
    assert.equal(upload.headers.get(HEADER_TTL), String(DEFAULT_TTL_SECONDS));

    const rawKey = Buffer.from(keyString, 'base64url');
    assert.deepEqual(leakedForms(observed, rawKey, '鍵'), []);
    for (let i = 0; i + 12 <= keyString.length; i++) assert.ok(!observed.toString('latin1').includes(keyString.slice(i, i + 12)), `鍵の一部 (${i}〜)`);
    assert.deepEqual(leakedForms(observed, Buffer.from(secret), '平文'), []);
    for (const fragment of ['123456789012', 'top-secret-passphrase', '口座', 'onerror']) assert.ok(!observed.includes(fragment), fragment);

    const heads = requests.map((r) => r.head).join('\n');
    assert.ok(!heads.includes('#') && !heads.includes('?'), 'リクエスト行・ヘッダーにフラグメントもクエリもない');
    assert.equal(requests.some((r) => r.headers.has('cookie') || r.headers.has('referer')), false, 'Cookie・Referer を送らない');

    const logText = JSON.stringify(world.logs);
    for (const value of [keyString, id, 'top-secret-passphrase']) assert.ok(!logText.includes(value), 'ログに機密がない');
  });

  it('リンクプレビュー・スキャナ（JS を実行して meta を叩く）が何度来ても消えず、受信者は最後まで開ける', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, secret);

    const scanners = Array.from({ length: 5 }, () => browse(world, link));
    await Promise.all(scanners.map(awaitConfirm));
    assert.equal(world.store.takes.length, 0);
    assert.equal(world.store.size, 1, 'スキャナがページを開いても、データは残っている');

    const receiver = browse(world, link);
    await awaitConfirm(receiver);
    clickOpen(receiver);
    const output = await waitFor(() => receiver.main.querySelector('[data-testid="decrypted-text"]'));
    assert.equal(output.textContent, secret);
  });

  it('2 回目にリンクを開いた人には「データが存在しません」。データは再取得できない', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, 'one time');

    const first = browse(world, link);
    await awaitConfirm(first);
    clickOpen(first);
    await waitFor(() => has(first.main, '[data-testid="decrypted-text"]'));

    const second = browse(world, link);
    await waitFor(() => /データが存在しません/.test(second.main.textContent ?? ''));
    assert.equal(has(second.main, '[data-action="open"]'), false);
  });

  it('同時に 2 人が「開く」を押しても、内容を読めるのは 1 人だけ（もう 1 人は「データが存在しません」）', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, 'race');

    const [a, b] = [browse(world, link), browse(world, link)];
    await Promise.all([awaitConfirm(a), awaitConfirm(b)]);
    clickOpen(a);
    clickOpen(b);
    await waitFor(() => [a, b].every((x) => has(x.main, '[data-testid="decrypted-text"]') || /データが存在しません/.test(x.main.textContent ?? '')));

    const winners = [a, b].filter((x) => has(x.main, '[data-testid="decrypted-text"]'));
    assert.equal(winners.length, 1);
    assert.equal(world.store.size, 0);
  });
});

describe('UI E2E: 不完全なリンク', () => {
  it('鍵が欠けたリンクは、サーバーへ一切リクエストせずに止まる。正しいリンクなら、その後も開ける', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, '欠けたリンク');
    const before = parseHttpRequests(world.observedOnWire()).length;

    for (const broken of [link.slice(0, -13), link.split('#')[0] ?? link, `${link}。`]) {
      const receiver = browse(world, broken);
      assert.match(receiver.main.textContent ?? '', /リンクが不正です/, broken);
    }
    assert.equal(parseHttpRequests(world.observedOnWire()).length, before, 'サーバーへのリクエストは増えていない');
    assert.equal(world.store.size, 1, 'データは消費されていない');

    const proper = browse(world, link);
    await awaitConfirm(proper);
    clickOpen(proper);
    await waitFor(() => has(proper.main, '[data-testid="decrypted-text"]'));
  });
});

describe('UI E2E: ファイルの共有', () => {
  it('ドロップ → 暗号化して送信 → 受信者がダウンロード。名前もバイト列も元どおりで、サーバーには名前が見えない', async (t) => {
    const world = await startWorld(t);
    const content = Uint8Array.from({ length: 200_000 }, (_, i) => (i * 7 + (i >> 8)) % 256);

    const sender = browse(world, HOME);
    click(query(sender.main, '#tab-file'));
    dropFiles(query(sender.main, '#file').closest('label') as HTMLLabelElement, [makeFile('山田太郎_診断書 (確定版).pdf', content)]);
    click(query(sender.main, '[data-action="submit"]'));
    const link = (await waitFor(() => sender.main.querySelector('[data-testid="share-link"]'))).textContent ?? '';

    const receiver = browse(world, link);
    await awaitConfirm(receiver);
    assert.match(receiver.main.textContent ?? '', /種類ファイル/, '確認画面の種類は「ファイル」');
    assert.doesNotMatch(receiver.main.textContent ?? '', /診断書/, '確認画面（サーバー由来）にファイル名は出ない');

    clickOpen(receiver);
    await waitFor(() => has(receiver.main, '[data-testid="received-file-name"]'));
    assert.equal(receiver.saved.length, 1);
    assert.equal(receiver.saved[0]?.name, '山田太郎_診断書 (確定版).pdf');
    assert.deepEqual(new Uint8Array(receiver.saved[0]?.data ?? new ArrayBuffer(0)), content);

    const observed = world.observedOnWire();
    assert.deepEqual(leakedForms(observed, Buffer.from('山田太郎_診断書'), 'ファイル名'), []);
    assert.equal(observed.includes('診断書'), false);
    assert.equal(world.store.puts[0]?.type, 'file');
    assert.equal(world.store.size, 0);
  });

  it('悪意ある名前（パス・双方向制御文字）のファイルは、無害化した名前で保存される', async (t) => {
    const world = await startWorld(t);
    const sender = browse(world, HOME);
    click(query(sender.main, '#tab-file'));
    dropFiles(query(sender.main, '#file').closest('label') as HTMLLabelElement, [makeFile('../../evil\u202Efdp.exe', 'MZ')]);
    click(query(sender.main, '[data-action="submit"]'));
    const link = (await waitFor(() => sender.main.querySelector('[data-testid="share-link"]'))).textContent ?? '';

    const receiver = browse(world, link);
    await awaitConfirm(receiver);
    clickOpen(receiver);
    await waitFor(() => has(receiver.main, '[data-testid="received-file-name"]'));

    const savedName = receiver.saved[0]?.name ?? '';
    assert.doesNotMatch(savedName, /[\\/\u202E]/u);
    assert.doesNotMatch(savedName, /^\./);
    assert.match(receiver.main.textContent ?? '', /実行ファイルまたはスクリプトの可能性があります/);
  });
});

describe('UI E2E: サーバーの制限・容量', () => {
  async function sendAndReadError(text: string, world: World): Promise<string> {
    const sender = browse(world, HOME);
    typeInto(query<HTMLTextAreaElement>(sender.main, '#message'), text);
    click(query(sender.main, '[data-action="submit"]'));
    const alert = await waitFor(() => sender.main.querySelector('[role="alert"]'));
    return alert.textContent ?? '';
  }

  it('サーバーが 413（暗号文が上限超過）を返したら、UI は「大きすぎます」と表示する。何も保存されない', async (t) => {
    const world = await startWorld(t, undefined, { maxPayloadBytes: 1024 });
    assert.match(await sendAndReadError('x'.repeat(4000), world), /サイズが上限（10 MB）を超えています/);
    assert.equal(world.store.size, 0);
  });

  it('サーバーが 503（保存容量の上限）を返したら、UI は容量不足を案内する', async (t) => {
    const world = await startWorld(t, () => new RecordingStore({ maxTotalBytes: 100, sweepIntervalMs: 0 }));
    await shareText(world, 'first'); // 1 件目は入る
    assert.match(await sendAndReadError('x'.repeat(200), world), /保存領域が上限に達しています/);
  });
});

describe('フロントエンドとバックエンドの契約（定数の整合）', () => {
  it('送信画面の有効期限の選択肢は、すべてサーバーが受け付ける範囲（60 秒〜7 日）で、既定値は一致する', () => {
    for (const { seconds } of TTL_OPTIONS) assert.ok(seconds >= 60 && seconds <= DEFAULT_MAX_TTL_SECONDS, `${seconds}`);
    assert.ok(TTL_OPTIONS.some((option) => option.seconds === UI_DEFAULT_TTL));
    assert.equal(UI_DEFAULT_TTL, DEFAULT_TTL_SECONDS);
  });

  it('画面が許す最大サイズ（ファイル名 1024 バイトの封筒・GCM タグを含む）は、サーバーの上限を超えない', () => {
    const envelopeOverhead = 1 + 2 + 1024; // 種別タグ + 名前長 + 名前（最大）
    const gcmTag = 16;
    assert.ok(MAX_UPLOAD_BYTES + envelopeOverhead + gcmTag <= DEFAULT_MAX_PAYLOAD_BYTES);
    assert.ok(DEFAULT_MAX_PAYLOAD_BYTES - MAX_UPLOAD_BYTES < 16 * 1024, '余裕は大きすぎない（画面の「10 MB」と実際の上限が乖離しない）');
  });

  it('ヘッダー名はフロントエンドとバックエンドで一致する（大文字小文字は区別しない）', () => {
    assert.equal(CLIENT_HEADER_IV.toLowerCase(), HEADER_IV);
    assert.equal(CLIENT_HEADER_TTL.toLowerCase(), HEADER_TTL);
    assert.equal(CLIENT_HEADER_TYPE.toLowerCase(), HEADER_TYPE);
  });

  it('画面から見えるページ内の要素は、UI の外へ何も読み込まない（img / script / link / iframe が 0）', async (t) => {
    const world = await startWorld(t);
    const link = await shareText(world, 'x');
    for (const b of [browse(world, HOME), browse(world, link)]) {
      assert.equal(b.doc.querySelectorAll('img, script, iframe, link, object, embed').length, 0);
    }
  });
});
