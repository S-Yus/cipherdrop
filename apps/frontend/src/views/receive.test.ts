import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ApiError } from '../api.ts';
import { mountApp } from '../app.ts';
import { encryptData, encryptFile, generateKeyCheckTag } from '../crypto.ts';
import type { EncryptedPayload } from '../crypto.ts';
import { SAMPLE_ID, click, createTestEnv, has, meta, query, waitFor } from '../testing/env.ts';
import type { ApiCall, TestEnvOptions } from '../testing/env.ts';

/**
 * 受取画面を開く。sealed の暗号文を返す API を用意し、鍵は sealed のものをリンクに載せる（key で上書き可）。
 * keyCheck を渡すと meta 応答に含める（省略時は、これまでどおり keyCheck を含めない＝後方互換のケース）。
 */
function open(sealed: EncryptedPayload, options: { type?: 'text' | 'file'; key?: string; path?: string; keyCheck?: string; env?: TestEnvOptions } = {}) {
  const type = options.type ?? 'text';
  const key = options.key ?? sealed.keyString;
  const t = createTestEnv({
    url: `https://cipherdrop.io${options.path ?? `/v/${SAMPLE_ID}`}${key === '' ? '' : `#${key}`}`,
    api: {
      getMeta: async () => ({
        ...meta(type, sealed.encryptedData.byteLength),
        ...(options.keyCheck === undefined ? {} : { keyCheck: options.keyCheck }),
      }),
      consume: async () => ({ encryptedData: sealed.encryptedData, iv: sealed.iv }),
    },
    ...options.env,
  });
  const app = mountApp(t.env);
  return { ...t, app };
}

const methods = (t: { calls: ApiCall[] }) => t.calls.map((call) => call.method);
const openButton = (t: { main: HTMLElement }) => query<HTMLButtonElement>(t.main, '[data-action="open"]');
const settle = () => new Promise((resolve) => setTimeout(resolve, 40));
/** 確認画面の dl（種類・サイズ・有効期限・暗号方式）を { 見出し: 値 } にする。 */
const rows = (t: { main: HTMLElement }): Record<string, string> =>
  Object.fromEntries([...t.main.querySelectorAll('dl > div')].map((row) => [row.querySelector('dt')?.textContent ?? '', row.querySelector('dd')?.textContent ?? '']));

/** 確認画面（Stage 1）が表示されるまで待つ。 */
async function untilConfirm(t: { main: HTMLElement }): Promise<void> {
  await waitFor(() => has(t.main, '[data-action="open"]'));
}

describe('受取画面 Stage 1（確認）: 開いただけでは何も消費しない', () => {
  it('ページ読み込み時に呼ぶのは meta だけ。警告・種類・サイズ・有効期限を表示し、consume は呼ばない', async () => {
    const sealed = await encryptData('secret');
    const t = open(sealed);
    await untilConfirm(t);
    await settle(); // 遅れて何かが呼ばれないことも確認する

    assert.deepEqual(methods(t), ['getMeta'], 'meta だけ');
    assert.deepEqual(t.calls[0]?.args, [SAMPLE_ID]);

    const shown = rows(t);
    assert.equal(query(t.main, 'h1').textContent, '受信データ');
    assert.equal(shown['種類'], 'テキスト');
    assert.equal(shown['サイズ'], `${sealed.encryptedData.byteLength} B`, '暗号文のサイズ');
    assert.match(shown['有効期限'] ?? '', /あと 23時間/, '有効期限までの残り時間');
    assert.equal(shown['暗号方式'], 'AES-256-GCM');
    assert.match(t.main.textContent ?? '', /このデータは一度開くとサーバーから永久削除されます/);
    assert.equal(openButton(t).textContent, 'データを復号して表示');
    assert.equal(has(t.main, '[data-testid="decrypted-text"]'), false, '内容はまだ表示しない');
  });

  it('リンクプレビューやスキャナが（JS を実行して）ページを何度開いても、消費されない', async () => {
    const sealed = await encryptData('secret');
    const opened = [];
    for (let i = 0; i < 5; i++) opened.push(open(sealed));
    await Promise.all(opened.map(untilConfirm));
    await settle();

    for (const t of opened) assert.deepEqual(methods(t), ['getMeta']);
  });

  it('ファイルの確認画面: 種類は「ファイル」、ボタンは「データを復号してダウンロード」', async () => {
    const sealed = await encryptFile({ name: '契約書.pdf', data: new ArrayBuffer(10) });
    const t = open(sealed, { type: 'file' });
    await untilConfirm(t);

    assert.equal(rows(t)['種類'], 'ファイル');
    assert.equal(openButton(t).textContent, 'データを復号してダウンロード');
    assert.doesNotMatch(t.main.textContent ?? '', /契約書/, '確認画面（サーバー由来の情報）にファイル名は現れない');
  });

  it('meta の取得中は読み込み表示（ボタンなし）', async () => {
    const sealed = await encryptData('x');
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        async getMeta() {
          await gate;
          return meta('text');
        },
      },
    });
    mountApp(t.env);

    assert.match(query(t.main, '[role="status"]').textContent ?? '', /確認中/);
    assert.equal(has(t.main, '[data-action="open"]'), false);
    release();
    await waitFor(() => has(t.main, '[data-action="open"]'));
  });
});

describe('受取画面 Stage 2（消費・復号）: 「開く」を押したときだけ', () => {
  it('ボタンで consume を 1 回だけ呼び、復号したテキストを表示する。アドレスバーから鍵が消える', async () => {
    const sealed = await encryptData('山田様\n口座番号: 0123-4567');
    const t = open(sealed);
    await untilConfirm(t);
    assert.equal(t.window.location.hash, `#${sealed.keyString}`, '確認段階では、リロードできるよう鍵は URL に残す');

    click(openButton(t));
    const output = await waitFor(() => t.main.querySelector('[data-testid="decrypted-text"]'));

    assert.equal(output.textContent, '山田様\n口座番号: 0123-4567');
    assert.deepEqual(methods(t), ['getMeta', 'consume']);
    assert.equal(t.window.location.hash, '', '取得（消滅）後は、URL から鍵を消す');
    assert.equal(t.window.location.pathname, `/v/${SAMPLE_ID}`);
    assert.match(t.main.textContent ?? '', /サーバー上のデータは削除済みです/);
    assert.equal(t.doc.activeElement?.tagName, 'H1', '結果の見出しにフォーカスが移る');
  });

  it('HTML・スクリプトを含むテキストは、要素にならず文字のまま表示される（XSS 対策）', async () => {
    const attack = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script><a href="javascript:alert(1)">x</a>&lt;b&gt;';
    const t = open(await encryptData(attack));
    await untilConfirm(t);
    click(openButton(t));
    const output = await waitFor(() => t.main.querySelector('[data-testid="decrypted-text"]'));

    assert.equal(output.textContent, attack);
    assert.equal(output.children.length, 0, '表示領域に要素が 1 つも生成されない');
    assert.equal(t.main.querySelectorAll('img, script, iframe, object, embed').length, 0);
    const handlers = [...t.main.querySelectorAll('*')].flatMap((element) => element.getAttributeNames().filter((name) => name.startsWith('on')));
    assert.deepEqual(handlers, [], 'イベントハンドラ属性が 1 つも存在しない');
    assert.equal((t.window as unknown as { __xss?: number }).__xss, undefined);
  });

  it('取得中は、ボタンが無効になりラベルが変わる。ダブルクリックしても consume は 1 回だけ', async () => {
    const sealed = await encryptData('once');
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        getMeta: async () => meta('text'),
        async consume() {
          await gate;
          return { encryptedData: sealed.encryptedData, iv: sealed.iv };
        },
      },
    });
    mountApp(t.env);
    await waitFor(() => has(t.main, '[data-action="open"]'));

    const button = openButton(t);
    click(button);
    click(button); // ダブルクリック
    await waitFor(() => openButton(t).textContent?.includes('取得・復号中'));
    assert.equal(openButton(t).disabled, true);

    release();
    await waitFor(() => has(t.main, '[data-testid="decrypted-text"]'));
    assert.equal(t.calls.filter((call) => call.method === 'consume').length, 1);
  });

  it('テキストをコピーできる。クリップボードに書かれるのは本文で、一定時間後に表示が戻る', async () => {
    const t = open(await encryptData('コピーする本文'));
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-action="copy-text"]'));

    const copy = query(t.main, '[data-action="copy-text"]');
    click(copy);
    await waitFor(() => t.clipboardWrites.length === 1);
    assert.deepEqual(t.clipboardWrites, ['コピーする本文']);
    assert.equal(copy.textContent, 'コピーしました');
    t.runTimers();
    assert.equal(copy.textContent, 'コピー');
  });

  it('クリップボードが使えなくても、失敗を伝えるだけで画面は壊れない', async () => {
    const t = open(await encryptData('x'), { env: { clipboard: 'none' } });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-action="copy-text"]'));

    click(query(t.main, '[data-action="copy-text"]'));
    await waitFor(() => /コピーできません/.test(t.main.textContent ?? ''));
  });
});

describe('受取画面: ファイル', () => {
  it('復号したファイルを、送信者が付けた名前でダウンロードする（アプリ内では開かない）', async () => {
    const data = Uint8Array.from({ length: 2000 }, (_, i) => (i * 31) % 256);
    const t = open(await encryptFile({ name: '契約書_最終版 (確定).pdf', data: data.buffer }), { type: 'file' });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="received-file-name"]'));

    assert.equal(t.saved.length, 1);
    assert.equal(t.saved[0]?.name, '契約書_最終版 (確定).pdf');
    assert.deepEqual(new Uint8Array(t.saved[0]?.data ?? new ArrayBuffer(0)), data);
    assert.equal(query(t.main, '[data-testid="received-file-name"]').textContent, '契約書_最終版 (確定).pdf');
    assert.match(t.main.textContent ?? '', /ダウンロードを開始しました/);
    assert.equal(has(t.main, '[data-testid="decrypted-text"]'), false);
    assert.deepEqual(methods(t), ['getMeta', 'consume']);
    assert.equal(t.window.location.hash, '');

    click(query(t.main, '[data-action="download-again"]'));
    assert.equal(t.saved.length, 2, '「もう一度ダウンロード」で再び保存できる');
  });

  it('悪意のあるファイル名は無害化してから保存・表示する（パス・双方向制御文字・NUL）', async () => {
    const t = open(await encryptFile({ name: '../../evil\u202Efdp.exe', data: new ArrayBuffer(4) }), { type: 'file' });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="received-file-name"]'));

    const savedName = t.saved[0]?.name ?? '';
    assert.doesNotMatch(savedName, /[\\/\u202E]/u);
    assert.doesNotMatch(savedName, /^\./);
    assert.equal(query(t.main, '[data-testid="received-file-name"]').textContent, savedName, '表示名と保存名は同じ');
  });

  it('実行ファイル・スクリプトなどの拡張子には注意喚起を出す。通常のファイルには出さない', async () => {
    const risky = open(await encryptFile({ name: 'invoice.pdf.exe', data: new ArrayBuffer(4) }), { type: 'file' });
    await untilConfirm(risky);
    click(openButton(risky));
    await waitFor(() => has(risky.main, '[data-testid="received-file-name"]'));
    assert.match(risky.main.textContent ?? '', /実行ファイルまたはスクリプトの可能性があります/);

    const safe = open(await encryptFile({ name: 'report.pdf', data: new ArrayBuffer(4) }), { type: 'file' });
    await untilConfirm(safe);
    click(openButton(safe));
    await waitFor(() => has(safe.main, '[data-testid="received-file-name"]'));
    assert.doesNotMatch(safe.main.textContent ?? '', /実行ファイルまたはスクリプトの可能性/);
  });

  it('自動ダウンロードが失敗した場合は、その旨を伝え、ボタンでもう一度保存できる', async () => {
    const t = open(await encryptFile({ name: 'a.txt', data: new ArrayBuffer(4) }), { type: 'file', env: { saveFileThrows: true } });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="received-file-name"]'));

    assert.match(query(t.main, '[role="alert"]').textContent ?? '', /自動でダウンロードできませんでした/);
    assert.doesNotMatch(t.main.textContent ?? '', /ダウンロードを開始しました/);
    assert.doesNotThrow(() => click(query(t.main, '[data-action="download-again"]')));
  });

  it('種別の分岐はサーバーのヒントではなく、復号後（認証済み）の種別で決まる', async () => {
    // サーバーは「file」と申告したが、中身はテキスト → テキストとして表示し、ダウンロードしない
    const lyingFile = open(await encryptData('本当はテキスト'), { type: 'file' });
    await untilConfirm(lyingFile);
    click(openButton(lyingFile));
    const output = await waitFor(() => lyingFile.main.querySelector('[data-testid="decrypted-text"]'));
    assert.equal(output.textContent, '本当はテキスト');
    assert.equal(lyingFile.saved.length, 0);

    // サーバーは「text」と申告したが、中身はファイル → ダウンロードし、テキスト表示はしない
    const lyingText = open(await encryptFile({ name: 'x.bin', data: new ArrayBuffer(4) }), { type: 'text' });
    await untilConfirm(lyingText);
    click(openButton(lyingText));
    await waitFor(() => has(lyingText.main, '[data-testid="received-file-name"]'));
    assert.equal(lyingText.saved.length, 1);
    assert.equal(has(lyingText.main, '[data-testid="decrypted-text"]'), false);
  });

  it('名前なしのバイナリ（API 経由の生データ）は既定の名前で保存する', async () => {
    const t = open(await encryptData(new Uint8Array([1, 2, 3]).buffer), { type: 'file' });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="received-file-name"]'));
    assert.equal(t.saved[0]?.name, 'cipherdrop-file');
  });
});

describe('受取画面: 不完全なリンクは、消費する前に止める（API を一切呼ばない）', () => {
  it('鍵が欠けている・余分・形式不正のリンクは「リンクが正しくありません」。meta も consume も呼ばれない', async () => {
    const sealed = await encryptData('x');
    const key = sealed.keyString;
    const lastIndex = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.indexOf(key.at(-1) ?? '');
    const nonCanonical = key.slice(0, -1) + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.charAt(lastIndex + 1);
    const badKeys: Array<[string, string]> = [
      ['鍵なし', ''],
      ['短い（途中で切れた）', key.slice(0, 30)],
      ['1 文字だけ足りない', key.slice(0, 42)],
      ['末尾に句読点（メールの自動リンクで付く）', `${key}。`],
      ['末尾にピリオド', `${key}.`],
      ['余分な文字', `${key}A`],
      ['標準 base64 の記号', `${key.slice(0, 42)}+`],
      ['非正規表現の鍵', nonCanonical],
    ];
    for (const [label, badKey] of badKeys) {
      const t = open(sealed, { key: badKey });
      assert.match(t.main.textContent ?? '', /リンクが不正です/, label);
      assert.equal(t.calls.length, 0, `${label}: API を呼んでいない`);
      assert.equal(has(t.main, '[data-action="open"]'), false, label);
    }
  });

  it('ID の形式が不正なパス（/v/short）も同様に止める', async () => {
    const sealed = await encryptData('x');
    const t = open(sealed, { path: '/v/short' });
    assert.match(t.main.textContent ?? '', /リンクが不正です/);
    assert.equal(t.calls.length, 0);
  });
});

describe('受取画面: 鍵確認値（形式は正しいが内容が違う鍵を、消費する前に止める）', () => {
  it('meta.keyCheck とローカルで計算した値が不一致なら「鍵が一致しません」。「開く」ボタンを出さず、consume は一度も呼ばない', async () => {
    const sealed = await encryptData('鍵確認ミスマッチの本文');
    const t = open(sealed, { keyCheck: '00000000' });
    await waitFor(() => /鍵が一致しません/.test(t.main.textContent ?? ''));

    assert.match(t.main.textContent ?? '', /共有リンクの復号鍵が正しくないか、途中で切れています/);
    assert.match(t.main.textContent ?? '', /正しい URL を確認してください/);
    assert.equal(has(t.main, '[data-action="open"]'), false, '「開く」ボタンを描画しない');
    assert.deepEqual(methods(t), ['getMeta'], 'consume は一度も呼ばれない（meta の確認だけ）');
  });

  it('不一致のエラーは、赤く塗りつぶさない静かな表示（border-red-500/20 bg-red-500/5）で、再試行ボタンを持たない', async () => {
    const t = open(await encryptData('x'), { keyCheck: 'ffffffff' });
    await waitFor(() => /鍵が一致しません/.test(t.main.textContent ?? ''));

    const alert = query(t.main, '[role="alert"]');
    assert.ok(alert.classList.contains('border-red-500/20') && alert.classList.contains('bg-red-500/5'));
    assert.equal(has(t.main, '[data-action="retry"]'), false, 'URL 自体が誤っているので、再試行しても直らない');
    assert.equal(has(t.main, 'button'), false, '操作できるボタンを 1 つも置かない');
  });

  it('一致すれば、通常どおり確認画面から開ける（誤検出で正しいデータへの到達を妨げない）', async () => {
    const sealed = await encryptData('鍵確認一致の本文');
    const correctTag = await generateKeyCheckTag(sealed.keyString);
    const t = open(sealed, { keyCheck: correctTag });
    await waitFor(() => has(t.main, '[data-action="open"]'));

    click(openButton(t));
    const output = await waitFor(() => t.main.querySelector('[data-testid="decrypted-text"]'));
    assert.equal(output.textContent, '鍵確認一致の本文');
    assert.deepEqual(methods(t), ['getMeta', 'consume']);
  });

  it('meta に keyCheck が無い（旧データ・未対応の送信側）なら、従来どおり確認画面が出る（後方互換）', async () => {
    const sealed = await encryptData('x');
    const t = open(sealed); // keyCheck を指定しない＝これまでの meta() と同じ
    await waitFor(() => has(t.main, '[data-action="open"]'));
    assert.equal(has(t.main, '[role="alert"]'), false);
  });

  it('ファイルでも同様に、不一致ならダウンロードせず止める', async () => {
    const sealed = await encryptFile({ name: '見積書.pdf', data: new ArrayBuffer(16) });
    const t = open(sealed, { type: 'file', keyCheck: '12345678' });
    await waitFor(() => /鍵が一致しません/.test(t.main.textContent ?? ''));

    assert.equal(t.saved.length, 0, 'ダウンロードは発生しない');
    assert.doesNotMatch(t.main.textContent ?? '', /見積書/, '確認前のファイル名は画面に出ない');
    assert.deepEqual(methods(t), ['getMeta']);
  });
});

describe('受取画面: エラー', () => {
  it('meta が 404（消費済み・期限切れ・存在しない）は「このリンクは無効です」', async () => {
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${(await encryptData('x')).keyString}`,
      api: {
        getMeta: async () => {
          throw new ApiError('not_found', 404);
        },
      },
    });
    mountApp(t.env);
    await waitFor(() => /データが存在しません/.test(t.main.textContent ?? ''));
    assert.deepEqual(t.calls.map((call) => call.method), ['getMeta']);
  });

  it('consume が 404（確認後に他の人が先に開いた）でも「このリンクは無効です」', async () => {
    const sealed = await encryptData('x');
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        getMeta: async () => meta('text'),
        consume: async () => {
          throw new ApiError('not_found', 404);
        },
      },
    });
    mountApp(t.env);
    await waitFor(() => has(t.main, '[data-action="open"]'));
    click(query(t.main, '[data-action="open"]'));
    await waitFor(() => /データが存在しません/.test(t.main.textContent ?? ''));
  });

  it('meta の通信エラーは再試行できる', async () => {
    const sealed = await encryptData('x');
    let attempts = 0;
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        async getMeta() {
          if (++attempts === 1) throw new ApiError('network');
          return meta('text');
        },
      },
    });
    mountApp(t.env);

    await waitFor(() => /サーバーに接続できません/.test(t.main.textContent ?? ''));
    click(query(t.main, '[data-action="retry"]'));
    await waitFor(() => has(t.main, '[data-action="open"]'));
    assert.equal(attempts, 2);
  });

  it('consume の通信エラーは再試行できる。失敗の間は、リロードできるよう URL の鍵を残す', async () => {
    const sealed = await encryptData('再試行で読める');
    let attempts = 0;
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        getMeta: async () => meta('text'),
        async consume() {
          if (++attempts === 1) throw new ApiError('network');
          return { encryptedData: sealed.encryptedData, iv: sealed.iv };
        },
      },
    });
    mountApp(t.env);
    await waitFor(() => has(t.main, '[data-action="open"]'));

    click(query(t.main, '[data-action="open"]'));
    await waitFor(() => /取得に失敗しました/.test(t.main.textContent ?? ''));
    assert.equal(t.window.location.hash, `#${sealed.keyString}`, '取得に失敗した間は鍵を消さない');

    click(query(t.main, '[data-action="retry-open"]'));
    const output = await waitFor(() => t.main.querySelector('[data-testid="decrypted-text"]'));
    assert.equal(output.textContent, '再試行で読める');
    assert.equal(attempts, 2);
    assert.equal(t.window.location.hash, '');
  });

  it('鍵が違う（形式は正しい）場合は復号に失敗する。取得済みなので鍵は URL から消え、本文は出さない', async () => {
    const sealed = await encryptData('本文');
    const other = await encryptData('別の鍵');
    const t = open(sealed, { key: other.keyString });
    await untilConfirm(t);
    click(openButton(t));

    await waitFor(() => /復号に失敗しました/.test(t.main.textContent ?? ''));
    assert.match(t.main.textContent ?? '', /サーバー上のデータは削除済みです/);
    assert.equal(t.window.location.hash, '');
    assert.equal(has(t.main, '[data-testid="decrypted-text"]'), false);
    assert.doesNotMatch(t.main.textContent ?? '', /本文/);
  });

  it('暗号文が改ざんされていたら、復号に失敗して内容を表示しない', async () => {
    const sealed = await encryptData('改ざんされる');
    const tampered = new Uint8Array(sealed.encryptedData);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: { getMeta: async () => meta('text'), consume: async () => ({ encryptedData: tampered.buffer, iv: sealed.iv }) },
    });
    mountApp(t.env);
    await waitFor(() => has(t.main, '[data-action="open"]'));
    click(query(t.main, '[data-action="open"]'));

    await waitFor(() => /復号に失敗しました/.test(t.main.textContent ?? ''));
    assert.doesNotMatch(t.main.textContent ?? '', /改ざんされる/);
  });

  it('画面を破棄したあとに応答が届いても、画面を更新しない', async () => {
    const sealed = await encryptData('x');
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const t = createTestEnv({
      url: `https://cipherdrop.io/v/${SAMPLE_ID}#${sealed.keyString}`,
      api: {
        async getMeta() {
          await gate;
          return meta('text');
        },
      },
    });
    const app = mountApp(t.env);
    app.destroy();
    release();
    await settle();
    assert.equal(t.root.childNodes.length, 0);
  });
});

describe('受取画面: 破棄（表示中のデータを画面から消去する）', () => {
  async function openedText(text: string) {
    const t = open(await encryptData(text));
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="decrypted-text"]'));
    return t;
  }

  it('「破棄」を 1 回押すと、本文が画面から消え、「破棄しました」に切り替わる。再表示できない', async () => {
    const t = await openedText('破棄される本文 SECRET-BODY');
    const before = t.calls.length;

    click(query(t.main, '[data-action="discard"]'));

    assert.equal(query(t.main, 'h1').textContent, '破棄しました');
    assert.equal((t.main.textContent ?? '').includes('SECRET-BODY'), false, '本文が DOM に残らない');
    assert.equal(has(t.main, '[data-testid="decrypted-text"]'), false);
    assert.equal(has(t.main, '[data-action="copy-text"]'), false);
    assert.equal(t.doc.activeElement?.tagName, 'H1');
    assert.match(t.main.textContent ?? '', /サーバー上のデータは削除済みのため、再表示できません/);
    assert.equal(t.calls.length, before, '破棄は API を呼ばない');
  });

  it('破棄のあとにコピー表示のタイマーが動いても、例外にならず画面は「破棄しました」のまま', async () => {
    const t = await openedText('x');
    click(query(t.main, '[data-action="copy-text"]'));
    await waitFor(() => t.clipboardWrites.length === 1);
    click(query(t.main, '[data-action="discard"]'));

    assert.doesNotThrow(() => t.runTimers());
    assert.equal(query(t.main, 'h1').textContent, '破棄しました');
  });

  it('ファイルも「破棄」できる。ファイル名・バイト列への参照が画面から消え、再ダウンロードできない', async () => {
    const t = open(await encryptFile({ name: 'secret-plan.pdf', data: new ArrayBuffer(8) }), { type: 'file' });
    await untilConfirm(t);
    click(openButton(t));
    await waitFor(() => has(t.main, '[data-testid="received-file-name"]'));
    assert.equal(t.saved.length, 1);

    click(query(t.main, '[data-action="discard"]'));
    assert.equal(query(t.main, 'h1').textContent, '破棄しました');
    assert.equal((t.main.textContent ?? '').includes('secret-plan'), false);
    assert.equal(has(t.main, '[data-action="download-again"]'), false);
  });

  it('復号結果には「コピー」と「破棄」の 2 つの操作がある（同じ大きさの副次ボタン）', async () => {
    const t = await openedText('x');
    assert.equal(query(t.main, '[data-action="copy-text"]').textContent, 'コピー');
    assert.equal(query(t.main, '[data-action="discard"]').textContent, '破棄');
    assert.match(t.main.textContent ?? '', /破棄すると再表示できません/);
  });
});

describe('受取画面: デザイン規則（事実だけを、静かに伝える）', () => {
  it('Stage 1 の警告は amber の静かな通知（border-amber-500/20 bg-amber-500/5）で、事実だけを伝える。赤い警告は使わない', async () => {
    const t = open(await encryptData('x'));
    await untilConfirm(t);

    const note = query(t.main, '[role="note"]');
    assert.ok(note.classList.contains('border-amber-500/20') && note.classList.contains('bg-amber-500/5'));
    assert.equal(query(note, 'p').textContent, 'このデータは一度開くとサーバーから永久削除されます');
    assert.equal(note.querySelectorAll('p').length, 2, '事実の 1 文と、実行時点の 1 文だけ');
    assert.equal(t.main.querySelector('[class*="red-"]'), null, 'Stage 1 に赤は使わない');
  });

  it('確認画面の値（種類・サイズ・有効期限・暗号方式）は等幅。箇条書き・特長欄・フッターはない', async () => {
    const t = open(await encryptData('x'));
    await untilConfirm(t);

    const values = [...t.main.querySelectorAll('dd')];
    assert.equal(values.length, 4);
    for (const dd of values) assert.ok(dd.classList.contains('font-mono'));
    assert.equal(t.doc.querySelectorAll('ul, ol, footer').length, 0);
  });

  it('復号したテキストは、安全なテキストノードとして等幅のコードブロックに表示される', async () => {
    const t = open(await encryptData('<b>bold</b> ID: 0123'));
    await untilConfirm(t);
    click(openButton(t));
    const output = await waitFor(() => t.main.querySelector('[data-testid="decrypted-text"]'));

    assert.equal(output.tagName, 'PRE');
    for (const name of ['font-mono', 'bg-zinc-950', 'border-zinc-800']) assert.ok(output.classList.contains(name), name);
    assert.equal(output.children.length, 0);
    assert.equal(query(t.main, '[data-testid="decrypted-size"]').textContent, 'テキスト · 20 B');
  });

  it('エラー表示は、赤く塗りつぶさず 1px の枠線と 5% の面だけ（border-red-500/20 bg-red-500/5）', async () => {
    const t = open(await encryptData('x'), { key: 'A'.repeat(20) });
    const alert = query(t.main, '[role="alert"]');
    assert.ok(alert.classList.contains('border-red-500/20') && alert.classList.contains('bg-red-500/5'));
  });
});
