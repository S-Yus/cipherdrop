import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ApiError } from '../api.ts';
import { mountApp } from '../app.ts';
import { decryptPayload } from '../crypto.ts';
import { MAX_UPLOAD_BYTES } from '../limits.ts';
import { NOW, SAMPLE_ID, click, createTestEnv, dropFiles, has, makeFile, press, query, typeInto, waitFor } from '../testing/env.ts';
import type { TestEnvOptions } from '../testing/env.ts';

/** 送信画面を開く。 */
function open(options: TestEnvOptions = {}) {
  const t = createTestEnv(options);
  const app = mountApp(t.env);
  return { ...t, app };
}

type Opened = ReturnType<typeof open>;

const submitButton = (t: Opened) => query<HTMLButtonElement>(t.main, '[data-action="submit"]');
const dropzone = (t: Opened) => query(t.main, '#file').closest('label') as HTMLLabelElement;
const shareLink = (t: Opened) => query(t.main, '[data-testid="share-link"]');

/** 送信ボタンを押し、リンクが表示されるまで待って、リンク（全文）を返す。 */
async function generateLink(t: Opened): Promise<string> {
  click(submitButton(t));
  const block = await waitFor(() => t.main.querySelector('[data-testid="share-link"]'));
  return block.textContent ?? '';
}

function choose(t: Opened, seconds: number): void {
  const select = query<HTMLSelectElement>(t.main, 'select#ttl');
  select.value = String(seconds);
  select.dispatchEvent(new t.window.Event('change', { bubbles: true }));
}

describe('送信画面: 初期表示（タスクだけに集中した構成）', () => {
  it('見出しは「新規共有」。入力・有効期限・送信ボタンが並び、入力が空の間は送信できない。API は呼ばない', () => {
    const t = open();
    assert.equal(query(t.main, 'h1').textContent, '新規共有');
    assert.equal(t.doc.title, 'CipherDrop');

    assert.equal(query(t.main, '#tab-text').getAttribute('aria-selected'), 'true');
    assert.equal(query(t.main, '#tab-file').getAttribute('aria-selected'), 'false');
    assert.equal(query(t.main, '#tab-text').textContent, 'テキスト');
    assert.equal(submitButton(t).textContent, '暗号化リンクを生成');
    assert.equal(submitButton(t).disabled, true);
    assert.equal(t.calls.length, 0);
  });

  it('暗号化ステータスバッジ（AES-256-GCM / Client-Side Encrypted）が、等幅で最上部に表示される', () => {
    const t = open();
    const badge = query(t.main, '[data-testid="status-badge"]');
    assert.equal(badge.textContent, 'AES-256-GCM / Client-Side Encrypted');
    assert.ok(badge.classList.contains('font-mono'));
    assert.equal(t.main.firstElementChild?.contains(badge), true, '本文の最初の要素');
  });

  it('URL ハッシュの鍵が送信されないこと・物理削除されることを、事実として 1 文で示す', () => {
    const t = open();
    assert.match(t.main.textContent ?? '', /URL ハッシュ（#）の復号鍵はサーバーに送信されません。取得後、サーバー上のデータは物理削除されます。/);
  });

  it('有効期限は素直な <select>（1時間・24時間・7日間。既定は 24時間）。ラジオやカードではない', () => {
    const t = open();
    const select = query<HTMLSelectElement>(t.main, 'select#ttl');
    assert.deepEqual([...select.options].map((o) => `${o.value}:${o.textContent}`), ['3600:1時間', '86400:24時間', '604800:7日間']);
    assert.equal(select.value, '86400');
    assert.equal(query(t.main, 'label[for="ttl"]').textContent, '有効期限');
    assert.equal(t.main.querySelectorAll('input[type="radio"]').length, 0);
  });

  it('入力欄はコードエディタのような無骨な見た目（bg-zinc-950 / border-zinc-800 / font-mono）', () => {
    const t = open();
    const editor = query(t.main, '#message');
    for (const name of ['bg-zinc-950', 'border-zinc-800', 'font-mono']) assert.ok(editor.classList.contains(name), name);
    assert.ok(query(t.main, 'select#ttl').classList.contains('font-mono'));
  });

  it('ヒーローの文章・3 並びの特長欄・箇条書き・フッターを置かない', () => {
    const t = open();
    assert.equal(t.main.querySelectorAll('ul, ol, footer').length, 0);
    assert.equal(t.doc.querySelectorAll('footer').length, 0);
    assert.equal(t.main.querySelectorAll('h1').length, 1);
    assert.equal(t.main.querySelectorAll('h2, h3').length, 0);
  });

  it('入力があれば送信できる。空白・改行だけでは送信できない', () => {
    const t = open();
    const message = query<HTMLTextAreaElement>(t.main, '#message');

    typeInto(message, '   \n\t ');
    assert.equal(submitButton(t).disabled, true);
    typeInto(message, 'a');
    assert.equal(submitButton(t).disabled, false);
    typeInto(message, '');
    assert.equal(submitButton(t).disabled, true);
  });

  it('メッセージ入力欄は、ブラウザの綴りチェック（外部送信の恐れ）と自動補完を無効にしている', () => {
    const t = open();
    const message = query(t.main, '#message');
    assert.equal(message.getAttribute('spellcheck'), 'false');
    assert.equal(message.getAttribute('autocomplete'), 'off');
  });
});

describe('送信画面: バイト数の表示（等幅）', () => {
  it('入力に応じて UTF-8 のバイト数を更新する（全角は 3 バイト）', () => {
    const t = open();
    const counter = query(t.main, '[data-testid="byte-count"]');
    assert.equal(counter.textContent, '0 B / 10 MB');
    assert.ok(counter.classList.contains('font-mono') || counter.closest('.font-mono') !== null);

    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'abc');
    assert.equal(counter.textContent, '3 B / 10 MB');
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'あい');
    assert.equal(counter.textContent, '6 B / 10 MB');
  });

  it('上限（10 MB）を超えたら、その場で「上限超過」と表示し、送信できなくする', () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'a'.repeat(MAX_UPLOAD_BYTES + 1));

    const counter = query(t.main, '[data-testid="byte-count"]');
    assert.match(counter.textContent ?? '', /上限超過/);
    assert.ok(counter.classList.contains('text-red-400'));
    assert.equal(submitButton(t).disabled, true);

    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'a');
    assert.doesNotMatch(counter.textContent ?? '', /上限超過/);
    assert.equal(submitButton(t).disabled, false);
  });
});

describe('送信画面: テキストの送信', () => {
  it('暗号化して送信し、リンクを表示する。API に渡るのは暗号文・IV・種別・TTL だけで、鍵はどこにも現れない', async () => {
    const t = open();
    const secret = 'パスワードは Tr0ub4dor&3 です';
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), secret);

    const link = await generateLink(t);
    assert.match(link, new RegExp(`^https://cipherdrop\\.io/v/${SAMPLE_ID}#[A-Za-z0-9_-]{43}$`));
    const keyString = link.split('#')[1] ?? '';

    assert.equal(t.calls.length, 1);
    const call = t.calls[0];
    assert.ok(call?.method === 'createPayload');
    const input = call.args[0];
    assert.deepEqual(Object.keys(input).sort(), ['encryptedData', 'iv', 'ttlSeconds', 'type'], 'API に渡す項目はこれだけ');
    assert.equal(input.type, 'text');
    assert.equal(input.ttlSeconds, 86_400);
    assert.equal(input.iv.byteLength, 12);

    // 鍵は、API に渡ったデータのどの表現にも現れない
    const sent = Buffer.concat([Buffer.from(input.encryptedData), Buffer.from(input.iv)]);
    const rawKey = Buffer.from(keyString, 'base64url');
    for (const needle of [keyString, rawKey, rawKey.toString('hex'), rawKey.toString('base64'), secret]) {
      assert.equal(sent.includes(needle), false, '鍵・平文が API 引数に含まれている');
    }

    // リンクの鍵で、送った暗号文を復号できる（リンクが正しい）
    assert.deepEqual(await decryptPayload(input.encryptedData, input.iv, keyString), { type: 'text', text: secret });
  });

  it('生成後、URL の # 以降（鍵）を強調表示し、「この鍵はサーバーを経由していません」と注記する。リンクは等幅', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    const link = await generateLink(t);

    const keyPart = query(t.main, '[data-testid="key-part"]');
    assert.equal(keyPart.textContent, `#${link.split('#')[1]}`, '強調されるのは # 以降だけ');
    assert.match(keyPart.className, /text-emerald-400/);
    assert.equal(shareLink(t).firstElementChild?.textContent, link.split('#')[0], '# より前は強調しない');
    assert.doesNotMatch(shareLink(t).firstElementChild?.className ?? '', /emerald/);
    assert.ok(shareLink(t).classList.contains('font-mono'));
    assert.match(t.main.textContent ?? '', /この鍵はサーバーを経由していません/);
  });

  it('生成後は、有効期限・内容・「再表示できません」の注記を表示し、見出しにフォーカスが移る。バッジは残る', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'abc');
    await generateLink(t);

    const text = t.main.textContent ?? '';
    assert.match(text, /共有リンクを生成しました/);
    assert.match(text, /このリンクは再表示できません/);
    assert.match(text, /あと 1日/, '有効期限までの残り時間（24 時間ちょうどは日数表記）');
    assert.match(text, /テキスト · 3 B/);
    assert.equal(has(t.main, '#message'), false, '入力フォームは消える');
    assert.equal(t.doc.activeElement?.tagName, 'H1', '状態の変化を支援技術に伝えるため見出しにフォーカスする');
    assert.ok(has(t.main, '[data-testid="status-badge"]'));
  });

  it('生成後の値（有効期限・内容）は等幅。注記は amber の静かな通知（border-amber-500/20 bg-amber-500/5）', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'abc');
    await generateLink(t);

    for (const dd of t.main.querySelectorAll('dd')) assert.ok(dd.classList.contains('font-mono'));
    const note = query(t.main, '[role="note"]');
    assert.ok(note.classList.contains('border-amber-500/20') && note.classList.contains('bg-amber-500/5'));
  });

  it('選んだ有効期限（7日間）が TTL として送られる', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    choose(t, 604_800);
    await generateLink(t);

    const call = t.calls[0];
    assert.ok(call?.method === 'createPayload');
    assert.equal(call.args[0].ttlSeconds, 604_800);
  });

  it('送信中は入力・ボタンが無効になり、ラベルが変わる。完了すると結果に切り替わる', async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const t = open({
      api: {
        async createPayload() {
          await gate;
          return { id: SAMPLE_ID, expiresAt: new Date(NOW + 3_600_000) };
        },
      },
    });
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    click(submitButton(t));

    await waitFor(() => submitButton(t).textContent?.includes('暗号化中'));
    assert.equal(submitButton(t).disabled, true);
    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').disabled, true);
    assert.equal(query<HTMLSelectElement>(t.main, 'select#ttl').disabled, true);
    assert.equal(query(t.main, 'form').getAttribute('aria-busy'), 'true');

    release();
    await waitFor(() => has(t.main, '[data-testid="share-link"]'));
  });

  it('テキストに含まれる HTML は画面に要素として現れない（リンク表示のみ）', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '<img src=x onerror=alert(1)><script>alert(2)</script>');
    await generateLink(t);

    assert.equal(t.main.querySelectorAll('img, script, iframe').length, 0);
    assert.doesNotMatch(t.main.textContent ?? '', /onerror/);
  });
});

describe('送信画面: ファイルの送信', () => {
  it('ドロップしたファイルを、名前ごと暗号化して送る（名前は暗号文の内側で、API 引数には現れない）', async () => {
    const t = open();
    click(query(t.main, '#tab-file'));
    assert.equal(query(t.main, '#tab-file').getAttribute('aria-selected'), 'true');
    assert.equal(submitButton(t).disabled, true, 'ファイル未選択では送れない');

    const content = Uint8Array.from({ length: 3000 }, (_, i) => (i * 13) % 256);
    dropFiles(dropzone(t), [makeFile('山田太郎_診断書.pdf', content)]);
    const selected = query(t.main, '[data-testid="selected-file-name"]');
    assert.equal(selected.textContent, '山田太郎_診断書.pdf');
    assert.ok(selected.classList.contains('font-mono'), 'ファイル名は等幅');
    assert.equal(submitButton(t).disabled, false);

    const link = await generateLink(t);
    const call = t.calls[0];
    assert.ok(call?.method === 'createPayload');
    const input = call.args[0];
    assert.equal(input.type, 'file');
    assert.equal(Buffer.from(input.encryptedData).includes('診断書'), false, 'ファイル名が暗号文に平文で現れない');

    const decrypted = await decryptPayload(input.encryptedData, input.iv, link.split('#')[1] ?? '');
    assert.ok(decrypted.type === 'file');
    assert.equal(decrypted.name, '山田太郎_診断書.pdf');
    assert.deepEqual(new Uint8Array(decrypted.data), content);
    assert.match(t.main.textContent ?? '', /ファイル · 山田太郎_診断書\.pdf · 2\.9 KB/);
  });

  it('ドロップ領域は等幅の仕様表示（最大 10 MB · ファイル名も暗号化）', () => {
    const t = open();
    click(query(t.main, '#tab-file'));
    assert.match(dropzone(t).textContent ?? '', /ファイルをドロップ、またはクリックして選択/);
    assert.match(dropzone(t).textContent ?? '', /最大 10 MB · ファイル名も暗号化/);
  });

  it('空のファイルは選べない。大きすぎるファイル（上限 10 MB 超）も選べず、理由を表示する', () => {
    const t = open();
    click(query(t.main, '#tab-file'));

    dropFiles(dropzone(t), [makeFile('empty.txt', '')]);
    assert.match(query(t.main, '[role="alert"]').textContent ?? '', /空のため送信できません/);
    assert.equal(submitButton(t).disabled, true);

    dropFiles(dropzone(t), [{ name: 'big.bin', size: MAX_UPLOAD_BYTES + 1 } as File]);
    assert.match(query(t.main, '[role="alert"]').textContent ?? '', /上限（10 MB）を超えています/);
    assert.equal(submitButton(t).disabled, true);
  });

  it('上限ちょうどのサイズは選べる', () => {
    const t = open();
    click(query(t.main, '#tab-file'));
    dropFiles(dropzone(t), [{ name: 'limit.bin', size: MAX_UPLOAD_BYTES } as File]);
    assert.equal(has(t.main, '[role="alert"]'), false);
    assert.equal(submitButton(t).disabled, false);
  });

  it('複数ファイルをドロップすると最初の 1 つを選び、その旨を案内する（エラー扱いではない）', () => {
    const t = open();
    click(query(t.main, '#tab-file'));
    dropFiles(dropzone(t), [makeFile('first.txt', 'a'), makeFile('second.txt', 'b')]);

    assert.equal(query(t.main, '[data-testid="selected-file-name"]').textContent, 'first.txt');
    assert.match(query(t.main, '[role="status"]').textContent ?? '', /1 つずつ送信してください/);
    assert.equal(has(t.main, '[role="alert"]'), false);
  });

  it('「選択を解除」でファイルを外せる', () => {
    const t = open();
    click(query(t.main, '#tab-file'));
    dropFiles(dropzone(t), [makeFile('a.txt', 'a')]);
    click(query(t.main, '[data-action="remove-file"]'));

    assert.equal(has(t.main, '[data-testid="selected-file-name"]'), false);
    assert.equal(submitButton(t).disabled, true);
  });

  it('タブを切り替えても、入力済みのテキストとバイト数は失われない', () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '書きかけ');
    click(query(t.main, '#tab-file'));
    click(query(t.main, '#tab-text'));
    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '書きかけ');
    assert.equal(query(t.main, '[data-testid="byte-count"]').textContent, '12 B / 10 MB');
  });

  it('タブは矢印キー・Home・End で切り替えられ、フォーカスも移る', () => {
    const t = open();
    press(query(t.main, '#tab-text'), 'ArrowRight');
    assert.equal(query(t.main, '#tab-file').getAttribute('aria-selected'), 'true');
    assert.equal(t.doc.activeElement?.id, 'tab-file');
    press(query(t.main, '#tab-file'), 'ArrowLeft');
    assert.equal(query(t.main, '#tab-text').getAttribute('aria-selected'), 'true');
    press(query(t.main, '#tab-text'), 'End');
    assert.equal(query(t.main, '#tab-file').getAttribute('aria-selected'), 'true');
    press(query(t.main, '#tab-file'), 'Home');
    assert.equal(query(t.main, '#tab-text').getAttribute('aria-selected'), 'true');
  });
});

describe('送信画面: エラー', () => {
  const failures: Array<[ApiError, RegExp]> = [
    [new ApiError('network'), /サーバーに接続できません/],
    [new ApiError('payload_too_large', 413), /サイズが上限（10 MB）を超えています/],
    [new ApiError('storage_full', 503), /保存領域が上限に達しています/],
    [new ApiError('server', 500), /通信でエラーが発生しました/],
    [new ApiError('invalid_response', 201), /通信でエラーが発生しました/],
  ];
  for (const [error, expected] of failures) {
    it(`API が ${error.code} で失敗したら、原因を表示し、入力は保持して再送信できる`, async () => {
      let attempts = 0;
      const t = open({
        api: {
          async createPayload(input) {
            if (++attempts === 1) throw error;
            return { id: SAMPLE_ID, expiresAt: new Date(NOW + input.ttlSeconds * 1000) };
          },
        },
      });
      typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '大事なテキスト');
      click(submitButton(t));

      const alert = await waitFor(() => t.main.querySelector('[role="alert"]'));
      assert.match(alert.textContent ?? '', expected);
      assert.ok(alert.classList.contains('border-red-500/20') && alert.classList.contains('bg-red-500/5'), '赤く塗りつぶさない静かなエラー表示');
      assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '大事なテキスト', '入力は失われない');
      assert.equal(submitButton(t).disabled, false);

      assert.match(await generateLink(t), /#[A-Za-z0-9_-]{43}$/, '再送信で成功する');
    });
  }

  it('想定外の例外でも、内部のメッセージは表示しない', async () => {
    const t = open({
      api: {
        async createPayload() {
          throw new Error('SECRET-INTERNAL-DETAIL /api/payload');
        },
      },
    });
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    click(submitButton(t));

    const alert = await waitFor(() => t.main.querySelector('[role="alert"]'));
    assert.match(alert.textContent ?? '', /予期しないエラー/);
    assert.doesNotMatch(t.main.textContent ?? '', /SECRET-INTERNAL-DETAIL/);
  });
});

describe('送信画面: リンクのコピーと新規共有', () => {
  async function withLink(options: TestEnvOptions = {}) {
    const t = open(options);
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    const link = await generateLink(t);
    return { t, link };
  }

  it('コピーすると、リンク全体（鍵を含む）がクリップボードへ書かれ、一定時間後に表示が戻る', async () => {
    const { t, link } = await withLink();
    const copy = query(t.main, '[data-action="copy"]');
    assert.equal(copy.textContent, 'リンクをコピー');

    click(copy);
    await waitFor(() => t.clipboardWrites.length === 1);
    assert.deepEqual(t.clipboardWrites, [link]);
    assert.equal(copy.textContent, 'コピーしました');
    assert.match(query(t.main, '[role="status"]').textContent ?? '', /リンクをコピーしました/);

    t.runTimers();
    assert.equal(copy.textContent, 'リンクをコピー');
    assert.equal(query(t.main, '[role="status"]').textContent, '');
  });

  for (const mode of ['fail', 'none'] as const) {
    it(`クリップボードが使えない（${mode}）ときは、リンクを選択状態にして手動コピーを案内する`, async () => {
      const { t, link } = await withLink({ clipboard: mode });
      click(query(t.main, '[data-action="copy"]'));

      await waitFor(() => /コピーできませんでした/.test(query(t.main, '[role="status"]').textContent ?? ''));
      assert.deepEqual(t.clipboardWrites, []);
      assert.equal(t.doc.activeElement?.id, 'share-link');
      assert.equal(t.doc.getSelection()?.toString(), link, 'リンク全体が選択されている');
    });
  }

  it('「新規共有」で入力フォームに戻り、内容はクリアされる（前のリンクは残らない）', async () => {
    const { t, link } = await withLink();
    click(query(t.main, '[data-action="reset"]'));

    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '');
    assert.equal(query(t.main, '[data-testid="byte-count"]').textContent, '0 B / 10 MB');
    assert.equal(has(t.main, '[data-testid="share-link"]'), false);
    assert.equal((t.main.textContent ?? '').includes(link.split('#')[1] ?? '?'), false, '鍵が画面に残らない');
  });

  it('画面を破棄するとコピー表示のタイマーも止まり、DOM は空になる', async () => {
    const { t } = await withLink();
    click(query(t.main, '[data-action="copy"]'));
    await waitFor(() => t.clipboardWrites.length === 1);

    t.app.destroy();
    assert.doesNotThrow(() => t.runTimers());
    assert.equal(t.root.childNodes.length, 0);
  });
});
