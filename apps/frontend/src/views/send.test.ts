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

/** 送信ボタンを押し、リンクが表示されるまで待って、リンクを返す。 */
async function generateLink(t: Opened): Promise<string> {
  click(submitButton(t));
  const field = await waitFor(() => t.main.querySelector<HTMLTextAreaElement>('#share-link'));
  return field.value;
}

function choose(t: Opened, seconds: number): void {
  const radio = query<HTMLInputElement>(t.main, `input[name="ttl"][value="${seconds}"]`);
  radio.checked = true;
  radio.dispatchEvent(new t.window.Event('change', { bubbles: true }));
}

describe('送信画面: 初期表示', () => {
  it('見出し・タブ・入力欄・有効期限（24時間が既定）が表示され、入力が空の間は送信できない。API は呼ばない', () => {
    const t = open();
    assert.match(t.main.textContent ?? '', /大切な情報を、一度だけ、安全に。/);
    assert.equal(t.doc.title, 'CipherDrop — 一度だけ開ける、安全な共有');

    assert.equal(query(t.main, '#tab-text').getAttribute('aria-selected'), 'true');
    assert.equal(query(t.main, '#tab-file').getAttribute('aria-selected'), 'false');
    assert.equal(query<HTMLInputElement>(t.main, 'input[name="ttl"]:checked').value, '86400');
    assert.deepEqual([...t.main.querySelectorAll('input[name="ttl"]')].map((r) => r.parentElement?.textContent), ['1時間', '24時間', '7日間']);
    assert.equal(submitButton(t).disabled, true);
    assert.equal(t.calls.length, 0);
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

describe('送信画面: メッセージの送信', () => {
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

  it('選んだ有効期限（7日間）が TTL として送られる', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    choose(t, 604_800);
    await generateLink(t);

    const call = t.calls[0];
    assert.ok(call?.method === 'createPayload');
    assert.equal(call.args[0].ttlSeconds, 604_800);
  });

  it('生成後は、リンク・有効期限・「再表示できません」の警告を表示し、見出しにフォーカスが移る', async () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    await generateLink(t);

    const text = t.main.textContent ?? '';
    assert.match(text, /共有リンクを生成しました/);
    assert.match(text, /このリンクは再表示できません/);
    assert.match(text, /あと 1日/, '有効期限までの残り時間（24 時間ちょうどは日数表記）');
    assert.equal(has(t.main, '#message'), false, '入力フォームは消える');
    assert.equal(t.doc.activeElement?.tagName, 'H2', '状態の変化を支援技術に伝えるため見出しにフォーカスする');
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

    await waitFor(() => submitButton(t).textContent?.includes('暗号化しています'));
    assert.equal(submitButton(t).disabled, true);
    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').disabled, true);
    assert.equal(query(t.main, 'form').getAttribute('aria-busy'), 'true');

    release();
    await waitFor(() => has(t.main, '#share-link'));
  });

  it('メッセージに含まれる HTML は画面に要素として現れない（リンク表示のみ）', async () => {
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
    assert.equal(query(t.main, '[data-testid="selected-file-name"]').textContent, '山田太郎_診断書.pdf');
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
    assert.match(t.main.textContent ?? '', /ファイル: 山田太郎_診断書\.pdf（2\.9 KB）/);
  });

  it('空のファイルは選べない。大きすぎるファイル（上限 10 MB 超）も選べず、理由を表示する', () => {
    const t = open();
    click(query(t.main, '#tab-file'));

    dropFiles(dropzone(t), [makeFile('empty.txt', '')]);
    assert.match(query(t.main, '[role="alert"]').textContent ?? '', /空のため送信できません/);
    assert.equal(submitButton(t).disabled, true);

    dropFiles(dropzone(t), [{ name: 'big.bin', size: MAX_UPLOAD_BYTES + 1 } as File]);
    assert.match(query(t.main, '[role="alert"]').textContent ?? '', /大きすぎます（最大 10 MB）/);
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

  it('タブを切り替えても、入力済みのメッセージは失われない', () => {
    const t = open();
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '書きかけのメッセージ');
    click(query(t.main, '#tab-file'));
    click(query(t.main, '#tab-text'));
    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '書きかけのメッセージ');
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
    [new ApiError('network'), /サーバーに接続できませんでした/],
    [new ApiError('payload_too_large', 413), /データが大きすぎます（最大 10 MB）/],
    [new ApiError('storage_full', 503), /保存領域が一時的に一杯です/],
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
      typeInto(query<HTMLTextAreaElement>(t.main, '#message'), '大事なメッセージ');
      click(submitButton(t));

      const alert = await waitFor(() => t.main.querySelector('[role="alert"]'));
      assert.match(alert.textContent ?? '', expected);
      assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '大事なメッセージ', '入力は失われない');
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

describe('送信画面: リンクのコピーと再作成', () => {
  async function withLink(options: TestEnvOptions = {}) {
    const t = open(options);
    typeInto(query<HTMLTextAreaElement>(t.main, '#message'), 'x');
    const link = await generateLink(t);
    return { t, link };
  }

  it('コピーすると、リンク全体（鍵を含む）がクリップボードへ書かれ、一定時間後に表示が戻る', async () => {
    const { t, link } = await withLink();
    const copy = query(t.main, '[data-action="copy"]');

    click(copy);
    await waitFor(() => t.clipboardWrites.length === 1);
    assert.deepEqual(t.clipboardWrites, [link]);
    assert.match(copy.textContent ?? '', /コピーしました/);
    assert.match(query(t.main, '[role="status"]').textContent ?? '', /コピーしました/);

    t.runTimers();
    assert.match(copy.textContent ?? '', /リンクをコピー/);
    assert.equal(query(t.main, '[role="status"]').textContent, '');
  });

  for (const mode of ['fail', 'none'] as const) {
    it(`クリップボードが使えない（${mode}）ときは、リンクを選択状態にして手動コピーを案内する`, async () => {
      const { t } = await withLink({ clipboard: mode });
      click(query(t.main, '[data-action="copy"]'));

      await waitFor(() => /コピーできませんでした/.test(query(t.main, '[role="status"]').textContent ?? ''));
      assert.deepEqual(t.clipboardWrites, []);
      assert.equal(t.doc.activeElement?.id, 'share-link');
    });
  }

  it('「新しく作成する」で入力フォームに戻り、内容はクリアされる（前のリンクは残らない）', async () => {
    const { t, link } = await withLink();
    click(query(t.main, '[data-action="reset"]'));

    assert.equal(query<HTMLTextAreaElement>(t.main, '#message').value, '');
    assert.equal(has(t.main, '#share-link'), false);
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
