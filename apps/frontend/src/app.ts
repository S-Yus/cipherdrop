/**
 * CipherDrop の画面（送信・受信）。
 *
 *   /            送信: ブラウザ内で暗号化 → 暗号文と IV だけを POST → 共有リンク（鍵は # 以降）を表示
 *   /v/{id}#key  受信: 鍵を URL から取り出してすぐ消す →「表示する」を押したときだけ取得（＝サーバー側で削除）→ 復号
 *
 * DOM への描画はすべて textContent / createElement で行う（HTML として解釈する API は使用禁止。
 * tests/security-policy.test.ts が検査し、本番では CSP の Trusted Types でも止まる）。
 */
import { base64UrlDecode, base64UrlEncode, CipherDropCryptoError, decryptData, encryptData, renderTextSafely } from './crypto.ts';
import { packFile, safeFileName, unpackFile } from './envelope.ts';

const HEADER_IV = 'X-CipherDrop-IV';
const HEADER_TTL = 'X-CipherDrop-TTL';
/** サーバーの既定上限（10 MiB）。暗号化のオーバーヘッドを見込んで、ファイルは少し手前で止める。 */
const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const MAX_FILE_BYTES = MAX_PAYLOAD_BYTES - 8 * 1024;
const VIEW_PATH = /^\/v\/([A-Za-z0-9_-]{22})$/;

type View = 'compose' | 'created' | 'reveal' | 'result' | 'failure';
const VIEWS: readonly View[] = ['compose', 'created', 'reveal', 'result', 'failure'];

function element<T extends HTMLElement>(id: string, type: new () => T): T {
  const found = document.getElementById(id);
  if (!(found instanceof type)) throw new Error(`Missing element #${id}`);
  return found;
}

function show(view: View): void {
  for (const name of VIEWS) element(name, HTMLElement).hidden = name !== view;
}

function fail(message: string): void {
  element('failure-message', HTMLElement).textContent = message;
  show('failure');
}

function setStatus(id: string, message: string): void {
  element(id, HTMLElement).textContent = message;
}

async function copyText(text: string, button: HTMLButtonElement): Promise<void> {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'コピーしました';
  } catch {
    button.textContent = 'コピーできませんでした';
  }
  setTimeout(() => {
    button.textContent = original;
  }, 2000);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function errorMessageForStatus(status: number): string {
  switch (status) {
    case 404:
      return 'このリンクは既に開封済みか、有効期限が切れているか、存在しません。内容はサーバーから削除されています。';
    case 413:
      return 'サイズが大きすぎます（上限 10 MB）。';
    case 429:
      return '短時間にリクエストが集中しています。しばらく待ってからもう一度お試しください。';
    case 503:
      return 'サーバーの保存容量が一時的にいっぱいです。しばらく待ってからもう一度お試しください。';
    default:
      return `サーバーとの通信に失敗しました（${status}）。時間をおいてもう一度お試しください。`;
  }
}

// ---------------------------------------------------------------------------
// 送信
// ---------------------------------------------------------------------------

function setupCompose(): void {
  const form = element('compose-form', HTMLFormElement);
  const textTab = element('tab-text', HTMLButtonElement);
  const fileTab = element('tab-file', HTMLButtonElement);
  const textPanel = element('panel-text', HTMLElement);
  const filePanel = element('panel-file', HTMLElement);
  const textarea = element('message', HTMLTextAreaElement);
  const fileInput = element('file', HTMLInputElement);
  const fileInfo = element('file-info', HTMLElement);
  const ttl = element('ttl', HTMLSelectElement);
  const submit = element('submit', HTMLButtonElement);
  let mode: 'text' | 'file' = 'text';

  const selectMode = (next: 'text' | 'file'): void => {
    mode = next;
    textTab.setAttribute('aria-selected', String(next === 'text'));
    fileTab.setAttribute('aria-selected', String(next === 'file'));
    textPanel.hidden = next !== 'text';
    filePanel.hidden = next !== 'file';
    setStatus('compose-status', '');
  };
  textTab.addEventListener('click', () => selectMode('text'));
  fileTab.addEventListener('click', () => selectMode('file'));

  fileInput.addEventListener('change', () => {
    const file = fileInput.files?.[0];
    fileInfo.textContent = file === undefined ? '' : `${file.name}（${formatBytes(file.size)}）`;
    setStatus('compose-status', file !== undefined && file.size > MAX_FILE_BYTES ? 'ファイルが大きすぎます（上限 約 10 MB）。' : '');
  });

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void (async () => {
      let payload: string | ArrayBuffer;
      if (mode === 'text') {
        if (textarea.value === '') return setStatus('compose-status', 'メッセージを入力してください。');
        payload = textarea.value;
      } else {
        const file = fileInput.files?.[0];
        if (file === undefined) return setStatus('compose-status', 'ファイルを選択してください。');
        if (file.size > MAX_FILE_BYTES) return setStatus('compose-status', 'ファイルが大きすぎます（上限 約 10 MB）。');
        payload = packFile(file.name, file.type, new Uint8Array(await file.arrayBuffer()));
      }

      submit.disabled = true;
      setStatus('compose-status', 'ブラウザ内で暗号化しています…');
      try {
        const { encryptedData, iv, keyString } = await encryptData(payload);
        if (encryptedData.byteLength > MAX_PAYLOAD_BYTES) return setStatus('compose-status', errorMessageForStatus(413));

        setStatus('compose-status', '暗号文を送信しています…');
        const response = await fetch('/api/payload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/octet-stream', [HEADER_IV]: base64UrlEncode(iv), [HEADER_TTL]: ttl.value },
          body: encryptedData,
          cache: 'no-store',
          credentials: 'omit',
          referrerPolicy: 'no-referrer',
        });
        if (response.status !== 201) return setStatus('compose-status', errorMessageForStatus(response.status));

        const { id, expiresAt } = (await response.json()) as { id: string; expiresAt: string };
        showCreated(`${location.origin}/v/${id}#${keyString}`, new Date(expiresAt));
        textarea.value = '';
        fileInput.value = '';
        fileInfo.textContent = '';
        setStatus('compose-status', '');
      } catch (error) {
        setStatus(
          'compose-status',
          error instanceof CipherDropCryptoError && error.code === 'WEBCRYPTO_UNAVAILABLE'
            ? 'このブラウザでは暗号化を利用できません（HTTPS でアクセスしてください）。'
            : '送信に失敗しました。通信環境を確認して、もう一度お試しください。',
        );
      } finally {
        submit.disabled = false;
      }
    })();
  });

  element('again', HTMLButtonElement).addEventListener('click', () => {
    element('share-url', HTMLInputElement).value = '';
    show('compose');
  });

  show('compose');
}

function showCreated(shareUrl: string, expiresAt: Date): void {
  const input = element('share-url', HTMLInputElement);
  input.value = shareUrl;
  element('expires-at', HTMLElement).textContent = expiresAt.toLocaleString('ja-JP', { dateStyle: 'medium', timeStyle: 'short' });
  show('created');
  input.focus();
  input.select();
}

// ---------------------------------------------------------------------------
// 受信
// ---------------------------------------------------------------------------

function setupView(id: string): void {
  // 鍵はメモリにだけ持ち、アドレスバーと履歴からはすぐに消す（画面の覗き見・履歴・同期からの漏洩対策）。
  const keyString = location.hash.slice(1);
  history.replaceState(null, '', location.pathname);

  if (base64UrlDecode(keyString)?.byteLength !== 32) {
    return fail('リンクが不完全です。# 以降を含めた URL 全体をコピーして開いてください。');
  }

  const reveal = element('reveal-button', HTMLButtonElement);
  show('reveal');

  // リンクプレビューやスキャナーに消費されないよう、取得は利用者が押したときだけ行う。
  reveal.addEventListener('click', () => {
    void (async () => {
      reveal.disabled = true;
      setStatus('reveal-status', '取得しています…');
      try {
        const response = await fetch(`/api/payload/${id}`, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
        if (response.status !== 200) return fail(errorMessageForStatus(response.status));

        const iv = base64UrlDecode(response.headers.get(HEADER_IV) ?? '');
        if (iv === null) return fail('サーバーからの応答が不正です。');

        let plain: string | ArrayBuffer;
        try {
          plain = await decryptData(await response.arrayBuffer(), iv, keyString);
        } catch {
          return fail('復号できませんでした。リンクが正しくないか、データが改ざんされています。内容はサーバーから既に削除されています。');
        }
        showResult(plain);
      } catch {
        fail('通信が途中で切れました。内容はサーバーから既に削除されている可能性があります。');
      } finally {
        reveal.disabled = false;
        setStatus('reveal-status', '');
      }
    })();
  });
}

function showResult(plain: string | ArrayBuffer): void {
  const textBox = element('result-text', HTMLElement);
  const fileBox = element('result-file', HTMLElement);

  if (typeof plain === 'string') {
    renderTextSafely(element('result-message', HTMLElement), plain);
    element('copy-message', HTMLButtonElement).addEventListener('click', (event) => {
      void copyText(plain, event.currentTarget as HTMLButtonElement);
    });
    textBox.hidden = false;
    fileBox.hidden = true;
  } else {
    const file = unpackFile(plain);
    const name = safeFileName(file?.name ?? '');
    const bytes = file?.bytes ?? new Uint8Array(plain);
    element('result-file-name', HTMLElement).textContent = `${name}（${formatBytes(bytes.byteLength)}）`;

    // MIME タイプは送信者が自由に決められるので使わない。octet-stream にしてブラウザに描画させない。
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const link = element('download', HTMLAnchorElement);
    link.href = url;
    link.download = name;
    textBox.hidden = true;
    fileBox.hidden = false;
  }
  show('result');
}

// ---------------------------------------------------------------------------

function main(): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-copy-target]')) {
    button.addEventListener('click', () => {
      const target = document.getElementById(button.dataset['copyTarget'] ?? '');
      if (target instanceof HTMLInputElement) void copyText(target.value, button);
    });
  }

  const id = VIEW_PATH.exec(location.pathname)?.[1];
  if (id !== undefined) setupView(id);
  else setupCompose();
}

main();
