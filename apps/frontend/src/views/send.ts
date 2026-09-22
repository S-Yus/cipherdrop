/**
 * 送信画面（/）。
 *
 * 入力（テキスト or ファイル）をブラウザ内で暗号化し、暗号文・IV・鍵確認値（任意）だけをサーバーへ送る。
 * 復号鍵は共有リンクの `#` 以降にだけ載せ、サーバーには送らない（api.ts の関数は鍵を受け取れない）。
 * 鍵確認値は鍵から一方向に導出した短いタグで、鍵そのものではない（crypto.ts の generateKeyCheckTag）。
 */
import { ApiError } from '../api.ts';
import type { PayloadType } from '../api.ts';
import { CipherDropCryptoError, encryptData, encryptFile, generateKeyCheckTag } from '../crypto.ts';
import { createDom, cx } from '../dom.ts';
import type { AppEnv, ViewHandle } from '../env.ts';
import { formatBytes, formatDateTime, formatRemaining } from '../format.ts';
import { createIcon } from '../icons.ts';
import { DEFAULT_TTL_SECONDS, MAX_UPLOAD_BYTES, TTL_OPTIONS } from '../limits.ts';
import { button, notice, statusBadge, ui } from '../ui.ts';

type Mode = 'text' | 'file';

interface Result {
  url: string;
  expiresAt: Date;
  type: PayloadType;
  fileName: string | null;
  size: number;
}

/** フォームの上に出す 1 件のメッセージ。danger は入力・通信の失敗、info は補足（操作は成功している）。 */
interface FormMessage {
  tone: 'danger' | 'info';
  text: string;
}

type Phase = { name: 'editing'; message: FormMessage | null } | { name: 'encrypting' } | { name: 'done'; result: Result };

const COPY_FEEDBACK_MS = 2_500;
const COPY_LABEL = 'リンクをコピー';
/** コピー結果の表示。空のときは高さを取らない（empty:mt-0）が、aria-live の領域としては常に存在させる。 */
const STATUS_OK = 'mt-2 text-sm text-emerald-400 empty:mt-0';
const STATUS_FAILED = 'mt-2 text-sm text-red-400 empty:mt-0';

export function mountSendView(env: AppEnv, container: HTMLElement): ViewHandle {
  const dom = createDom(env.doc);
  const state: { mode: Mode; text: string; textBytes: number; file: File | null; ttlSeconds: number } = {
    mode: 'text',
    text: '',
    textBytes: 0,
    file: null,
    ttlSeconds: DEFAULT_TTL_SECONDS,
  };
  let phase: Phase = { name: 'editing', message: null };
  let submitButton: HTMLButtonElement | null = null;
  let byteCounter: HTMLElement | null = null;
  let pendingFocus: string | null = null;
  let feedbackTimer: unknown = null;
  let destroyed = false;

  // ---- 描画 -------------------------------------------------------------------------------

  function render(): void {
    submitButton = null;
    byteCounter = null;
    container.replaceChildren(
      dom.h('div', { class: 'mb-4' }, statusBadge(dom, 'AES-256-GCM / Client-Side Encrypted')),
      ...(phase.name === 'done' ? [resultView(phase.result)] : [intro(), form()]),
    );
    if (pendingFocus !== null) {
      container.querySelector<HTMLElement>(pendingFocus)?.focus();
      pendingFocus = null;
    }
  }

  function intro(): HTMLElement {
    return dom.h(
      'div',
      { class: 'mb-5 space-y-2' },
      dom.h('h1', { class: ui.h1 }, '新規共有'),
      dom.h('p', { class: ui.sub }, 'URL ハッシュ（#）の復号鍵はサーバーに送信されません。取得後、サーバー上のデータは物理削除されます。'),
    );
  }

  function form(): HTMLElement {
    const busy = phase.name === 'encrypting';
    const message = phase.name === 'editing' ? phase.message : null;

    submitButton = button(dom, {
      variant: 'primary',
      type: 'submit',
      action: 'submit',
      busy,
      label: busy ? '暗号化中…' : '暗号化リンクを生成',
      disabled: busy || !canSubmit(),
    });

    const element = dom.h(
      'form',
      { class: ui.card, 'aria-busy': busy ? 'true' : 'false' },
      modeTabs(busy),
      dom.h('div', { role: 'tabpanel', id: 'panel', 'aria-labelledby': `tab-${state.mode}`, class: 'mt-4' }, state.mode === 'text' ? messageField(busy) : fileField(busy)),
      expiryField(busy),
      message !== null &&
        dom.h(
          'div',
          { class: 'mt-5' },
          notice(dom, {
            tone: message.tone === 'danger' ? 'danger' : 'info',
            ...(message.tone === 'danger' ? { icon: 'alert' as const } : {}),
            title: message.text,
            role: message.tone === 'danger' ? 'alert' : 'status',
            autofocus: true,
          }),
        ),
      dom.h('div', { class: 'mt-5' }, submitButton),
    );
    element.addEventListener('submit', (event) => {
      event.preventDefault();
      void submit();
    });
    return element;
  }

  function modeTabs(disabled: boolean): HTMLElement {
    const tab = (mode: Mode, label: string): HTMLElement => {
      const selected = state.mode === mode;
      return dom.h(
        'button',
        {
          type: 'button',
          role: 'tab',
          id: `tab-${mode}`,
          'aria-selected': selected ? 'true' : 'false',
          'aria-controls': 'panel',
          tabindex: selected ? 0 : -1,
          disabled,
          class: cx(ui.tabBase, selected ? ui.tabActive : ui.tabIdle),
          on: {
            click: () => switchMode(mode),
            keydown: (event) => onTabKeydown(event as KeyboardEvent),
          },
        },
        label,
      );
    };
    return dom.h('div', { role: 'tablist', 'aria-label': '共有する内容の種類', class: ui.tabList }, tab('text', 'テキスト'), tab('file', 'ファイル'));
  }

  function onTabKeydown(event: KeyboardEvent): void {
    const order: Mode[] = ['text', 'file'];
    const current = order.indexOf(state.mode);
    let next = current;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % order.length;
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current + order.length - 1) % order.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = order.length - 1;
    else return;

    event.preventDefault();
    switchMode(order[next] ?? 'text');
  }

  function switchMode(mode: Mode): void {
    if (mode === state.mode || phase.name === 'encrypting') return;
    state.mode = mode;
    phase = { name: 'editing', message: null };
    pendingFocus = '[role="tab"][aria-selected="true"]';
    render();
  }

  function messageField(busy: boolean): HTMLElement {
    const textarea = dom.h('textarea', {
      id: 'message',
      rows: 10,
      autocomplete: 'off',
      // ブラウザの綴りチェックは、入力内容を外部サービスへ送る実装がある。機密を扱う入力欄では無効にする。
      spellcheck: 'false',
      placeholder: '共有するテキストを入力',
      disabled: busy,
      value: state.text,
      class: ui.editor,
    });
    byteCounter = dom.h('span', { 'data-testid': 'byte-count', class: cx('font-mono', state.textBytes > MAX_UPLOAD_BYTES ? 'text-red-400' : 'text-zinc-400') }, describeBytes(state.textBytes));
    textarea.addEventListener('input', () => {
      state.text = textarea.value;
      state.textBytes = new TextEncoder().encode(state.text).byteLength;
      refreshEditorState();
    });
    return dom.h(
      'div',
      {},
      dom.h('label', { for: 'message', class: 'sr-only' }, '共有するテキスト'),
      textarea,
      dom.h('div', { class: cx('mt-1.5 flex items-center justify-between', ui.mutedMono) }, dom.h('span', {}, 'UTF-8'), byteCounter),
    );
  }

  function fileField(busy: boolean): HTMLElement {
    const input = dom.h('input', { type: 'file', id: 'file', class: 'sr-only', disabled: busy });
    input.addEventListener('change', () => {
      const file = input.files?.[0] ?? null;
      input.value = ''; // 同じファイルを選び直しても change が発火するように
      if (file !== null) selectFile(file);
    });

    const file = state.file;
    const zone = dom.h(
      'label',
      { class: ui.dropzone },
      input,
      file === null
        ? [
            dom.h('span', { class: 'text-sm text-zinc-200' }, 'ファイルをドロップ、またはクリックして選択'),
            dom.h('span', { class: ui.mutedMono }, `最大 ${formatBytes(MAX_UPLOAD_BYTES)} · ファイル名も暗号化`),
          ]
        : [
            dom.h('span', { class: 'max-w-full truncate font-mono text-sm text-zinc-100', 'data-testid': 'selected-file-name' }, file.name),
            dom.h('span', { class: ui.mutedMono }, `${formatBytes(file.size)} · クリックまたはドロップで変更`),
          ],
    );

    const setDragging = (on: boolean): void => {
      for (const name of ui.dropzoneActive.split(' ')) zone.classList.toggle(name, on);
      zone.classList.toggle(ui.dropzoneIdleBorder, !on);
    };
    zone.addEventListener('dragenter', (event) => {
      event.preventDefault();
      if (!busy) setDragging(true);
    });
    zone.addEventListener('dragover', (event) => {
      event.preventDefault(); // drop を受け付けるために必須
      if (!busy) setDragging(true);
    });
    zone.addEventListener('dragleave', () => setDragging(false));
    zone.addEventListener('drop', (event) => {
      event.preventDefault();
      setDragging(false);
      if (busy) return;
      const files = (event as Event & { dataTransfer?: { files?: ArrayLike<File> } | null }).dataTransfer?.files;
      const first = files?.[0];
      if (first !== undefined) selectFile(first, (files?.length ?? 0) > 1);
    });

    return dom.h(
      'div',
      {},
      dom.h('span', { class: 'sr-only' }, 'ファイル'),
      zone,
      file !== null &&
        dom.h('div', { class: 'mt-3' }, button(dom, { variant: 'secondary', label: '選択を解除', action: 'remove-file', disabled: busy, on: { click: removeFile } })),
    );
  }

  function expiryField(busy: boolean): HTMLElement {
    const select = dom.h(
      'select',
      { id: 'ttl', name: 'ttl', disabled: busy, class: ui.select },
      ...TTL_OPTIONS.map(({ seconds, label }) => dom.h('option', { value: String(seconds), selected: state.ttlSeconds === seconds }, label)),
    );
    select.addEventListener('change', () => {
      state.ttlSeconds = Number(select.value);
    });
    return dom.h(
      'div',
      { class: 'mt-5' },
      dom.h('div', { class: 'flex items-center justify-between gap-4' }, dom.h('label', { for: 'ttl', class: 'text-sm font-medium text-zinc-200' }, '有効期限'), select),
      dom.h('p', { class: 'mt-1.5 text-xs text-zinc-400' }, '期限を過ぎたデータは、未取得でも自動的に削除されます。'),
    );
  }

  function resultView(result: Result): HTMLElement {
    // 鍵（# 以降）を、それ以外の部分と視覚的に区別する。
    const hashAt = result.url.indexOf('#');
    const linkBlock = dom.h(
      'div',
      {
        id: 'share-link',
        role: 'group',
        'aria-labelledby': 'share-link-label',
        'data-testid': 'share-link',
        tabindex: 0,
        class: cx(ui.codeBlock, 'select-all'),
      },
      dom.h('span', { class: 'text-zinc-400' }, result.url.slice(0, hashAt)),
      dom.h('span', { 'data-testid': 'key-part', class: 'rounded-sm bg-emerald-500/10 text-emerald-400' }, result.url.slice(hashAt)),
    );

    const status = dom.h('p', { role: 'status', 'aria-live': 'polite', class: STATUS_OK });
    const copyButton: HTMLButtonElement = button(dom, {
      variant: 'primary',
      label: COPY_LABEL,
      action: 'copy',
      on: { click: () => void copyLink(result.url, linkBlock, copyButton, status) },
    });

    const remaining = result.expiresAt.getTime() - env.now();
    const row = (label: string, value: string, sub?: string): HTMLElement =>
      dom.h('div', { class: ui.row }, dom.h('dt', { class: ui.rowLabel }, label), dom.h('dd', { class: ui.rowValue }, value, sub !== undefined && dom.h('span', { class: ui.rowSub }, sub)));

    return dom.h(
      'section',
      { class: cx(ui.card, 'space-y-5') },
      dom.h(
        'div',
        { class: 'flex items-center gap-2' },
        createIcon(dom, 'check', 'size-4 text-emerald-500'),
        dom.h('h1', { class: ui.h1, tabindex: -1, 'data-autofocus': 'true' }, '共有リンクを生成しました'),
      ),
      dom.h(
        'div',
        {},
        dom.h('p', { id: 'share-link-label', class: ui.label }, '共有リンク'),
        linkBlock,
        dom.h(
          'p',
          { class: 'mt-2 text-xs leading-relaxed text-zinc-400' },
          dom.h('span', { class: 'font-mono text-emerald-400' }, '#'),
          ' 以降は復号鍵です。この鍵はサーバーを経由していません（ブラウザは # 以降を HTTP リクエストに含めません）。',
        ),
      ),
      dom.h('div', {}, copyButton, status),
      dom.h(
        'dl',
        {},
        row('有効期限', formatDateTime(result.expiresAt), `あと ${formatRemaining(remaining)}`),
        row('内容', result.type === 'file' ? `ファイル · ${result.fileName ?? ''} · ${formatBytes(result.size)}` : `テキスト · ${formatBytes(result.size)}`),
      ),
      notice(dom, { tone: 'warn', icon: 'alert', title: 'このリンクは再表示できません' }, dom.h('p', {}, '復号鍵はこのブラウザ内にのみ存在します。画面を閉じる前にコピーしてください。')),
      dom.h('div', {}, button(dom, { variant: 'secondary', label: '新規共有', action: 'reset', on: { click: reset } })),
    );
  }

  // ---- 操作 -------------------------------------------------------------------------------

  function describeBytes(bytes: number): string {
    return `${formatBytes(bytes)} / ${formatBytes(MAX_UPLOAD_BYTES)}${bytes > MAX_UPLOAD_BYTES ? ' 上限超過' : ''}`;
  }

  function canSubmit(): boolean {
    if (phase.name === 'encrypting') return false;
    return state.mode === 'text' ? state.text.trim() !== '' && state.textBytes <= MAX_UPLOAD_BYTES : state.file !== null;
  }

  /** 入力のたびに、バイト数の表示と送信ボタンの有効/無効だけを更新する（フォーム全体は再描画しない）。 */
  function refreshEditorState(): void {
    const over = state.textBytes > MAX_UPLOAD_BYTES;
    if (byteCounter !== null) {
      byteCounter.textContent = describeBytes(state.textBytes);
      byteCounter.classList.toggle('text-red-400', over);
      byteCounter.classList.toggle('text-zinc-400', !over);
    }
    if (submitButton !== null) submitButton.disabled = !canSubmit();
  }

  function selectFile(file: File, droppedMultiple = false): void {
    if (file.size === 0) return showFormMessage({ tone: 'danger', text: 'このファイルは空のため送信できません。' });
    if (file.size > MAX_UPLOAD_BYTES) {
      return showFormMessage({ tone: 'danger', text: `ファイルが上限（${formatBytes(MAX_UPLOAD_BYTES)}）を超えています。` });
    }

    state.file = file;
    if (droppedMultiple) {
      return showFormMessage({ tone: 'info', text: '複数のファイルは 1 つずつ送信してください。最初のファイルを選択しました。' });
    }
    phase = { name: 'editing', message: null };
    render();
  }

  function showFormMessage(message: FormMessage): void {
    phase = { name: 'editing', message };
    pendingFocus = '[data-autofocus]';
    render();
  }

  function removeFile(): void {
    state.file = null;
    phase = { name: 'editing', message: null };
    render();
  }

  async function submit(): Promise<void> {
    if (!canSubmit()) return;

    // 送信元は、状態を変える前に確定させる（途中で抜けて画面が「暗号化中」のまま固まることがないように）。
    const source =
      state.mode === 'text'
        ? ({ kind: 'text', text: state.text } as const)
        : state.file !== null
          ? ({ kind: 'file', file: state.file } as const)
          : null;
    if (source === null) return;
    const ttlSeconds = state.ttlSeconds;

    phase = { name: 'encrypting' };
    render();

    try {
      let encrypted;
      let type: PayloadType;
      let size: number;
      let fileName: string | null = null;

      if (source.kind === 'text') {
        size = new TextEncoder().encode(source.text).byteLength;
        if (size > MAX_UPLOAD_BYTES) throw new UserFacingError(`テキストが上限（${formatBytes(MAX_UPLOAD_BYTES)}）を超えています。`);
        encrypted = await encryptData(source.text);
        type = 'text';
      } else {
        let data: ArrayBuffer;
        try {
          data = await source.file.arrayBuffer();
        } catch {
          throw new UserFacingError('ファイルを読み込めませんでした。もう一度選択してください。');
        }
        size = data.byteLength;
        fileName = source.file.name;
        encrypted = await encryptFile({ name: fileName, data });
        type = 'file';
      }

      // 鍵確認値: 鍵から一方向に導出した短いタグ（鍵そのものではない）。受取画面が、コピペミス・
      // 途中欠損で違う内容になった鍵を、消費する前に検出するために使う。
      const keyCheck = await generateKeyCheckTag(encrypted.keyString);

      const { id, expiresAt } = await env.api.createPayload({
        encryptedData: encrypted.encryptedData,
        iv: encrypted.iv,
        type,
        ttlSeconds,
        keyCheck,
      });
      if (destroyed) return;

      // 鍵はここで初めて URL の # 以降に載る。api.ts を通っていないので、サーバーへ送られることはない。
      const url = `${env.location.origin}/v/${id}#${encrypted.keyString}`;
      phase = { name: 'done', result: { url, expiresAt, type, fileName, size } };
      pendingFocus = '[data-autofocus]';
    } catch (error) {
      if (destroyed) return;
      phase = { name: 'editing', message: { tone: 'danger', text: describeSendError(error) } };
      pendingFocus = '[data-autofocus]';
    }
    render();
  }

  /** リンク全体を選択状態にする（クリップボードが使えないとき、Ctrl+C でコピーできるように）。 */
  function selectContents(node: Node): void {
    const selection = env.doc.getSelection();
    if (selection === null) return;
    const range = env.doc.createRange();
    range.selectNodeContents(node);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  async function copyLink(url: string, linkBlock: HTMLElement, copyButton: HTMLButtonElement, status: HTMLElement): Promise<void> {
    const label = copyButton.querySelector('[data-label]');
    try {
      if (env.clipboard === null) throw new Error('clipboard unavailable');
      await env.clipboard.writeText(url);
      status.className = STATUS_OK;
      status.textContent = 'リンクをコピーしました。';
      if (label !== null) label.textContent = 'コピーしました';
    } catch {
      linkBlock.focus();
      selectContents(linkBlock);
      status.className = STATUS_FAILED;
      status.textContent = 'コピーできませんでした。リンクを選択したので、Ctrl+C（Mac は ⌘+C）でコピーしてください。';
    }

    if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
    feedbackTimer = env.setTimeout(() => {
      if (destroyed) return;
      if (label !== null) label.textContent = COPY_LABEL;
      status.textContent = '';
    }, COPY_FEEDBACK_MS);
  }

  function reset(): void {
    state.text = '';
    state.textBytes = 0;
    state.file = null;
    state.mode = 'text';
    phase = { name: 'editing', message: null };
    render();
  }

  render();
  return {
    destroy() {
      destroyed = true;
      if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
      container.replaceChildren();
    },
  };
}

/** 画面にそのまま出してよい（固定文言の）エラー。 */
class UserFacingError extends Error {}

/** 例外の message は表示しない（意図しない情報の露出を避け、固定文言だけを見せる）。 */
function describeSendError(error: unknown): string {
  if (error instanceof UserFacingError) return error.message;
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'payload_too_large':
        return `サイズが上限（${formatBytes(MAX_UPLOAD_BYTES)}）を超えています。`;
      case 'storage_full':
        return 'サーバーの保存領域が上限に達しています。時間をおいて再実行してください。';
      case 'network':
        return 'サーバーに接続できません。ネットワークを確認して再実行してください。';
      default:
        return 'サーバーとの通信でエラーが発生しました。時間をおいて再実行してください。';
    }
  }
  if (error instanceof CipherDropCryptoError && error.code === 'WEBCRYPTO_UNAVAILABLE') {
    return 'この環境では暗号化を実行できません。HTTPS（または localhost）で接続してください。';
  }
  return '予期しないエラーが発生しました。再実行してください。';
}
