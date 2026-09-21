/**
 * 送信画面（/）。
 *
 * 入力（メッセージ or ファイル）をブラウザ内で暗号化し、暗号文と IV だけをサーバーへ送る。
 * 復号鍵は共有リンクの `#` 以降にだけ載せ、サーバーには送らない（api.ts の関数は鍵を受け取れない）。
 */
import { ApiError } from '../api.ts';
import type { PayloadType } from '../api.ts';
import { CipherDropCryptoError, encryptData, encryptFile } from '../crypto.ts';
import { createDom, cx } from '../dom.ts';
import type { AppEnv, ViewHandle } from '../env.ts';
import { formatBytes, formatDateTime, formatRemaining } from '../format.ts';
import { createIcon } from '../icons.ts';
import type { IconName } from '../icons.ts';
import { DEFAULT_TTL_SECONDS, MAX_UPLOAD_BYTES, TTL_OPTIONS } from '../limits.ts';
import { button, notice, ui } from '../ui.ts';

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

export function mountSendView(env: AppEnv, container: HTMLElement): ViewHandle {
  const dom = createDom(env.doc);
  const state: { mode: Mode; text: string; file: File | null; ttlSeconds: number } = {
    mode: 'text',
    text: '',
    file: null,
    ttlSeconds: DEFAULT_TTL_SECONDS,
  };
  let phase: Phase = { name: 'editing', message: null };
  let submitButton: HTMLButtonElement | null = null;
  let pendingFocus: string | null = null;
  let feedbackTimer: unknown = null;
  let destroyed = false;

  // ---- 描画 -------------------------------------------------------------------------------

  function render(): void {
    submitButton = null;
    container.replaceChildren(...(phase.name === 'done' ? [resultCard(phase.result)] : [hero(), form(), assurances()]));
    if (pendingFocus !== null) {
      container.querySelector<HTMLElement>(pendingFocus)?.focus();
      pendingFocus = null;
    }
  }

  function hero(): HTMLElement {
    return dom.h(
      'section',
      { class: 'mb-8 text-center sm:mb-10' },
      dom.h('h1', { class: ui.h1 }, '大切な情報を、一度だけ、安全に。'),
      dom.h(
        'p',
        { class: cx(ui.lead, 'mx-auto mt-4 max-w-xl') },
        '暗号化はあなたのブラウザの中で完結します。サーバーは内容も鍵も見られず、相手が開くと同時に完全に消滅します。',
      ),
    );
  }

  function assurances(): HTMLElement {
    const items: Array<[IconName, string, string]> = [
      ['shield-check', 'AES-256-GCM で暗号化', 'ブラウザ標準の Web Crypto API だけで実行します。'],
      ['key', '鍵はサーバーに届かない', '復号鍵は共有リンクの # 以降にだけ含まれます。'],
      ['clock', '開封と同時に消滅', '期限切れの未開封データも自動で削除されます。'],
    ];
    return dom.h(
      'ul',
      { class: 'mt-8 grid gap-5 sm:grid-cols-3' },
      ...items.map(([icon, title, body]) =>
        dom.h(
          'li',
          { class: 'flex gap-3 sm:flex-col' },
          createIcon(dom, icon, 'size-6 text-accent'),
          dom.h('div', {}, dom.h('p', { class: 'text-sm font-semibold text-fg' }, title), dom.h('p', { class: 'mt-0.5 text-sm text-muted' }, body)),
        ),
      ),
    );
  }

  function form(): HTMLElement {
    const busy = phase.name === 'encrypting';
    const message = phase.name === 'editing' ? phase.message : null;

    submitButton = button(dom, {
      variant: 'primary',
      type: 'submit',
      action: 'submit',
      icon: busy ? 'spinner' : 'lock',
      busy,
      label: busy ? '暗号化しています…' : '暗号化して共有リンクを生成',
      disabled: busy || !canSubmit(),
    });

    const element = dom.h(
      'form',
      { class: ui.card, 'aria-busy': busy ? 'true' : 'false' },
      modeTabs(busy),
      dom.h(
        'div',
        { role: 'tabpanel', id: 'panel', 'aria-labelledby': `tab-${state.mode}`, class: 'mt-6' },
        state.mode === 'text' ? messageField(busy) : fileField(busy),
      ),
      expiryField(busy),
      message !== null &&
        dom.h(
          'div',
          { class: 'mt-6' },
          notice(dom, {
            tone: message.tone === 'danger' ? 'danger' : 'info',
            icon: message.tone === 'danger' ? 'alert' : 'check',
            title: message.text,
            role: message.tone === 'danger' ? 'alert' : 'status',
            autofocus: true,
          }),
        ),
      dom.h('div', { class: 'mt-6' }, submitButton),
      dom.h(
        'p',
        { class: 'mt-4 flex items-start gap-2 text-sm text-muted' },
        createIcon(dom, 'lock', 'mt-1 size-4'),
        '鍵は共有リンクの # 以降にのみ含まれ、サーバーには送信されません。',
      ),
    );
    element.addEventListener('submit', (event) => {
      event.preventDefault();
      void submit();
    });
    return element;
  }

  function modeTabs(disabled: boolean): HTMLElement {
    const tab = (mode: Mode, label: string, icon: IconName): HTMLElement => {
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
        createIcon(dom, icon, 'size-4'),
        label,
      );
    };
    return dom.h(
      'div',
      { role: 'tablist', 'aria-label': '共有する内容の種類', class: 'grid grid-cols-2 gap-1 rounded-xl border border-line bg-sunken p-1' },
      tab('text', 'メッセージ', 'message'),
      tab('file', 'ファイル', 'file'),
    );
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
      rows: 9,
      autocomplete: 'off',
      // ブラウザの綴りチェックは、入力内容を外部サービスへ送る実装がある。機密を扱う入力欄では無効にする。
      spellcheck: 'false',
      placeholder: 'パスワードや契約内容など、共有したい内容を入力してください',
      'aria-describedby': 'message-hint',
      disabled: busy,
      value: state.text,
      class: ui.textarea,
    });
    textarea.addEventListener('input', () => {
      state.text = textarea.value;
      updateSubmit();
    });
    return dom.h(
      'div',
      {},
      dom.h('label', { for: 'message', class: ui.label }, 'メッセージ'),
      textarea,
      dom.h('p', { id: 'message-hint', class: ui.hint }, `そのまま貼り付けられます。最大 ${formatBytes(MAX_UPLOAD_BYTES)}。`),
    );
  }

  function fileField(busy: boolean): HTMLElement {
    const input = dom.h('input', { type: 'file', id: 'file', class: 'sr-only', 'aria-describedby': 'file-hint', disabled: busy });
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
            createIcon(dom, 'upload', 'size-8 text-accent'),
            dom.h('span', { class: 'text-base font-semibold text-fg' }, 'ここにファイルをドラッグ＆ドロップ'),
            dom.h('span', { class: 'text-sm text-muted' }, 'またはクリックして選択'),
          ]
        : [
            createIcon(dom, 'file', 'size-8 text-accent'),
            dom.h('span', { class: 'max-w-full truncate text-base font-semibold text-fg', 'data-testid': 'selected-file-name' }, file.name),
            dom.h('span', { class: 'text-sm text-muted' }, `${formatBytes(file.size)} ・ クリックまたはドロップで変更`),
          ],
    );

    const highlight = (on: boolean): void => {
      for (const name of ui.dropzoneActive.split(' ')) zone.classList.toggle(name, on);
    };
    zone.addEventListener('dragenter', (event) => {
      event.preventDefault();
      if (!busy) highlight(true);
    });
    zone.addEventListener('dragover', (event) => {
      event.preventDefault(); // drop を受け付けるために必須
      if (!busy) highlight(true);
    });
    zone.addEventListener('dragleave', () => highlight(false));
    zone.addEventListener('drop', (event) => {
      event.preventDefault();
      highlight(false);
      if (busy) return;
      const files = (event as Event & { dataTransfer?: { files?: ArrayLike<File> } | null }).dataTransfer?.files;
      const first = files?.[0];
      if (first !== undefined) selectFile(first, (files?.length ?? 0) > 1);
    });

    return dom.h(
      'div',
      {},
      dom.h('span', { class: ui.label }, 'ファイル'),
      zone,
      dom.h('p', { id: 'file-hint', class: ui.hint }, `1 つのファイルを送れます。最大 ${formatBytes(MAX_UPLOAD_BYTES)}。ファイル名も暗号化されます。`),
      file !== null &&
        dom.h(
          'div',
          { class: 'mt-3' },
          button(dom, { variant: 'secondary', icon: 'x', label: '選択を解除', action: 'remove-file', disabled: busy, on: { click: removeFile } }),
        ),
    );
  }

  function expiryField(busy: boolean): HTMLElement {
    const options = TTL_OPTIONS.map(({ seconds, label }) => {
      const radio = dom.h('input', {
        type: 'radio',
        name: 'ttl',
        value: String(seconds),
        checked: state.ttlSeconds === seconds,
        disabled: busy,
        class: 'sr-only',
      });
      radio.addEventListener('change', () => {
        state.ttlSeconds = seconds;
      });
      return dom.h('label', { class: ui.radioCard }, radio, dom.h('span', {}, label));
    });
    return dom.h(
      'fieldset',
      { class: 'mt-6' },
      dom.h('legend', { class: ui.label }, '有効期限'),
      dom.h('div', { class: 'grid grid-cols-3 gap-2' }, ...options),
      dom.h('p', { class: ui.hint }, '期限を過ぎると、未開封でもサーバーから自動的に削除されます。'),
    );
  }

  function resultCard(result: Result): HTMLElement {
    // 1 行の入力欄だと長いリンクの後半（鍵の部分）が見えなくなる。折り返して全文を見せる（読み取り専用の textarea）。
    const input = dom.h('textarea', {
      id: 'share-link',
      readonly: true,
      rows: 3,
      spellcheck: 'false',
      autocomplete: 'off',
      value: result.url,
      class: 'block w-full resize-none rounded-xl border border-line-strong bg-sunken px-3 py-3 font-mono text-sm leading-relaxed text-fg [overflow-wrap:anywhere] focus:border-accent',
    });
    input.addEventListener('focus', () => input.select());

    const status = dom.h('p', { role: 'status', 'aria-live': 'polite', class: 'mt-2 min-h-6 text-sm text-ok' });
    const copyButton: HTMLButtonElement = button(dom, {
      variant: 'primary',
      icon: 'copy',
      label: COPY_LABEL,
      action: 'copy',
      on: { click: () => void copyLink(input, copyButton, status) },
    });

    const remaining = result.expiresAt.getTime() - env.now();
    const row = (label: string, value: string): HTMLElement =>
      dom.h('div', { class: ui.row }, dom.h('dt', { class: 'text-sm text-muted' }, label), dom.h('dd', { class: 'min-w-0 text-right text-sm font-medium text-fg [overflow-wrap:anywhere]' }, value));

    return dom.h(
      'section',
      { class: ui.card },
      dom.h(
        'div',
        { class: 'flex items-center gap-3' },
        dom.h('span', { class: 'grid size-10 shrink-0 place-items-center rounded-full bg-ok-bg text-ok ring-1 ring-ok-line' }, createIcon(dom, 'check', 'size-5')),
        dom.h('h2', { class: ui.h2, tabindex: -1, 'data-autofocus': 'true' }, '共有リンクを生成しました'),
      ),
      dom.h('p', { class: 'mt-3 text-muted' }, '下のリンクを相手に送ってください。相手がリンクを開いて「データを開く」を押すと、内容が表示されます。'),
      dom.h(
        'div',
        { class: 'mt-6' },
        dom.h('label', { for: 'share-link', class: ui.label }, '共有リンク'),
        input,
        dom.h('div', { class: 'mt-3' }, copyButton),
        status,
      ),
      dom.h(
        'dl',
        { class: 'mt-2 mb-6' },
        row('有効期限', `${formatDateTime(result.expiresAt)}（あと ${formatRemaining(remaining)}）`),
        row('内容', result.type === 'file' ? `ファイル: ${result.fileName ?? ''}（${formatBytes(result.size)}）` : 'メッセージ'),
      ),
      notice(
        dom,
        { tone: 'warn', icon: 'alert', title: 'このリンクは再表示できません' },
        dom.h('p', {}, '復号鍵はこのブラウザの中にしか存在せず、サーバーには保存されません。この画面を閉じる前に、必ずリンクをコピーして相手に共有してください。'),
      ),
      dom.h('div', { class: 'mt-6' }, button(dom, { variant: 'secondary', icon: 'upload', label: '新しく作成する', action: 'reset', on: { click: reset } })),
    );
  }

  // ---- 操作 -------------------------------------------------------------------------------

  function canSubmit(): boolean {
    if (phase.name === 'encrypting') return false;
    return state.mode === 'text' ? state.text.trim() !== '' : state.file !== null;
  }

  function updateSubmit(): void {
    if (submitButton !== null) submitButton.disabled = !canSubmit();
  }

  function selectFile(file: File, droppedMultiple = false): void {
    if (file.size === 0) return showFormMessage({ tone: 'danger', text: 'このファイルは空のため送信できません。' });
    if (file.size > MAX_UPLOAD_BYTES) {
      return showFormMessage({ tone: 'danger', text: `ファイルが大きすぎます（最大 ${formatBytes(MAX_UPLOAD_BYTES)}）。` });
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
        if (size > MAX_UPLOAD_BYTES) throw new UserFacingError(`メッセージが大きすぎます（最大 ${formatBytes(MAX_UPLOAD_BYTES)}）。`);
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

      const { id, expiresAt } = await env.api.createPayload({
        encryptedData: encrypted.encryptedData,
        iv: encrypted.iv,
        type,
        ttlSeconds,
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

  async function copyLink(input: HTMLTextAreaElement, copyButton: HTMLButtonElement, status: HTMLElement): Promise<void> {
    const label = copyButton.querySelector('[data-label]');
    try {
      if (env.clipboard === null) throw new Error('clipboard unavailable');
      await env.clipboard.writeText(input.value);
      status.className = 'mt-2 min-h-6 text-sm text-ok';
      status.textContent = 'リンクをコピーしました。';
      if (label !== null) label.textContent = 'コピーしました';
    } catch {
      input.focus();
      input.select();
      status.className = 'mt-2 min-h-6 text-sm text-danger';
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
        return `データが大きすぎます（最大 ${formatBytes(MAX_UPLOAD_BYTES)}）。`;
      case 'storage_full':
        return 'サーバーの保存領域が一時的に一杯です。しばらくしてから、もう一度お試しください。';
      case 'network':
        return 'サーバーに接続できませんでした。ネットワークを確認して、もう一度お試しください。';
      default:
        return 'サーバーとの通信でエラーが発生しました。しばらくしてから、もう一度お試しください。';
    }
  }
  if (error instanceof CipherDropCryptoError && error.code === 'WEBCRYPTO_UNAVAILABLE') {
    return 'このブラウザ環境では暗号化を実行できません。HTTPS（または localhost）で接続していることを確認してください。';
  }
  return '予期しないエラーが発生しました。もう一度お試しください。';
}
