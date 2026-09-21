/**
 * 受取・復号画面（/v/:id#key）。2 段階で取得する。
 *
 *   Stage 1 確認  ページ読み込み時に GET …/meta を呼ぶ。何も消費しない。「開くと消滅する」警告を出して待つ。
 *   Stage 2 消費  受信者が「開く」ボタンを押したときだけ POST …/consume を呼ぶ。復号して表示（またはダウンロード）する。
 *
 * これにより、リンクプレビュー・クローラー・セキュリティスキャナがこのページを開いても、データは消えない。
 * 復号後のテキストは renderTextSafely（テキストノード）でだけ描画し、HTML としては一切解釈しない。
 */
import { ApiError } from '../api.ts';
import type { PayloadMeta } from '../api.ts';
import { decryptPayload, isValidKeyString, renderTextSafely } from '../crypto.ts';
import type { DecryptedPayload } from '../crypto.ts';
import { createDom, cx } from '../dom.ts';
import type { Children } from '../dom.ts';
import type { AppEnv, ViewHandle } from '../env.ts';
import { FALLBACK_FILE_NAME, hasRiskyExtension, sanitizeFileName } from '../file-name.ts';
import { formatBytes, formatDateTime, formatRemaining } from '../format.ts';
import { createIcon } from '../icons.ts';
import { button, notice, ui } from '../ui.ts';

type Phase =
  | { name: 'loading' }
  | { name: 'invalid-link' }
  | { name: 'unavailable' }
  | { name: 'load-error' }
  | { name: 'confirm'; meta: PayloadMeta }
  | { name: 'opening'; meta: PayloadMeta }
  | { name: 'open-error'; meta: PayloadMeta }
  | { name: 'decrypt-failed' }
  | { name: 'text'; text: string }
  | { name: 'file'; fileName: string; size: number; data: ArrayBuffer; risky: boolean; saveFailed: boolean };

const COPY_FEEDBACK_MS = 2_500;

export function mountReceiveView(env: AppEnv, container: HTMLElement, route: { id: string | null }): ViewHandle {
  const dom = createDom(env.doc);
  const id = route.id;
  // 鍵はページ内のメモリにだけ置く。サーバーへ送る経路はない（api.ts の関数は鍵を受け取れない）。
  let keyString = env.location.hash.startsWith('#') ? env.location.hash.slice(1) : '';
  // リンクが不完全なら、暗号文を「消費する前に」止める。形式不正の鍵で開くと、データだけが失われる。
  let phase: Phase = id !== null && isValidKeyString(keyString) ? { name: 'loading' } : { name: 'invalid-link' };
  let pendingFocus: string | null = null;
  let feedbackTimer: unknown = null;
  let destroyed = false;

  // ---- 描画 -------------------------------------------------------------------------------

  function render(): void {
    container.replaceChildren(card(), dom.h('p', { class: 'mt-6 text-center' }, dom.h('a', { href: '/', class: 'text-sm font-semibold text-accent underline underline-offset-4' }, 'CipherDrop で新しく共有する')));
    if (pendingFocus !== null) {
      container.querySelector<HTMLElement>(pendingFocus)?.focus();
      pendingFocus = null;
    }
  }

  function heading(text: string): HTMLElement {
    return dom.h('h2', { class: ui.h2, tabindex: -1, 'data-autofocus': 'true' }, text);
  }

  function section(...children: Children): HTMLElement {
    return dom.h('section', { class: cx(ui.card, 'space-y-6') }, ...children);
  }

  function card(): HTMLElement {
    switch (phase.name) {
      case 'loading':
        return loadingCard();
      case 'invalid-link':
        return messageCard('danger', 'リンクが正しくありません', [
          '共有リンクの後半（鍵の部分）が欠けているか、余分な文字が含まれています。メールやチャットでの折り返し・句読点の付加が原因のことがあります。',
          '送信者にリンクの再送を依頼してください。このリンクではデータを開いていないため、正しいリンクがあれば開けます。',
        ]);
      case 'unavailable':
        return messageCard('warn', 'このリンクは無効です', [
          'すでに開封された、有効期限が切れた、またはリンクが正しくない可能性があります。',
          'データは一度開くとサーバーから削除されます。送信者に新しいリンクの発行を依頼してください。',
        ]);
      case 'load-error':
        return messageCard('danger', 'サーバーに接続できませんでした', ['ネットワークを確認して、もう一度お試しください。'], {
          label: 'もう一度確認する',
          action: 'retry',
          onClick: () => void load(),
        });
      case 'open-error': {
        const { meta } = phase;
        return messageCard(
          'danger',
          'データを取得できませんでした',
          ['通信に失敗しました。通信の途中で切断された場合、データはすでに消滅している可能性があります。'],
          { label: 'もう一度試す', action: 'retry-open', onClick: () => void open(meta) },
        );
      }
      case 'decrypt-failed':
        return messageCard('danger', 'データを復号できませんでした', [
          'データは取得されましたが、復号に失敗しました。リンクの鍵が正しくないか、データが改ざんされた可能性があります。',
          'このデータはすでにサーバーから削除されています。送信者に再送を依頼してください。',
        ]);
      case 'confirm':
      case 'opening':
        return confirmCard(phase.meta, phase.name === 'opening');
      case 'text':
        return textCard(phase.text);
      case 'file':
        return fileCard(phase);
    }
  }

  function loadingCard(): HTMLElement {
    const bar = (width: string): HTMLElement => dom.h('div', { class: cx('h-5 rounded-md bg-sunken motion-safe:animate-pulse', width) });
    return section(
      dom.h('div', { role: 'status', class: 'space-y-4' }, dom.h('span', { class: 'sr-only' }, '共有データを確認しています…'), bar('w-1/3'), bar('w-2/3'), bar('w-full'), bar('w-5/6')),
    );
  }

  function messageCard(
    tone: 'danger' | 'warn',
    title: string,
    paragraphs: string[],
    action?: { label: string; action: string; onClick: () => void },
  ): HTMLElement {
    return section(
      notice(dom, { tone, icon: 'alert', title, role: 'alert', autofocus: true }, ...paragraphs.map((text) => dom.h('p', {}, text))),
      action &&
        button(dom, { variant: 'secondary', label: action.label, action: action.action, on: { click: action.onClick } }),
    );
  }

  /** Stage 1: 確認。警告を出し、受信者が押すまで何も消費しない。 */
  function confirmCard(meta: PayloadMeta, opening: boolean): HTMLElement {
    const isFile = meta.type === 'file';
    const remaining = meta.expiresAt.getTime() - env.now();
    const row = (label: string, value: string): HTMLElement =>
      dom.h('div', { class: ui.row }, dom.h('dt', { class: 'text-sm text-muted' }, label), dom.h('dd', { class: 'text-right text-sm font-medium text-fg' }, value));

    return section(
      dom.h(
        'div',
        { class: 'space-y-2' },
        dom.h('p', { class: 'text-sm font-semibold text-accent' }, '共有されたデータが届いています'),
        // サーバーの種別ヒントは表示だけに使う（実際の種別は復号後に確定する）。
        dom.h('h2', { class: ui.h2, tabindex: -1, 'data-autofocus': 'true' }, isFile ? 'ファイルを受け取る' : 'メッセージを受け取る'),
      ),
      dom.h(
        'dl',
        {},
        row('種類', isFile ? 'ファイル' : 'テキストメッセージ'),
        row('サイズ', formatBytes(meta.size)),
        row('有効期限', `${formatDateTime(meta.expiresAt)}（あと ${formatRemaining(remaining)}）`),
      ),
      notice(
        dom,
        { tone: 'warn', icon: 'alert', title: 'このデータは一度開くとサーバーから永久に消滅します' },
        dom.h('p', {}, `「${isFile ? 'ファイルをダウンロード' : 'データを開く'}」を押した瞬間に、サーバー上のデータは完全に削除され、二度と取得できません。`),
        dom.h(
          'ul',
          { class: 'list-disc space-y-1 pl-5' },
          dom.h('li', {}, '開いた内容は、この画面にだけ表示されます。'),
          dom.h('li', {}, '同じリンクを他の人に送っても、開けるのは最初の 1 回だけです。'),
          dom.h('li', {}, 'プレビューしただけでは消えません。準備ができてから押してください。'),
        ),
      ),
      button(dom, {
        variant: 'primary',
        action: 'open',
        icon: opening ? 'spinner' : isFile ? 'download' : 'key',
        busy: opening,
        label: opening ? '取得して復号しています…' : isFile ? 'ファイルをダウンロード' : 'データを開く',
        disabled: opening,
        on: { click: () => void open(meta) },
      }),
    );
  }

  /** Stage 2 の結果（テキスト）。renderTextSafely でテキストノードとしてだけ描画する。 */
  function textCard(text: string): HTMLElement {
    const output = dom.h('pre', {
      role: 'region',
      'aria-label': 'メッセージの内容',
      tabindex: 0,
      'data-testid': 'decrypted-text',
      class: 'max-h-[60vh] overflow-auto rounded-xl border border-line-strong bg-sunken p-4 font-sans text-base leading-relaxed text-fg whitespace-pre-wrap [overflow-wrap:anywhere]',
    });
    renderTextSafely(output, text);

    const copyButton: HTMLButtonElement = button(dom, {
      variant: 'secondary',
      icon: 'copy',
      label: 'テキストをコピー',
      action: 'copy-text',
      on: { click: () => void copyText(text, copyButton) },
    });

    return section(
      dom.h('div', { class: 'flex items-center gap-3' }, createIcon(dom, 'check', 'size-6 text-ok'), heading('メッセージを受け取りました')),
      output,
      dom.h('div', {}, copyButton),
      deletedNotice(),
    );
  }

  /** Stage 2 の結果（ファイル）。ダウンロードするだけで、アプリの画面内では開かない。 */
  function fileCard(file: Extract<Phase, { name: 'file' }>): HTMLElement {
    return section(
      dom.h('div', { class: 'flex items-center gap-3' }, createIcon(dom, 'check', 'size-6 text-ok'), heading('ファイルを受け取りました')),
      dom.h(
        'div',
        { class: 'flex items-center gap-4 rounded-xl border border-line-strong bg-sunken p-4' },
        createIcon(dom, 'file', 'size-8 text-accent'),
        dom.h(
          'div',
          { class: 'min-w-0' },
          dom.h('p', { class: 'font-semibold text-fg [overflow-wrap:anywhere]', 'data-testid': 'received-file-name' }, file.fileName),
          dom.h('p', { class: 'text-sm text-muted' }, formatBytes(file.size)),
        ),
      ),
      file.saveFailed
        ? notice(dom, { tone: 'warn', icon: 'alert', title: '自動でダウンロードできませんでした', role: 'alert' }, dom.h('p', {}, '下のボタンで保存してください。'))
        : dom.h('p', { role: 'status', class: 'text-sm text-ok' }, 'ダウンロードを開始しました。'),
      file.risky &&
        notice(
          dom,
          { tone: 'warn', icon: 'alert', title: '実行ファイルやスクリプトの可能性があります' },
          dom.h('p', {}, '送信元が信頼できる場合にのみ開いてください。心当たりのないファイルは開かずに削除してください。'),
        ),
      dom.h('div', {}, button(dom, { variant: 'secondary', icon: 'download', label: 'もう一度ダウンロード', action: 'download-again', on: { click: () => saveAgain(file) } })),
      deletedNotice(),
    );
  }

  function deletedNotice(): HTMLElement {
    return notice(
      dom,
      { tone: 'info', icon: 'shield-check', title: 'このデータはサーバーから削除されました' },
      dom.h('p', {}, 'この画面を閉じると、もう一度開くことはできません。必要な内容は今のうちに控えてください。'),
    );
  }

  // ---- 操作 -------------------------------------------------------------------------------

  /** Stage 1: メタ情報を取得する。何も消費しない。 */
  async function load(): Promise<void> {
    if (id === null) return;
    phase = { name: 'loading' };
    render();
    try {
      const meta = await env.api.getMeta(id);
      if (destroyed) return;
      phase = { name: 'confirm', meta };
    } catch (error) {
      if (destroyed) return;
      phase = error instanceof ApiError && error.code === 'not_found' ? { name: 'unavailable' } : { name: 'load-error' };
    }
    pendingFocus = '[data-autofocus]';
    render();
  }

  /** Stage 2: 受信者が明示的にボタンを押したときだけ呼ばれる。取得（＝サーバー側で削除）して復号する。 */
  async function open(meta: PayloadMeta): Promise<void> {
    if (id === null || phase.name === 'opening') return;
    phase = { name: 'opening', meta };
    render();

    let consumed: { encryptedData: ArrayBuffer; iv: Uint8Array };
    try {
      consumed = await env.api.consume(id);
    } catch (error) {
      if (destroyed) return;
      phase = error instanceof ApiError && error.code === 'not_found' ? { name: 'unavailable' } : { name: 'open-error', meta };
      pendingFocus = '[data-autofocus]';
      render();
      return;
    }
    if (destroyed) return;

    // ここから先、サーバーの暗号文は消滅済み。アドレスバーから鍵を消す（履歴・画面共有・URL のコピーに残さない）。
    env.history.replaceState(null, '', env.location.pathname);

    try {
      phase = present(await decryptPayload(consumed.encryptedData, consumed.iv, keyString));
    } catch {
      phase = { name: 'decrypt-failed' };
    } finally {
      keyString = ''; // 用済みの鍵をこのビューから手放す
    }
    pendingFocus = '[data-autofocus]';
    render();
  }

  /** 復号結果から表示を決める。分岐にはサーバーの種別ヒントではなく、復号後（認証済み）の type を使う。 */
  function present(payload: DecryptedPayload): Phase {
    if (payload.type === 'text') return { name: 'text', text: payload.text };

    const fileName = sanitizeFileName(payload.type === 'file' ? payload.name : FALLBACK_FILE_NAME);
    let saveFailed = false;
    try {
      env.saveFile(fileName, payload.data);
    } catch {
      saveFailed = true;
    }
    return { name: 'file', fileName, size: payload.data.byteLength, data: payload.data, risky: hasRiskyExtension(fileName), saveFailed };
  }

  function saveAgain(file: Extract<Phase, { name: 'file' }>): void {
    try {
      env.saveFile(file.fileName, file.data);
    } catch {
      // 失敗しても、画面はそのまま（ボタンをもう一度押せる）
    }
  }

  async function copyText(text: string, copyButton: HTMLButtonElement): Promise<void> {
    const label = copyButton.querySelector('[data-label]');
    try {
      if (env.clipboard === null) throw new Error('clipboard unavailable');
      await env.clipboard.writeText(text);
      if (label !== null) label.textContent = 'コピーしました';
    } catch {
      if (label !== null) label.textContent = 'コピーできませんでした（手動で選択してください）';
    }
    if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
    feedbackTimer = env.setTimeout(() => {
      if (!destroyed && label !== null) label.textContent = 'テキストをコピー';
    }, COPY_FEEDBACK_MS);
  }

  render();
  if (phase.name === 'loading') void load();

  return {
    destroy() {
      destroyed = true;
      if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
      container.replaceChildren();
    },
  };
}
