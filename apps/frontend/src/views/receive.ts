/**
 * 受取・復号画面（/v/:id#key）。2 段階で取得する。
 *
 *   Stage 1 確認  ページ読み込み時に GET …/meta を呼ぶ。何も消費しない。「開くと削除される」ことを示して待つ。
 *   Stage 2 消費  受信者が実行ボタンを押したときだけ POST …/consume を呼ぶ。復号して表示（またはダウンロード）する。
 *
 * これにより、リンクプレビュー・クローラー・セキュリティスキャナがこのページを開いても、データは消えない。
 * 復号後のテキストは renderTextSafely（テキストノード）でだけ描画し、HTML としては一切解釈しない。
 *
 * Stage 1 では、URL の鍵の形式検証（isValidKeyString）に加えて、meta.keyCheck があればローカルで
 * 計算した確認値と照合する（keyCheckMismatch）。不一致なら「開く」ボタン自体を描画せず、POST consume を
 * 発行する手段を作らない。コピペミス・途中欠損で「形式は正しいが内容が違う」鍵によって、消費（＝サーバー
 * 側の物理削除）だけが先に起きてデータが失われる事故を防ぐ。
 */
import { ApiError } from '../api.ts';
import type { PayloadMeta } from '../api.ts';
import { decryptPayload, generateKeyCheckTag, isValidKeyString, renderTextSafely } from '../crypto.ts';
import type { DecryptedPayload } from '../crypto.ts';
import { createDom, cx } from '../dom.ts';
import type { Children } from '../dom.ts';
import type { AppEnv, ViewHandle } from '../env.ts';
import { FALLBACK_FILE_NAME, hasRiskyExtension, sanitizeFileName } from '../file-name.ts';
import { formatBytes, formatDateTime, formatRemaining } from '../format.ts';
import { button, notice, ui } from '../ui.ts';

type Phase =
  | { name: 'loading' }
  | { name: 'invalid-link' }
  | { name: 'unavailable' }
  | { name: 'load-error' }
  | { name: 'key-mismatch' }
  | { name: 'confirm'; meta: PayloadMeta }
  | { name: 'opening'; meta: PayloadMeta }
  | { name: 'open-error'; meta: PayloadMeta }
  | { name: 'decrypt-failed' }
  | { name: 'text'; text: string }
  | { name: 'file'; fileName: string; size: number; data: ArrayBuffer; risky: boolean; saveFailed: boolean }
  | { name: 'discarded' };

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
    container.replaceChildren(card());
    if (pendingFocus !== null) {
      container.querySelector<HTMLElement>(pendingFocus)?.focus();
      pendingFocus = null;
    }
  }

  function heading(text: string): HTMLElement {
    return dom.h('h1', { class: ui.h1, tabindex: -1, 'data-autofocus': 'true' }, text);
  }

  function section(...children: Children): HTMLElement {
    return dom.h('section', { class: cx(ui.card, 'space-y-5') }, ...children);
  }

  function card(): HTMLElement {
    switch (phase.name) {
      case 'loading':
        return section(dom.h('p', { role: 'status', class: ui.mutedMono }, '確認中…'));
      case 'invalid-link':
        return messageCard('danger', 'リンクが不正です', [
          '復号鍵（# 以降）が欠落しているか、形式が不正です。取得は実行されていません。',
          '送信者にリンクの再送を依頼してください。',
        ]);
      case 'unavailable':
        return messageCard('warn', 'データが存在しません', ['取得済み、有効期限切れ、またはリンクの誤りです。']);
      case 'load-error':
        return messageCard('danger', 'サーバーに接続できません', ['ネットワークを確認して再実行してください。'], {
          label: '再試行',
          action: 'retry',
          onClick: () => void load(),
        });
      case 'key-mismatch':
        // 「開く」ボタンを含む confirmCard は描画しない（消費リクエストを発行する手段を、そもそも作らない）。
        return messageCard('danger', '鍵が一致しません', [
          '共有リンクの復号鍵が正しくないか、途中で切れています。データの消滅を防ぐため、開く処理を停止しました。',
          '正しい URL を確認してください。',
        ]);
      case 'open-error': {
        const { meta } = phase;
        return messageCard('danger', '取得に失敗しました', ['通信の途中で切断された場合、データは既に削除されている可能性があります。'], {
          label: '再試行',
          action: 'retry-open',
          onClick: () => void open(meta),
        });
      }
      case 'decrypt-failed':
        return messageCard('danger', '復号に失敗しました', [
          '鍵が一致しないか、データが改ざんされています。サーバー上のデータは削除済みです。',
          '送信者に再送を依頼してください。',
        ]);
      case 'confirm':
      case 'opening':
        return confirmCard(phase.meta, phase.name === 'opening');
      case 'text':
        return textCard(phase.text);
      case 'file':
        return fileCard(phase);
      case 'discarded':
        return section(
          heading('破棄しました'),
          dom.h('p', { class: ui.sub }, '表示していたデータを画面から消去しました。サーバー上のデータは削除済みのため、再表示できません。'),
        );
    }
  }

  function messageCard(
    tone: 'danger' | 'warn',
    title: string,
    paragraphs: string[],
    action?: { label: string; action: string; onClick: () => void },
  ): HTMLElement {
    return section(
      notice(dom, { tone, icon: 'alert', title, role: 'alert', autofocus: true }, ...paragraphs.map((text) => dom.h('p', {}, text))),
      action && dom.h('div', {}, button(dom, { variant: 'secondary', label: action.label, action: action.action, on: { click: action.onClick } })),
    );
  }

  /** Stage 1: 確認。削除されることを事実として示し、受信者が実行するまで何も消費しない。 */
  function confirmCard(meta: PayloadMeta, opening: boolean): HTMLElement {
    const isFile = meta.type === 'file';
    const actionLabel = isFile ? 'データを復号してダウンロード' : 'データを復号して表示';
    const remaining = meta.expiresAt.getTime() - env.now();
    const row = (label: string, value: string, sub?: string): HTMLElement =>
      dom.h('div', { class: ui.row }, dom.h('dt', { class: ui.rowLabel }, label), dom.h('dd', { class: ui.rowValue }, value, sub !== undefined && dom.h('span', { class: ui.rowSub }, sub)));

    return section(
      // サーバーの種別ヒントは表示だけに使う（実際の種別は復号後に確定する）。
      heading('受信データ'),
      dom.h(
        'dl',
        {},
        row('種類', isFile ? 'ファイル' : 'テキスト'),
        row('サイズ', formatBytes(meta.size)),
        row('有効期限', formatDateTime(meta.expiresAt), `あと ${formatRemaining(remaining)}`),
        row('暗号方式', 'AES-256-GCM'),
      ),
      notice(
        dom,
        { tone: 'warn', icon: 'alert', title: 'このデータは一度開くとサーバーから永久削除されます' },
        dom.h('p', {}, `「${actionLabel}」を実行した時点で削除されます。`),
      ),
      button(dom, {
        variant: 'primary',
        action: 'open',
        busy: opening,
        label: opening ? '取得・復号中…' : actionLabel,
        disabled: opening,
        on: { click: () => void open(meta) },
      }),
    );
  }

  /** Stage 2 の結果（テキスト）。renderTextSafely でテキストノードとしてだけ描画する。 */
  function textCard(text: string): HTMLElement {
    const output = dom.h('pre', {
      role: 'region',
      'aria-label': '復号結果',
      tabindex: 0,
      'data-testid': 'decrypted-text',
      class: cx(ui.codeBlock, 'max-h-[60vh] overflow-auto whitespace-pre-wrap'),
    });
    renderTextSafely(output, text);

    const copyButton: HTMLButtonElement = button(dom, {
      variant: 'secondary',
      label: 'コピー',
      action: 'copy-text',
      on: { click: () => void copyText(text, copyButton) },
    });

    return section(
      dom.h(
        'div',
        { class: 'flex items-baseline justify-between gap-4' },
        heading('復号結果'),
        dom.h('span', { 'data-testid': 'decrypted-size', class: ui.mutedMono }, `テキスト · ${formatBytes(new TextEncoder().encode(text).byteLength)}`),
      ),
      output,
      dom.h('div', { class: 'flex gap-2' }, copyButton, discardButton()),
      dom.h('p', { class: 'text-xs text-zinc-400' }, 'サーバー上のデータは削除済みです。破棄すると再表示できません。'),
    );
  }

  /** Stage 2 の結果（ファイル）。ダウンロードするだけで、アプリの画面内では開かない。 */
  function fileCard(file: Extract<Phase, { name: 'file' }>): HTMLElement {
    return section(
      dom.h(
        'div',
        { class: 'flex items-baseline justify-between gap-4' },
        heading('復号完了'),
        dom.h('span', { class: ui.mutedMono }, `ファイル · ${formatBytes(file.size)}`),
      ),
      dom.h('div', { class: ui.codeBlock, 'data-testid': 'received-file-name' }, file.fileName),
      file.saveFailed
        ? notice(dom, { tone: 'warn', icon: 'alert', title: '自動でダウンロードできませんでした', role: 'alert' }, dom.h('p', {}, '「再ダウンロード」で保存してください。'))
        : dom.h('p', { role: 'status', class: 'text-sm text-emerald-400' }, 'ダウンロードを開始しました。'),
      file.risky &&
        notice(
          dom,
          { tone: 'warn', icon: 'alert', title: '実行ファイルまたはスクリプトの可能性があります' },
          dom.h('p', {}, '信頼できる送信元のファイルのみ開いてください。'),
        ),
      dom.h(
        'div',
        { class: 'flex gap-2' },
        button(dom, { variant: 'secondary', label: '再ダウンロード', action: 'download-again', on: { click: () => saveAgain(file) } }),
        discardButton(),
      ),
      dom.h('p', { class: 'text-xs text-zinc-400' }, 'サーバー上のデータは削除済みです。破棄すると再ダウンロードできません。'),
    );
  }

  function discardButton(): HTMLButtonElement {
    return button(dom, { variant: 'secondary', label: '破棄', action: 'discard', on: { click: discard } });
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
      phase = (await keyCheckMismatch(meta)) ? { name: 'key-mismatch' } : { name: 'confirm', meta };
    } catch (error) {
      if (destroyed) return;
      phase = error instanceof ApiError && error.code === 'not_found' ? { name: 'unavailable' } : { name: 'load-error' };
    }
    pendingFocus = '[data-autofocus]';
    render();
  }

  /**
   * meta.keyCheck と、URL の鍵からローカルで計算した確認値を照合する。「確実に違うと分かる」ときだけ true。
   *   - meta.keyCheck が無い（旧データ・未対応の送信側）→ 判定できないので false（＝通常どおり続行）
   *   - ローカルでの計算自体が失敗した（WebCrypto 不使用環境など）→ 同様に false
   *   - 両方そろっていて、値が一致しない → true（＝鍵が壊れている。消費させない）
   * 「判定できない」場合を false 側に倒すのは、誤検出でデータへの到達自体を妨げないための安全側の既定値。
   * その場合も、消費（POST consume）自体は AES-GCM の認証タグが最終的な防御として機能する。
   */
  async function keyCheckMismatch(meta: PayloadMeta): Promise<boolean> {
    if (meta.keyCheck === undefined) return false;
    try {
      return (await generateKeyCheckTag(keyString)) !== meta.keyCheck;
    } catch {
      return false;
    }
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

  /** 表示中のデータ（復号したテキスト・ファイルのバイト列）を、この画面から消去する。参照を手放すので再表示はできない。 */
  function discard(): void {
    if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
    feedbackTimer = null;
    phase = { name: 'discarded' };
    pendingFocus = '[data-autofocus]';
    render();
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
      if (label !== null) label.textContent = 'コピーできません';
    }
    if (feedbackTimer !== null) env.clearTimeout(feedbackTimer);
    feedbackTimer = env.setTimeout(() => {
      if (!destroyed && label !== null) label.textContent = 'コピー';
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
