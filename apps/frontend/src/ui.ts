/**
 * デザインの部品。Tailwind の標準パレットだけを使う。
 *
 *   背景 bg-zinc-950 / 面 bg-zinc-900/50 + border-zinc-800（1px・フラット）/ 文字 zinc-100・zinc-400
 *   アクセント: emerald（暗号化・安全の状態）と白（主要な操作）のみ / 警告 amber・エラー red は静かな 5% の面
 *   等幅（font-mono）: 鍵・URL・サイズ・期限・ステータスなど、精密さが要る値
 *
 * 影・グラデーションは使わない。色・装飾の規則は tests/design-rules.test.ts が機械的に検査する。
 */
import { cx } from './dom.ts';
import type { Children, Dom, Listener } from './dom.ts';
import { createIcon } from './icons.ts';
import type { IconName } from './icons.ts';

export const ui = {
  card: 'rounded-lg border border-zinc-800 bg-zinc-900/50 p-5 sm:p-6',
  h1: 'text-lg font-semibold tracking-tight text-zinc-100 focus:outline-none',
  sub: 'text-sm leading-relaxed text-zinc-400',
  label: 'mb-1.5 block text-sm font-medium text-zinc-200',
  /** コードエディタのような入力面。 */
  editor:
    'block w-full resize-y rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-sm leading-relaxed text-zinc-100 placeholder:text-zinc-400 focus:border-zinc-600 disabled:opacity-60',
  select: 'rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 focus:border-zinc-500 disabled:opacity-60',
  tabList: 'flex gap-5 border-b border-zinc-800',
  tabBase: '-mb-px border-b-2 px-0.5 pb-2 text-sm font-medium transition-colors disabled:opacity-60',
  tabActive: 'border-zinc-100 text-zinc-100',
  tabIdle: 'border-transparent text-zinc-400 hover:text-zinc-200',
  dropzone:
    'flex min-h-36 cursor-pointer flex-col items-center justify-center gap-1.5 rounded-md border border-dashed border-zinc-700 bg-zinc-950 px-4 py-6 text-center transition-colors hover:border-zinc-500 has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-emerald-500',
  /** ドラッグ中の状態。idle の枠線（border-zinc-700）と入れ替えて使う（同じ property の競合を避けるため）。 */
  dropzoneIdleBorder: 'border-zinc-700',
  dropzoneActive: 'border-emerald-500 bg-emerald-500/5',
  /** 値を等幅で並べる行（種類・サイズ・有効期限など）。 */
  row: 'flex items-baseline justify-between gap-6 border-b border-zinc-800 py-2.5 last:border-b-0',
  rowLabel: 'shrink-0 text-sm text-zinc-400',
  rowValue: 'min-w-0 text-right font-mono text-sm text-zinc-100 [overflow-wrap:anywhere]',
  /** 値の下に添える補足（残り時間など）。 */
  rowSub: 'block text-xs text-zinc-400',
  /** URL・復号結果など、コードのように見せるブロック。 */
  codeBlock: 'block w-full rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-sm leading-relaxed text-zinc-100 [overflow-wrap:anywhere]',
  mutedMono: 'font-mono text-xs text-zinc-400',
} as const;

const BUTTON_BASE =
  'inline-flex cursor-pointer items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40';

/** 主要な操作は白（bg-white text-black）。それ以外は枠線だけ。 */
const BUTTON_VARIANTS = {
  primary: 'w-full bg-white px-4 py-2.5 text-sm font-semibold text-black hover:bg-zinc-200',
  secondary: 'border border-zinc-700 bg-transparent px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-800',
} as const;

export interface ButtonOptions {
  variant: keyof typeof BUTTON_VARIANTS;
  label: string;
  type?: 'button' | 'submit';
  disabled?: boolean;
  /** 実行中の表示（小さなスピナーを回す）。 */
  busy?: boolean;
  id?: string;
  /** 操作の識別子（data-action）。テストや自動操作から、ボタンを文言に依存せず特定するため。 */
  action?: string;
  on?: Record<string, Listener>;
}

/** ボタン。ラベルは <span data-label> に入れるので、あとから textContent で差し替えられる。 */
export function button(dom: Dom, options: ButtonOptions): HTMLButtonElement {
  const { variant, label, type = 'button', disabled = false, busy = false, id, action, on } = options;
  return dom.h(
    'button',
    {
      type,
      disabled,
      ...(id === undefined ? {} : { id }),
      ...(action === undefined ? {} : { 'data-action': action }),
      ...(on === undefined ? {} : { on }),
      class: cx(BUTTON_BASE, BUTTON_VARIANTS[variant]),
    },
    busy && createIcon(dom, 'spinner', 'size-4 motion-safe:animate-spin'),
    dom.h('span', { 'data-label': 'true' }, label),
  );
}

/** 暗号化の状態を示す小さなバッジ（等幅）。緑の点は「暗号化がクライアント側で行われる」ことを示す。 */
export function statusBadge(dom: Dom, text: string): HTMLElement {
  return dom.h(
    'span',
    { 'data-testid': 'status-badge', class: 'inline-flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/50 px-2 py-1 font-mono text-xs text-zinc-400' },
    dom.h('span', { 'aria-hidden': 'true', class: 'size-1.5 rounded-full bg-emerald-500' }),
    text,
  );
}

export type NoticeTone = 'warn' | 'danger' | 'ok' | 'info';

/** 警告は amber、エラーは red、成功は emerald。どれも 1px の枠線と 5% の面だけの静かな表現（赤く塗りつぶさない）。 */
const NOTICE_TONES: Record<NoticeTone, { box: string; title: string; icon: string }> = {
  warn: { box: 'border-amber-500/20 bg-amber-500/5', title: 'text-amber-400', icon: 'text-amber-500' },
  danger: { box: 'border-red-500/20 bg-red-500/5', title: 'text-red-400', icon: 'text-red-500' },
  ok: { box: 'border-emerald-500/20 bg-emerald-500/5', title: 'text-emerald-400', icon: 'text-emerald-500' },
  info: { box: 'border-zinc-800 bg-zinc-900/50', title: 'text-zinc-200', icon: 'text-zinc-400' },
};

export interface NoticeOptions {
  tone: NoticeTone;
  icon?: IconName;
  title: string;
  /** エラーは 'alert'（即時に読み上げ）、補足は 'note'。 */
  role?: 'alert' | 'note' | 'status';
  /** 描画後にフォーカスを移す（エラー・状態変化を支援技術に伝える）。 */
  autofocus?: boolean;
}

/** 警告・エラー・補足。タイトルは事実を 1 行で、本文は必要なときだけ。 */
export function notice(dom: Dom, options: NoticeOptions, ...body: Children): HTMLElement {
  const { tone, icon, title, role = 'note', autofocus = false } = options;
  const styles = NOTICE_TONES[tone];
  return dom.h(
    'div',
    {
      role,
      class: cx('flex gap-3 rounded-md border p-3.5', styles.box),
      ...(autofocus ? { 'data-autofocus': 'true', tabindex: -1 } : {}),
    },
    icon && createIcon(dom, icon, cx('mt-0.5 size-4', styles.icon)),
    dom.h('div', { class: 'min-w-0 space-y-1 text-sm leading-relaxed text-zinc-300' }, dom.h('p', { class: cx('font-semibold', styles.title) }, title), ...body),
  );
}
