/**
 * デザインの部品。class は Tailwind のユーティリティで、色は styles.css の意味トークン（surface / muted / accent …）を使う。
 * ここに色の値は書かない（ライト/ダークの切替は CSS 変数だけで完結する）。
 */
import { cx } from './dom.ts';
import type { Children, Dom, Listener } from './dom.ts';
import { createIcon } from './icons.ts';
import type { IconName } from './icons.ts';

export const ui = {
  card: 'rounded-2xl border border-line bg-surface p-5 shadow-card sm:p-8',
  h1: 'text-balance text-3xl font-bold leading-tight tracking-tight text-fg sm:text-4xl',
  h2: 'text-xl font-bold leading-snug text-fg focus:outline-none',
  lead: 'text-pretty text-base leading-relaxed text-muted sm:text-lg',
  label: 'mb-2 block text-sm font-semibold text-fg',
  hint: 'mt-2 text-sm text-muted',
  textarea:
    'block w-full resize-y rounded-xl border border-line-strong bg-sunken px-4 py-3 text-base leading-relaxed text-fg placeholder:text-muted focus:border-accent focus:bg-surface disabled:opacity-60',
  tabBase:
    'inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60',
  tabActive: 'bg-surface text-accent shadow-sm ring-1 ring-line-strong',
  tabIdle: 'text-muted hover:text-fg',
  dropzone:
    'flex min-h-44 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-line-strong bg-sunken px-4 py-8 text-center transition-colors hover:border-accent hover:bg-accent-soft has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-accent',
  dropzoneActive: 'border-accent bg-accent-soft',
  radioCard:
    'flex cursor-pointer items-center justify-center rounded-xl border border-line-strong bg-surface px-3 py-2.5 text-sm font-semibold text-fg transition-colors hover:bg-sunken has-checked:border-accent has-checked:bg-accent-soft has-checked:text-accent has-focus-visible:outline-2 has-focus-visible:outline-offset-2 has-focus-visible:outline-accent has-disabled:cursor-not-allowed has-disabled:opacity-60',
  row: 'flex items-baseline justify-between gap-4 border-b border-line py-3 last:border-b-0',
} as const;

const BUTTON_VARIANTS = {
  // 画面の主要な操作。カードいっぱいの幅にして、押すべきものが一目で分かるようにする。
  primary: 'w-full justify-center bg-accent-solid px-5 py-3.5 text-base text-on-accent hover:bg-accent-hover',
  secondary: 'border border-line-strong bg-surface px-4 py-2.5 text-sm text-fg hover:bg-sunken',
} as const;

export interface ButtonOptions {
  variant: keyof typeof BUTTON_VARIANTS;
  label: string;
  icon?: IconName;
  type?: 'button' | 'submit';
  disabled?: boolean;
  /** 実行中の表示（アイコンを回転させる）。 */
  busy?: boolean;
  id?: string;
  /** 操作の識別子（data-action）。テストや計測なしの自動操作から、ボタンを文言に依存せず特定するため。 */
  action?: string;
  on?: Record<string, Listener>;
}

/** ボタン。ラベルは <span data-label> に入れるので、あとから textContent で差し替えられる。 */
export function button(dom: Dom, options: ButtonOptions): HTMLButtonElement {
  const { variant, label, icon, type = 'button', disabled = false, busy = false, id, action, on } = options;
  return dom.h(
    'button',
    {
      type,
      disabled,
      ...(id === undefined ? {} : { id }),
      ...(action === undefined ? {} : { 'data-action': action }),
      ...(on === undefined ? {} : { on }),
      class: cx(
        'inline-flex cursor-pointer items-center gap-2 rounded-xl font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        BUTTON_VARIANTS[variant],
      ),
    },
    icon && createIcon(dom, icon, cx('size-5', busy && 'motion-safe:animate-spin')),
    dom.h('span', { 'data-label': 'true' }, label),
  );
}

export type NoticeTone = 'warn' | 'danger' | 'ok' | 'info';

const NOTICE_TONES: Record<NoticeTone, string> = {
  warn: 'border-warn-line bg-warn-bg text-warn',
  danger: 'border-danger-line bg-danger-bg text-danger',
  ok: 'border-ok-line bg-ok-bg text-ok',
  info: 'border-line-strong bg-sunken text-fg',
};

export interface NoticeOptions {
  tone: NoticeTone;
  icon: IconName;
  title: string;
  /** エラーは 'alert'（即時に読み上げ）、補足は 'note'。 */
  role?: 'alert' | 'note' | 'status';
  /** 描画後にフォーカスを移す（エラー・状態変化を支援技術に伝える）。 */
  autofocus?: boolean;
}

/** 警告・エラー・補足のカード。タイトルは太字、本文は小さめ。 */
export function notice(dom: Dom, options: NoticeOptions, ...body: Children): HTMLElement {
  const { tone, icon, title, role = 'note', autofocus = false } = options;
  return dom.h(
    'div',
    {
      role,
      class: cx('flex gap-3 rounded-xl border p-4', NOTICE_TONES[tone]),
      ...(autofocus ? { 'data-autofocus': 'true', tabindex: -1 } : {}),
    },
    createIcon(dom, icon, 'mt-0.5 size-5'),
    dom.h('div', { class: 'min-w-0 space-y-1.5 text-sm leading-relaxed' }, dom.h('p', { class: 'text-base font-bold leading-snug' }, title), ...body),
  );
}
