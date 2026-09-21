import { createDom, cx } from './dom.ts';
import type { AppEnv, ViewHandle } from './env.ts';
import { createIcon } from './icons.ts';
import { resolveRoute } from './router.ts';
import { applyTheme, effectiveTheme, storeTheme } from './theme.ts';
import { ui } from './ui.ts';
import { mountReceiveView } from './views/receive.ts';
import { mountSendView } from './views/send.ts';

const TITLES = {
  send: 'CipherDrop — 一度だけ開ける、安全な共有',
  receive: 'CipherDrop — 共有データを受け取る',
  notFound: 'ページが見つかりません — CipherDrop',
} as const;

/** ヘッダー・フッターと、URL に応じた画面（送信 / 受取 / 404）を組み立てて表示する。 */
export function mountApp(env: AppEnv): ViewHandle {
  const dom = createDom(env.doc);
  const route = resolveRoute(env.location.pathname);

  function themeToggle(): HTMLElement {
    const dark = effectiveTheme(env.doc, env.prefersDark) === 'dark';
    return dom.h(
      'button',
      {
        type: 'button',
        'aria-label': dark ? 'ライトモードに切り替える' : 'ダークモードに切り替える',
        'data-action': 'toggle-theme',
        class: 'grid size-10 cursor-pointer place-items-center rounded-lg border border-line text-muted transition-colors hover:bg-sunken hover:text-fg',
        on: {
          click: () => {
            const next = dark ? 'light' : 'dark';
            applyTheme(env.doc, next);
            storeTheme(env.storage, next);
            const replacement = themeToggle();
            header.querySelector('[data-action="toggle-theme"]')?.replaceWith(replacement);
            replacement.focus();
          },
        },
      },
      createIcon(dom, dark ? 'sun' : 'moon', 'size-5'),
    );
  }

  const header = dom.h(
    'header',
    { class: 'border-b border-line bg-surface' },
    dom.h(
      'div',
      { class: 'mx-auto flex w-full max-w-2xl items-center justify-between px-4 py-3' },
      dom.h(
        'a',
        { href: '/', class: 'inline-flex items-center gap-2.5 rounded-lg py-1 text-lg font-bold tracking-tight text-fg' },
        dom.h('span', { class: 'grid size-9 place-items-center rounded-xl bg-accent-solid text-on-accent' }, createIcon(dom, 'lock', 'size-5')),
        'CipherDrop',
      ),
      themeToggle(),
    ),
  );

  const main = dom.h('main', { id: 'main', tabindex: -1, class: 'mx-auto w-full max-w-2xl flex-1 px-4 py-8 focus:outline-none sm:py-12' });

  const skipLink = dom.h(
    'a',
    {
      href: '#main',
      class: 'sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:rounded-lg focus:bg-surface focus:px-4 focus:py-2 focus:text-fg focus:shadow-card',
    },
    '本文へスキップ',
  );

  const footer = dom.h(
    'footer',
    { class: 'border-t border-line py-8' },
    dom.h(
      'div',
      { class: 'mx-auto max-w-2xl px-4 text-center text-sm text-muted' },
      dom.h('p', {}, '暗号化と復号はあなたのブラウザの中で行われます。サーバーは内容も鍵も保持しません。'),
      dom.h('p', { class: 'mt-1 font-semibold' }, 'CipherDrop'),
    ),
  );

  env.root.replaceChildren(dom.h('div', { class: 'flex min-h-dvh flex-col' }, skipLink, header, main, footer));

  let view: ViewHandle;
  switch (route.name) {
    case 'send':
      env.doc.title = TITLES.send;
      view = mountSendView(env, main);
      break;
    case 'receive':
      env.doc.title = TITLES.receive;
      view = mountReceiveView(env, main, route);
      break;
    case 'not-found':
      env.doc.title = TITLES.notFound;
      view = mountNotFound();
      break;
  }

  function mountNotFound(): ViewHandle {
    main.replaceChildren(
      dom.h(
        'section',
        { class: cx(ui.card, 'space-y-4') },
        dom.h('h2', { class: ui.h2, tabindex: -1 }, 'ページが見つかりません'),
        dom.h('p', { class: 'text-muted' }, 'お探しのページは存在しないか、移動した可能性があります。'),
        dom.h('a', { href: '/', class: 'inline-block text-sm font-semibold text-accent underline underline-offset-4' }, 'トップページへ戻る'),
      ),
    );
    return { destroy: () => main.replaceChildren() };
  }

  return {
    destroy() {
      view.destroy();
      env.root.replaceChildren();
    },
  };
}
