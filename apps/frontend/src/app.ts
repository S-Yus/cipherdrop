import { createDom, cx } from './dom.ts';
import type { AppEnv, ViewHandle } from './env.ts';
import { createIcon } from './icons.ts';
import { resolveRoute } from './router.ts';
import { ui } from './ui.ts';
import { mountReceiveView } from './views/receive.ts';
import { mountSendView } from './views/send.ts';

const TITLES = {
  send: 'CipherDrop',
  receive: '受信データ — CipherDrop',
  notFound: 'ページが見つかりません — CipherDrop',
} as const;

/** ヘッダー（ワードマークのみ）と、URL に応じた画面（送信 / 受取 / 404）を組み立てて表示する。 */
export function mountApp(env: AppEnv): ViewHandle {
  const dom = createDom(env.doc);
  const route = resolveRoute(env.location.pathname);

  const header = dom.h(
    'header',
    { class: 'border-b border-zinc-800' },
    dom.h(
      'div',
      { class: 'mx-auto flex h-12 w-full max-w-2xl items-center justify-between px-4' },
      dom.h(
        'a',
        { href: '/', class: 'inline-flex items-center gap-2 rounded text-sm font-semibold tracking-tight text-zinc-100' },
        createIcon(dom, 'lock', 'size-4 text-emerald-500'),
        'CipherDrop',
      ),
      // 送信画面以外では、新しい共有を始める入口を 1 つだけ置く。
      route.name === 'send' ? null : dom.h('a', { href: '/', class: 'rounded text-sm text-zinc-400 hover:text-zinc-100' }, '新規共有'),
    ),
  );

  const main = dom.h('main', { id: 'main', tabindex: -1, class: 'mx-auto w-full max-w-2xl flex-1 px-4 py-8 focus:outline-none sm:py-12' });

  const skipLink = dom.h(
    'a',
    {
      href: '#main',
      class: 'sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-10 focus:rounded-md focus:bg-white focus:px-3 focus:py-2 focus:text-black',
    },
    '本文へスキップ',
  );

  env.root.replaceChildren(dom.h('div', { class: 'flex min-h-dvh flex-col' }, skipLink, header, main));

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
        { class: cx(ui.card, 'space-y-3') },
        dom.h('h1', { class: ui.h1, tabindex: -1 }, 'ページが見つかりません'),
        dom.h('p', { class: ui.sub }, '指定されたパスは存在しません。'),
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
