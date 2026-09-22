/** 共有リンクの ID（バックエンドが発行する 128bit の base64url、22 文字）。 */
export const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export type Route =
  | { name: 'send' }
  /** id が null のときは `/v/...` だが ID の形式が正しくない（欠け・余分な文字など）。 */
  | { name: 'receive'; id: string | null }
  | { name: 'not-found' };

/** URL のパス部分だけから画面を決める（鍵はパスではなくフラグメントにあり、ここには渡らない）。 */
export function resolveRoute(pathname: string): Route {
  if (pathname === '/' || pathname === '/index.html') return { name: 'send' };

  const receive = /^\/v\/([^/]*)\/?$/.exec(pathname);
  if (receive) {
    const id = receive[1] ?? '';
    return { name: 'receive', id: ID_PATTERN.test(id) ? id : null };
  }
  return { name: 'not-found' };
}
