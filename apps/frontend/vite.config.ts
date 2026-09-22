import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import type { Plugin } from 'vite';

/**
 * 本番ビルドの index.html に埋め込む CSP。
 *
 * - スクリプト・スタイルは自オリジンの外部ファイルだけ（インライン・eval・外部 CDN はすべて禁止）。
 * - 通信先は自オリジンだけ（connect-src 'self'）。第三者への通信（フォント・解析・CDN）は設計上存在しない。
 * - require-trusted-types-for 'script': DOM XSS の入口（HTML 挿入 API など）に文字列を渡すと例外になる。
 *   このコードベースはそれらを使わないので影響はなく、万一混入しても実行時に止まる（多層防御）。
 *
 * <meta> では frame-ancestors / report-uri / sandbox が効かない。クリックジャッキング対策の
 * `Content-Security-Policy: frame-ancestors 'none'`（または X-Frame-Options）は配信側のレスポンスヘッダーで付けること。
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
].join('; ');

/** 開発サーバー（HMR がインライン処理を使う）には適用せず、`vite build` の出力にだけ CSP を入れる。 */
function contentSecurityPolicy(): Plugin {
  return {
    name: 'cipherdrop:content-security-policy',
    apply: 'build',
    transformIndexHtml() {
      return [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
          injectTo: 'head-prepend', // CSP は、統制対象のスクリプト・スタイルより前に置く
        },
      ];
    },
  };
}

// 開発時もブラウザからは同一オリジンに見えるよう、/api はバックエンド（既定 127.0.0.1:8787）へ中継する。
const api = { '/api': 'http://127.0.0.1:8787' };

export default defineConfig({
  plugins: [tailwindcss(), contentSecurityPolicy()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy: api },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true, proxy: api },
  build: {
    target: 'es2022',
    sourcemap: false,
    assetsInlineLimit: 0, // data: URI にしない（CSP の img-src / font-src を 'self' だけに保つ）
    modulePreload: { polyfill: false },
  },
});
