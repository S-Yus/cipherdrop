/**
 * 配布物（`vite build` の出力）そのものの検査。
 *
 * ソースコードが安全でも、ビルド設定の変更やプラグインの挿入で「実際に配られるファイル」は変わり得る。
 * ここでは本番ビルドを実行し、生成された index.html・JS・CSS が次を満たしていることを確認する。
 *   - 厳格な CSP（<meta>）が <head> の先頭に入っている（インライン・eval・外部読み込みを許可しない）
 *   - インラインのスクリプト・スタイル・イベントハンドラ属性が存在しない
 *   - HTML 挿入 API・eval・外部 URL への参照が、バンドルに含まれない（第三者への通信が発生し得ない）
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FRONTEND = join(ROOT, 'apps/frontend');
const OUT = join(FRONTEND, 'dist-test'); // .gitignore 済み。テストの最後に削除する

const read = (relative: string): string => readFileSync(join(OUT, relative), 'utf8');

describe('本番ビルドの配布物', () => {
  let html = '';
  let js = '';
  let css = '';
  let assets: string[] = [];

  before(() => {
    const viteBin = join(dirname(createRequire(import.meta.url).resolve('vite/package.json')), 'bin/vite.js');
    const result = spawnSync(process.execPath, [viteBin, 'build', '--outDir', OUT, '--emptyOutDir'], { cwd: FRONTEND, encoding: 'utf8' });
    assert.equal(result.status, 0, `vite build に失敗:\n${result.stdout}\n${result.stderr}`);

    assets = readdirSync(join(OUT, 'assets'));
    html = read('index.html');
    js = read(`assets/${assets.find((f) => f.endsWith('.js')) ?? ''}`);
    css = read(`assets/${assets.find((f) => f.endsWith('.css')) ?? ''}`);
  });

  after(() => rmSync(OUT, { recursive: true, force: true }));

  it('出力は index.html・favicon.svg と、JS・CSS が 1 つずつだけ（テーマ初期化などの追加スクリプトはない）', () => {
    assert.ok(existsSync(join(OUT, 'index.html')));
    assert.ok(existsSync(join(OUT, 'favicon.svg')));
    assert.equal(existsSync(join(OUT, 'theme-init.js')), false, 'ダーク固定なのでテーマ初期化スクリプトは不要');
    assert.equal(assets.filter((f) => f.endsWith('.js')).length, 1);
    assert.equal(assets.filter((f) => f.endsWith('.css')).length, 1);
    assert.equal(assets.filter((f) => !/\.(js|css)$/.test(f)).length, 0, 'JS・CSS 以外のアセット（画像・フォント・ソースマップ）を出力しない');
  });

  describe('Content-Security-Policy', () => {
    const csp = (): Map<string, string> => {
      const tags = [...html.matchAll(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/g)];
      assert.equal(tags.length, 1, 'CSP の <meta> がちょうど 1 つある');
      const content = (tags[0]?.[1] ?? '').replaceAll('&#39;', "'").replaceAll('&quot;', '"').replaceAll('&amp;', '&');
      return new Map(content.split(';').map((part) => part.trim().split(/\s+/)).map(([name = '', ...values]) => [name, values.join(' ')]));
    };

    it('スクリプト・スタイル・通信・画像・フォントは自オリジンだけ。それ以外はすべて拒否する', () => {
      const policy = csp();
      assert.equal(policy.get('default-src'), "'none'");
      for (const directive of ['script-src', 'style-src', 'connect-src', 'img-src', 'font-src']) {
        assert.equal(policy.get(directive), "'self'", directive);
      }
      assert.equal(policy.get('object-src'), "'none'");
      assert.equal(policy.get('base-uri'), "'none'");
      assert.equal(policy.get('form-action'), "'none'");
    });

    it("DOM XSS の入口を止める（require-trusted-types-for 'script'）", () => {
      assert.equal(csp().get('require-trusted-types-for'), "'script'");
    });

    it("どのディレクティブにも 'unsafe-inline' / 'unsafe-eval' / ワイルドカード / data: / http(s): / blob: を許可していない", () => {
      for (const [directive, value] of csp()) {
        assert.doesNotMatch(value, /unsafe-|\*|data:|https?:|blob:|wss?:/i, `${directive}: ${value}`);
      }
    });

    it('CSP の <meta> は <head> の先頭にあり、統制対象のスクリプト・スタイルより前にある', () => {
      const head = html.slice(html.indexOf('<head>') + '<head>'.length);
      assert.match(head.trimStart(), /^<meta http-equiv="Content-Security-Policy"/);
      const cspAt = html.indexOf('Content-Security-Policy');
      for (const tag of ['<script', '<link', '<style']) {
        const at = html.indexOf(tag);
        assert.ok(at === -1 || at > cspAt, `${tag} が CSP より前にある`);
      }
    });

    it('<meta charset> は先頭 1024 バイト以内（CSP の後ろに押し出されていない）', () => {
      assert.ok(html.indexOf('<meta charset') < 1024);
    });
  });

  describe('index.html', () => {
    it('スクリプトはすべて外部ファイル（src あり・本文なし）。インラインのスクリプト・スタイルは存在しない', () => {
      const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
      assert.equal(scripts.length, 1, 'スクリプトはエントリーの 1 本だけ');
      for (const [, attributes = '', body = ''] of scripts) {
        assert.match(attributes, /\bsrc="\//, 'src を持つ');
        assert.equal(body.trim(), '', 'インラインの本文がない');
      }
      assert.doesNotMatch(html, /<style\b/i);
    });

    it('イベントハンドラ属性（onclick 等）・style 属性・javascript: を含まない', () => {
      assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
      assert.doesNotMatch(html, /\sstyle\s*=/i);
      assert.doesNotMatch(html, /javascript:/i);
    });

    it('参照する src / href は、すべて同一オリジンの実在するファイル', () => {
      const references = [...html.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((m) => m[1] ?? '');
      assert.ok(references.length >= 3, 'favicon・CSS・JS');
      for (const reference of references) {
        assert.match(reference, /^\/[^/]/, `同一オリジンの絶対パス: ${reference}`);
        assert.ok(existsSync(join(OUT, reference)), `存在する: ${reference}`);
      }
    });

    it('ダーク固定（color-scheme: dark）。遷移先へ参照元を渡さない（no-referrer）。検索エンジンに載せない（noindex）', () => {
      assert.match(html, /<meta name="color-scheme" content="dark"/);
      assert.match(html, /<meta name="referrer" content="no-referrer"/);
      assert.match(html, /<meta name="robots" content="noindex, nofollow"/);
    });
  });

  describe('バンドル（JS・CSS）', () => {
    it('HTML 挿入 API・eval・new Function・document.write・iframe の srcdoc を含まない', () => {
      for (const forbidden of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'createContextualFragment', 'parseFromString', 'document.write', 'srcdoc', 'eval(', 'new Function', 'dangerouslySetInnerHTML']) {
        assert.equal(js.includes(forbidden), false, `JS に "${forbidden}" が含まれている`);
      }
    });

    it('外部ホストの URL を含まない（唯一の例外は SVG の名前空間）。第三者への通信が発生し得ない', () => {
      const urls = [...js.matchAll(/https?:\/\/[^\s"'`)\\]+/g)].map((m) => m[0]);
      assert.deepEqual([...new Set(urls)], ['http://www.w3.org/2000/svg']);

      // ライセンス表記のコメント（https://tailwindcss.com など）は通信を起こさないので除く。
      const cssRules = css.replace(/\/\*[\s\S]*?\*\//g, '');
      const external = [...cssRules.matchAll(/https?:\/\/[^\s"')]+/g), ...cssRules.matchAll(/@import[^;]*;?/g), ...cssRules.matchAll(/url\([^)]*\)/g)].map((m) => m[0]);
      assert.deepEqual(external, [], 'CSS は外部 URL・@import・url() を一切含まない（外部フォント・CDN・画像を読まない）');
    });

    it('通信は fetch（自オリジンの /api）だけ。WebSocket・EventSource・sendBeacon・XMLHttpRequest を使わない', () => {
      for (const channel of ['WebSocket', 'EventSource', 'sendBeacon', 'XMLHttpRequest']) {
        assert.equal(js.includes(channel), false, channel);
      }
      assert.ok(js.includes('/api/payload'));
    });

    it('ソースマップを配らない', () => {
      assert.doesNotMatch(js, /sourceMappingURL/);
      assert.doesNotMatch(css, /sourceMappingURL/);
    });

    it('サイズの目安: 依存ライブラリが紛れ込んでいない（JS < 100 KB, CSS < 60 KB）', () => {
      assert.ok(js.length < 100_000, `JS が ${js.length} バイト`);
      assert.ok(css.length < 60_000, `CSS が ${css.length} バイト`);
    });

    describe('デザイン規則（実際にビルドされた CSS）', () => {
      // ライセンス表記などのコメントは除いて、実際に効く記述だけを見る。
      const rules = (): string => css.replace(/\/\*[\s\S]*?\*\//g, '');

      it('グラデーションを使わない', () => {
        assert.doesNotMatch(rules(), /gradient\(/);
      });

      it('影・リングを使わない（浮き上がる表現がない）', () => {
        assert.equal(rules().includes('--tw-shadow'), false);
        assert.equal(rules().includes('--tw-ring'), false);
        assert.deepEqual([...rules().matchAll(/box-shadow:\s*(?!none)[^;}]+/g)].map((m) => m[0]), []);
      });

      it('使われている色は zinc・emerald・amber・red（と white / black）だけ。紫・青・インディゴなどが存在しない', () => {
        const families = new Set([...rules().matchAll(/--color-([a-z]+)(?:-\d+)?\s*:/g)].map((m) => m[1] ?? ''));
        assert.ok(families.has('zinc') && families.has('emerald') && families.has('amber'), `使われている色: ${[...families].join(', ')}`);
        assert.deepEqual([...families].filter((name) => !['zinc', 'emerald', 'amber', 'red', 'white', 'black'].includes(name)), []);
      });

      it('ダーク固定: color-scheme: dark を宣言し、OS のライト設定で見た目を切り替えない', () => {
        assert.match(rules(), /color-scheme:\s*dark/);
        assert.doesNotMatch(rules(), /prefers-color-scheme/);
      });

      it('フォントは OS 標準のものだけ（@font-face を持たない）。等幅（--font-mono）を定義している', () => {
        assert.doesNotMatch(rules(), /@font-face/);
        assert.match(rules(), /--font-mono:[^;]*monospace/);
      });
    });
  });
});
