/**
 * デザイン規則の機械的な強制。「AI が作ったような安っぽさ」が後から混入しないようにする。
 *
 * 目指す姿は、無駄を削ぎ落とした堅牢なエンタープライズ・セキュリティツール。
 *   色      ソリッドなダーク（zinc）+ アクセントは emerald と白だけ。警告 amber・エラー red は静かに。
 *           グラデーション・影・リング・任意の色（bg-[#…]）は使わない。
 *   コピー  事実とアクションだけ。キャッチコピー・形容詞過剰な文言・感嘆符・絵文字を使わない。
 *   構成    ヒーロー・3 並びの特長欄・フッターを置かない。開いた瞬間にメインタスクだけが見える。
 *
 * class 文字列と UI 文言は TypeScript の AST から集める（コメントは対象外）。配布物の CSS への反映は
 * tests/build-output.test.ts が検査している。
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import ts from 'typescript';
import { ui } from '../apps/frontend/src/ui.ts';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = join(ROOT, 'apps/frontend/src');

/** 配布される TypeScript ソース（テスト・テスト支援を除く）。 */
function sources(): Array<{ path: string; source: string }> {
  return readdirSync(SRC, { recursive: true, encoding: 'utf8' })
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && !file.startsWith('testing/'))
    .map((file) => ({ path: file, source: readFileSync(join(SRC, file), 'utf8') }));
}

/** ソース内のすべての文字列リテラル（テンプレートの固定部分を含む）。class 文字列も UI 文言もここに含まれる。 */
function stringLiterals(source: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const values: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isStringLiteralLike(node)) values.push(node.text);
    else if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) values.push(node.text);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return values;
}

/** dom.h('<tag>', …) で作られる HTML 要素のタグ名。 */
function createdTags(source: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const tags: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'h') {
      const [first] = node.arguments;
      if (first && ts.isStringLiteralLike(first)) tags.push(first.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return tags;
}

/** HTML の class 属性（index.html の noscript など）。 */
function htmlClassStrings(html: string): string[] {
  return [...html.matchAll(/\sclass="([^"]*)"/g)].map((m) => m[1] ?? '');
}

/** 文字列を class トークン（variant つきのまま）に分ける。 */
function classTokens(strings: string[]): string[] {
  return strings.flatMap((text) => text.split(/\s+/)).filter(Boolean);
}

/** variant（hover: / sm: / has-checked: / dark: など）の部分。 */
const variantsOf = (token: string): string => /^((?:[a-z0-9-]+:)+)/.exec(token)?.[1] ?? '';
/** variant を外した、ユーティリティ本体。 */
const baseOf = (token: string): string => token.slice(variantsOf(token).length);

const COLOR_FAMILIES = ['slate', 'gray', 'zinc', 'neutral', 'stone', 'red', 'orange', 'amber', 'yellow', 'lime', 'green', 'emerald', 'teal', 'cyan', 'sky', 'blue', 'indigo', 'violet', 'purple', 'fuchsia', 'pink', 'rose'];
const ALLOWED_FAMILIES = new Set(['zinc', 'neutral', 'emerald', 'amber', 'red']);
const COLOR_UTILITY = new RegExp(`^(?:bg|text|border(?:-[xytblrse])?|outline|ring|fill|stroke|divide|decoration|caret|accent|placeholder|from|via|to)-(${COLOR_FAMILIES.join('|')})-\\d+(?:/\\d+)?$`);

/** class トークン（variant つき）のデザイン規則違反を、理由つきで返す。 */
function designViolations(rawTokens: string[]): Array<{ token: string; reason: string }> {
  const violations: Array<{ token: string; reason: string }> = [];
  for (const raw of rawTokens) {
    const base = baseOf(raw);
    const report = (reason: string): void => void violations.push({ token: raw, reason });

    const family = COLOR_UTILITY.exec(base)?.[1];
    if (family !== undefined && !ALLOWED_FAMILIES.has(family)) report('許可された色（zinc / neutral / emerald / amber / red）以外');
    if (/^(?:bg|text|border|outline|fill|stroke|from|via|to)-\[(?:#|rgb|hsl|hwb|lab|lch|oklab|oklch|color\()/.test(base)) report('任意の色の直接指定');
    if (/^bg-(?:gradient|linear|radial|conic)/.test(base) || /^(?:from|via|to)-(?:[a-z]+-\d|\[|transparent|current|white|black)/.test(base)) report('グラデーション');
    if (/^(?:(?:drop|inset|text)-)?shadow(?:-(?!none$).+)?$/.test(base) || /^(?:inset-)?ring(?:-|$)/.test(base)) report('影・リング');
    if (/(?:^|:)(?:dark|light):/.test(variantsOf(raw))) report('ダーク固定なので light / dark の切替 variant は使わない');
  }
  return violations;
}

// ---------------------------------------------------------------------------

describe('デザイン規則: 色（Dark & Solid）', () => {
  const all = sources();
  const html = readFileSync(join(ROOT, 'apps/frontend/index.html'), 'utf8');
  const rawTokens = classTokens([...all.flatMap(({ source }) => stringLiterals(source)), ...htmlClassStrings(html)]);
  const tokens = rawTokens.map(baseOf);

  it('検査の対象に、指定されたパレット・等幅・警告色の class が含まれている（検査が空振りしていない）', () => {
    for (const expected of ['bg-zinc-950', 'border-zinc-800', 'bg-zinc-900/50', 'font-mono', 'border-amber-500/20', 'bg-amber-500/5', 'text-emerald-500', 'bg-emerald-500', 'bg-white', 'text-black']) {
      assert.ok(tokens.includes(expected), `${expected} が使われていない`);
    }
  });

  it('class の色は zinc・neutral・emerald・amber・red だけ。紫・青・インディゴなどを使わない', () => {
    const usedFamilies = new Set(tokens.map((token) => COLOR_UTILITY.exec(token)?.[1]).filter((family): family is string => family !== undefined));
    assert.ok(usedFamilies.has('zinc') && usedFamilies.has('emerald') && usedFamilies.has('amber'), [...usedFamilies].join(', '));
    assert.deepEqual([...usedFamilies].filter((family) => !ALLOWED_FAMILIES.has(family)), []);
  });

  it('グラデーション・影・リング・任意の色（bg-[#…]）・light/dark の切替 variant を使わない', () => {
    assert.deepEqual(designViolations(rawTokens), []);
  });

  it('ページの背景は bg-zinc-950 のソリッド。CSS に色の直書き・グラデーション・影・外部フォントがない', () => {
    const css = readFileSync(join(SRC, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.match(css, /@apply\s+bg-zinc-950/);
    assert.doesNotMatch(css, /gradient\(/);
    assert.doesNotMatch(css, /box-shadow|text-shadow|drop-shadow/);
    assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(|oklch\(/, '色は Tailwind のパレット経由だけ（直書きしない）');
    assert.doesNotMatch(css, /@font-face|@import\s+url/);
  });

  it('ダーク固定: color-scheme: dark を宣言し、OS のライト設定で見た目を切り替えない', () => {
    const css = readFileSync(join(SRC, 'styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.match(css, /color-scheme:\s*dark/);
    assert.doesNotMatch(css, /prefers-color-scheme|data-theme/);
    assert.match(html, /<meta name="color-scheme" content="dark"/);
  });
});

describe('デザイン規則: タイポグラフィ（等幅は精密な値だけ）', () => {
  it('鍵・URL・サイズ・期限・入力面・選択肢・ステータスは等幅。見出しと説明文は等幅にしない（sans-serif）', () => {
    for (const name of ['editor', 'select', 'rowValue', 'codeBlock', 'mutedMono'] as const) {
      assert.match(ui[name], /\bfont-mono\b/, `ui.${name}`);
    }
    for (const name of ['h1', 'sub', 'label'] as const) {
      assert.doesNotMatch(ui[name], /\bfont-mono\b/, `ui.${name}`);
    }
  });

  it('入力面はコードエディタ調（bg-zinc-950 / border-zinc-800 / font-mono）', () => {
    for (const name of ['bg-zinc-950', 'border-zinc-800', 'font-mono']) assert.match(ui.editor, new RegExp(`\\b${name}\\b`), name);
  });
});

describe('デザイン規則: コピー（事実とアクションだけ）', () => {
  const html = readFileSync(join(ROOT, 'apps/frontend/index.html'), 'utf8');
  const visibleText = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '').replace(/<[^>]+>/g, ' ');
  /** 画面に出る文言を持つソース。 */
  const uiSources = sources().filter(({ path }) => path.startsWith('views/') || path === 'app.ts' || path === 'ui.ts');
  const corpus = [...uiSources.flatMap(({ source }) => stringLiterals(source)), visibleText];

  const HYPE_JA = ['シームレス', '次世代', '最先端', '革新', '魔法', 'マジック', '圧倒的', '究極', 'かんたん', '簡単', '誰でも', 'あなたの大切', '大切な情報', '安心して', '快適', 'スマート', 'パワフル', 'ワンストップ', 'お任せ', 'おすすめ', 'スピーディ', '洗練', '未来'];
  const HYPE_EN = /empower|seamless|magic|next-?gen|revolution|supercharge|unlock|effortless|cutting-?edge|world-?class|blazing|delight|why choose/i;

  it('検査の対象に、実際の UI 文言が含まれている（検査が空振りしていない）', () => {
    const text = corpus.join('\n');
    for (const expected of ['暗号化リンクを生成', 'データを復号して表示', 'データを復号してダウンロード', 'このデータは一度開くとサーバーから永久削除されます', 'この鍵はサーバーを経由していません']) {
      assert.ok(text.includes(expected), expected);
    }
  });

  it('マーケティング的な語・キャッチコピーを使わない', () => {
    const text = corpus.join('\n');
    assert.deepEqual(HYPE_JA.filter((word) => text.includes(word)), []);
    assert.equal(HYPE_EN.test(text), false, text.match(HYPE_EN)?.[0]);
  });

  it('感嘆符・絵文字・装飾記号（✓ ★ → ● など）を使わない', () => {
    const text = corpus.join('\n');
    assert.deepEqual([...text.matchAll(/[!！]/g)].map((m) => m[0]), [], '感嘆符');
    // ⌘（キー名の表記）だけは記号として使う
    assert.deepEqual([...text.replaceAll('⌘', '').matchAll(/\p{Extended_Pictographic}/gu)].map((m) => m[0]), [], '絵文字');
    assert.deepEqual([...text.matchAll(/[←-⇿☀-➿⬀-⯿■-◿]/g)].map((m) => m[0]), [], '装飾記号・矢印');
  });

  it('画面のタイトルとボタンは、目的が明確（ボタンは動詞で終わる）', () => {
    const text = corpus.join('\n');
    for (const label of ['暗号化リンクを生成', 'リンクをコピー', 'データを復号して表示', 'データを復号してダウンロード', 'コピー', '破棄', '再ダウンロード', '新規共有']) {
      assert.ok(text.includes(label), label);
    }
  });
});

describe('デザイン規則: 構成（タスクだけに集中する）', () => {
  it('リスト・フッター・画像・ナビゲーションなど、特長欄やヒーローを作る要素を生成しない', () => {
    const banned = new Set(['ul', 'ol', 'li', 'footer', 'aside', 'nav', 'figure', 'img', 'picture', 'video', 'canvas', 'iframe', 'blockquote', 'h2', 'h3']);
    const found = sources().flatMap(({ path, source }) => createdTags(source).filter((tag) => banned.has(tag)).map((tag) => `${path}: <${tag}>`));
    assert.deepEqual(found, []);
  });

  it('見出しは各画面 1 つの h1 だけ（h2 以下の「選ばれる理由」のような節を作らない）', () => {
    const tags = sources().flatMap(({ source }) => createdTags(source));
    assert.ok(tags.includes('h1'));
    assert.equal(tags.filter((tag) => /^h[2-6]$/.test(tag)).length, 0);
  });
});

describe('デザイン規則: 検査器の自己テスト（違反を本当に検出できること・誤検知しないこと）', () => {
  it('AI 的な配色・装飾（グラデーション・紫・影・リング・任意色・light/dark 切替）を検出する', () => {
    const bad = classTokens(['bg-gradient-to-r from-purple-500 to-blue-500 shadow-lg ring-1 text-indigo-400 bg-[#7c3aed] hover:bg-violet-600 dark:bg-zinc-900 shadow-md drop-shadow-xl light:text-zinc-100']);
    const found = designViolations(bad).map((v) => v.token);
    for (const expected of bad) assert.ok(found.includes(expected), `${expected} を検出できていない`);
    // 1 つのトークンが複数の規則に違反することがある（from-purple-500 は「色」と「グラデーション」）ので、集合で比べる。
    assert.deepEqual([...new Set(found)].sort(), [...bad].sort(), '違反しているトークンだけを報告する');
  });

  it('許可された class は違反にならない（variant 付き・透明度付き・shadow-none を含む）', () => {
    const good = classTokens(['bg-zinc-950 border-zinc-800 bg-zinc-900/50 hover:bg-zinc-800 focus:border-zinc-600 text-emerald-500 bg-emerald-500/10 border-amber-500/20 bg-red-500/5 shadow-none font-mono text-sm has-checked:border-emerald-500 placeholder:text-zinc-400 bg-white text-black sm:p-6 motion-safe:animate-spin']);
    assert.deepEqual(designViolations(good), []);
  });

  it('createdTags は dom.h の第 1 引数だけを拾う', () => {
    assert.deepEqual(createdTags("dom.h('ul', {}, dom.h('li', {}, 'x')); other.push('footer'); dom.svg('path', {});"), ['ul', 'li']);
  });
});
