/**
 * 「絶対遵守のセキュリティルール」をコードレベルで機械的に強制するテスト。
 * 人のレビューに頼らず、ルール違反のコードが入った時点で CI が落ちるようにする。
 *
 *   - フロントエンド: HTML を解釈して DOM に流し込む API と eval の使用禁止（XSS 対策）
 *   - バックエンド:   console.* の使用禁止（ログ経由の漏洩対策。ログは固定スキーマの log() のみ）
 *   - 暗号モジュール: 外部ライブラリに依存しない（Web Crypto API のみ）
 *   - バックエンド:   ランタイム依存パッケージ 0（node:* と相対 import のみ）
 *
 * 検査は正規表現ではなく TypeScript の AST で行う。コメントや文字列中の言及では誤検知しない。
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import ts from 'typescript';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** 文字列を HTML として解釈する（XSS の原因になる）プロパティ／メソッド。 */
const HTML_SINKS = new Set([
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'setHTMLUnsafe',
  'createContextualFragment',
  'parseFromString',
  'srcdoc',
]);

interface Rules {
  htmlSinks: boolean;
  console: boolean;
}

interface Violation {
  line: number;
  message: string;
}

function findViolations(source: string, rules: Rules): Violation[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const violations: Violation[] = [];
  const report = (node: ts.Node, message: string): void => {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    violations.push({ line: line + 1, message });
  };
  const isIdentifier = (node: ts.Node, name: string): boolean => ts.isIdentifier(node) && node.text === name;

  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node)) {
      const property = node.name.text;
      if (rules.htmlSinks && HTML_SINKS.has(property)) {
        report(node, `HTML を解釈する API ".${property}" は使用禁止（renderTextSafely を使うこと）`);
      }
      if (rules.htmlSinks && (property === 'write' || property === 'writeln') && isIdentifier(node.expression, 'document')) {
        report(node, `document.${property} は使用禁止`);
      }
      if (rules.console && isIdentifier(node.expression, 'console')) {
        report(node, `console.${property} は使用禁止（ログは固定スキーマの log() だけを使うこと）`);
      }
    }
    if (rules.htmlSinks && ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
      if (HTML_SINKS.has(node.argumentExpression.text)) report(node, `HTML を解釈する API ["${node.argumentExpression.text}"] は使用禁止`);
    }
    // 動的コード実行は、どちらのアプリでも常に禁止
    if (ts.isCallExpression(node) && isIdentifier(node.expression, 'eval')) report(node, 'eval は使用禁止');
    if (ts.isNewExpression(node) && isIdentifier(node.expression, 'Function')) report(node, 'new Function は使用禁止');
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return violations;
}

/** import / export from / import() / require() のモジュール指定子をすべて集める。 */
function moduleSpecifiers(source: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const specifiers: string[] = [];
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      specifiers.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && node.arguments.length > 0) {
      const [first] = node.arguments;
      const isDynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const isRequire = ts.isIdentifier(node.expression) && node.expression.text === 'require';
      if ((isDynamicImport || isRequire) && first && ts.isStringLiteralLike(first)) specifiers.push(first.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return specifiers;
}

/** テストを除く、アプリ本体の TypeScript ソース。 */
function productionSources(app: 'frontend' | 'backend'): Array<{ path: string; source: string }> {
  const dir = join(ROOT, 'apps', app, 'src');
  return readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts'))
    .map((file) => ({ path: `apps/${app}/src/${file}`, source: readFileSync(join(dir, file), 'utf8') }));
}

function format(path: string, violations: Violation[]): string[] {
  return violations.map((v) => `${path}:${v.line} ${v.message}`);
}

// ---------------------------------------------------------------------------

describe('セキュリティポリシー: アプリ本体のコード', () => {
  it('フロントエンド: HTML 挿入系 API・document.write・eval・new Function を使っていない（XSS 対策）', () => {
    const sources = productionSources('frontend');
    assert.ok(sources.length > 0, '検査対象のファイルがあること');

    const violations = sources.flatMap(({ path, source }) => format(path, findViolations(source, { htmlSinks: true, console: false })));
    assert.deepEqual(violations, []);
  });

  it('バックエンド: console.* を使っていない（ログ経由の漏洩対策）', () => {
    const sources = productionSources('backend');
    assert.ok(sources.length > 0, '検査対象のファイルがあること');

    const violations = sources.flatMap(({ path, source }) => format(path, findViolations(source, { htmlSinks: false, console: true })));
    assert.deepEqual(violations, []);
  });

  it('暗号モジュール (crypto.ts): 外部ライブラリに依存しない（相対 import のみ。Web Crypto API はグローバル）', () => {
    const cryptoModule = productionSources('frontend').find(({ path }) => path.endsWith('/crypto.ts'));
    assert.ok(cryptoModule, 'crypto.ts が存在すること');

    const external = moduleSpecifiers(cryptoModule.source).filter((specifier) => !specifier.startsWith('./') && !specifier.startsWith('../'));
    assert.deepEqual(external, []);
  });

  it('バックエンド: ランタイム依存パッケージが 0（node:* と相対 import のみ）', () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, 'apps/backend/package.json'), 'utf8')) as { dependencies?: object };
    assert.deepEqual(Object.keys(manifest.dependencies ?? {}), []);

    const external = productionSources('backend').flatMap(({ path, source }) =>
      moduleSpecifiers(source)
        .filter((specifier) => !specifier.startsWith('node:') && !specifier.startsWith('./'))
        .map((specifier) => `${path} imports "${specifier}"`),
    );
    assert.deepEqual(external, []);
  });
});

// ---------------------------------------------------------------------------
// 検査器そのものの自己テスト（違反を本当に検出できること・誤検知しないこと）
// ---------------------------------------------------------------------------

describe('セキュリティポリシー: 検査器の自己テスト', () => {
  const frontendRules: Rules = { htmlSinks: true, console: false };
  const backendRules: Rules = { htmlSinks: false, console: true };

  const violating: Array<[string, string, Rules]> = [
    ['innerHTML への代入', 'el.innerHTML = userInput;', frontendRules],
    ['outerHTML への代入', 'el.outerHTML = userInput;', frontendRules],
    ['ブラケット記法での innerHTML', "el['innerHTML'] = userInput;", frontendRules],
    ['insertAdjacentHTML', "el.insertAdjacentHTML('beforeend', userInput);", frontendRules],
    ['createContextualFragment', 'range.createContextualFragment(userInput);', frontendRules],
    ['DOMParser', "new DOMParser().parseFromString(userInput, 'text/html');", frontendRules],
    ['iframe.srcdoc', 'frame.srcdoc = userInput;', frontendRules],
    ['document.write', 'document.write(userInput);', frontendRules],
    ['eval', 'eval(userInput);', frontendRules],
    ['new Function', "new Function('return ' + userInput);", frontendRules],
    ['console.log', 'console.log(req.url);', backendRules],
    ['console.error', 'console.error(error);', backendRules],
  ];
  for (const [name, code, rules] of violating) {
    it(`違反を検出する: ${name}`, () => {
      assert.equal(findViolations(code, rules).length, 1, code);
    });
  }

  const allowed: Array<[string, string, Rules]> = [
    ['コメント中の言及', '// innerHTML は使わない\n/* eval も console.log も使わない */\nconst a = 1;', { htmlSinks: true, console: true }],
    ['文字列リテラル中の言及', "const message = 'do not use innerHTML or eval(x) or console.log';", { htmlSinks: true, console: true }],
    ['安全な DOM API', "el.replaceChildren(document.createTextNode(text)); el.textContent = 'x';", { htmlSinks: true, console: true }],
    ['独自のロガー', 'log({ event: "request" }); logger.log("x");', { htmlSinks: true, console: true }],
    ['バックエンドでは HTML 系は対象外', 'const html = el.innerHTML;', backendRules],
    ['フロントエンドでは console は対象外', 'console.log(1);', frontendRules],
  ];
  for (const [name, code, rules] of allowed) {
    it(`誤検知しない: ${name}`, () => {
      assert.deepEqual(findViolations(code, rules), []);
    });
  }

  it('モジュール指定子を import / export from / import() / require() から集められる', () => {
    const code = `
      import a from 'left-pad';
      import type { B } from './b.ts';
      export { c } from 'node:fs';
      const d = await import('dynamic-pkg');
      const e = require('legacy-pkg');
    `;
    assert.deepEqual(moduleSpecifiers(code).sort(), ['./b.ts', 'dynamic-pkg', 'left-pad', 'legacy-pkg', 'node:fs']);
  });
});
