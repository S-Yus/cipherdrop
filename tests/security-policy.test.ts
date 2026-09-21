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

/**
 * `x.<method>(...)` の呼び出しを、それを含む「名前付き関数・メソッド」ごとに集める。
 * 名前付き関数の外（アロー関数だけ・トップレベル）なら '(top-level)'。
 */
function functionsCalling(source: string, method: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === method) {
      let owner = '(top-level)';
      for (let parent: ts.Node | undefined = node.parent; parent; parent = parent.parent) {
        if ((ts.isFunctionDeclaration(parent) || ts.isMethodDeclaration(parent)) && parent.name) {
          owner = parent.name.getText(sourceFile);
          break;
        }
      }
      names.push(owner);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names;
}

/** 名前付き関数の本体が参照しているプロパティ名（`x.foo` の foo）をすべて集める。 */
function propertiesReadInFunction(source: string, functionName: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === functionName && node.body) {
      const collect = (inner: ts.Node): void => {
        if (ts.isPropertyAccessExpression(inner)) names.push(inner.name.text);
        ts.forEachChild(inner, collect);
      };
      collect(node.body);
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names;
}

/** interface のメンバー名。 */
function interfaceMembers(source: string, interfaceName: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === interfaceName) {
      for (const member of node.members) if (member.name) names.push(member.name.getText(sourceFile));
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names;
}

/** テストを除く、アプリ本体の TypeScript ソース。 */
function productionSources(app: 'frontend' | 'backend'): Array<{ path: string; source: string }> {
  const dir = join(ROOT, 'apps', app, 'src');
  return readdirSync(dir, { recursive: true, encoding: 'utf8' })
    // テストと、テスト支援（src/testing/）は配布物に入らないので対象外
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && !file.startsWith('testing/'))
    .map((file) => ({ path: `apps/${app}/src/${file}`, source: readFileSync(join(dir, file), 'utf8') }));
}

/**
 * 名前付き関数が、自分自身の処理として呼ぶ「素の関数」（foo() 形式。x.foo() は含まない）の名前。
 * 入れ子の関数・アロー関数の中身（イベントハンドラなど、あとで実行されるもの）は含めない。
 * 「読み込み時に実行される処理から呼ばれていないこと」を検査するために使う。
 */
function plainCallsMadeBy(source: string, functionName: string): string[] {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const names: string[] = [];
  const isFunctionLike = (node: ts.Node): boolean =>
    ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node);
  const collect = (node: ts.Node): void => {
    if (isFunctionLike(node)) return; // あとで実行される入れ子の関数には入らない
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) names.push(node.expression.text);
    ts.forEachChild(node, collect);
  };
  const find = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === functionName && node.body) {
      ts.forEachChild(node.body, collect);
      return;
    }
    ts.forEachChild(node, find);
  };
  find(sourceFile);
  return names;
}

/** ソース内のすべての識別子名（変数・関数・プロパティ名など。コメントと文字列は含まない）。 */
function identifierNames(source: string): Set<string> {
  const sourceFile = ts.createSourceFile('inspected.ts', source, ts.ScriptTarget.Latest, true);
  const names = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node)) names.add(node.text);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return names;
}

/** ソース内のすべての文字列リテラル（テンプレートの固定部分を含む）。 */
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

describe('セキュリティポリシー: 2 段階消費（副作用のある操作は POST consume だけ）', () => {
  const backend = (file: string) => {
    const found = productionSources('backend').find(({ path }) => path.endsWith(`/${file}`));
    assert.ok(found, `${file} が存在すること`);
    return found.source;
  };

  it('暗号文を取り出して削除する store.take() は consumePayload だけが呼べる（GET 系ハンドラからは呼べない）', () => {
    assert.deepEqual(functionsCalling(backend('server.ts'), 'take'), ['consumePayload']);
  });

  it('メタ情報の型 PayloadMeta は type / size / expiresAt だけ。暗号文・IV を持てない', () => {
    assert.deepEqual(interfaceMembers(backend('store.ts'), 'PayloadMeta').sort(), ['expiresAt', 'size', 'type']);
  });

  it('メタ確認のハンドラ readMeta は、暗号文・IV を参照しない', () => {
    const read = propertiesReadInFunction(backend('server.ts'), 'readMeta');
    assert.ok(read.length > 0, 'readMeta が存在し、何かを読んでいること');
    assert.deepEqual(read.filter((name) => name === 'ciphertext' || name === 'iv'), []);
  });

  it('検査器の自己テスト: 違反する実装（GET 系ハンドラが take を呼ぶ・PayloadMeta に暗号文を足す）を検出できる', () => {
    assert.deepEqual(functionsCalling('async function readMeta(id) { return store.take(id); }', 'take'), ['readMeta']);
    assert.deepEqual(functionsCalling('class S { async take(id) { return 1; } }', 'take'), [], '定義は呼び出しではない');
    assert.deepEqual(
      functionsCalling('async function consumePayload(id) { const p = await ctx.store.take(id); }', 'take'),
      ['consumePayload'],
    );
    assert.deepEqual(functionsCalling('const f = () => store.take(1);', 'take'), ['(top-level)']);

    assert.deepEqual(
      interfaceMembers('export interface PayloadMeta { type: string; size: number; ciphertext: Uint8Array }', 'PayloadMeta'),
      ['type', 'size', 'ciphertext'],
    );
    assert.deepEqual(propertiesReadInFunction('function readMeta(m) { return m.ciphertext; }', 'readMeta'), ['ciphertext']);
  });
});

describe('セキュリティポリシー: フロントエンド UI', () => {
  const sources = productionSources('frontend');
  const file = (name: string): string => {
    const found = sources.find(({ path }) => path.endsWith(`/src/${name}`));
    assert.ok(found, `${name} が存在すること`);
    return found.source;
  };
  const others = (except: string[]) => sources.filter(({ path }) => !except.some((name) => path.endsWith(`/src/${name}`)));

  it('画面のファイルが検査対象に含まれている（views/ 配下・dom.ts・api.ts を取りこぼしていない）', () => {
    const names = sources.map(({ path }) => path.replace('apps/frontend/src/', ''));
    for (const expected of ['app.ts', 'api.ts', 'crypto.ts', 'dom.ts', 'download.ts', 'main.ts', 'views/send.ts', 'views/receive.ts']) {
      assert.ok(names.includes(expected), expected);
    }
    assert.equal(names.some((name) => name.startsWith('testing/') || name.endsWith('.test.ts')), false);
  });

  it('属性の設定（setAttribute 系）は dom.ts だけ。属性の許可リストを迂回して利用者由来の値を属性へ流せない', () => {
    const callers = others(['dom.ts']).flatMap(({ path, source }) =>
      ['setAttribute', 'setAttributeNS', 'setAttributeNode', 'setAttributeNodeNS'].flatMap((method) =>
        functionsCalling(source, method).map((owner) => `${path} ${owner} calls ${method}`),
      ),
    );
    assert.deepEqual(callers, []);
    assert.ok(functionsCalling(file('dom.ts'), 'setAttribute').length > 0, 'dom.ts には存在する（許可リスト経由）');
  });

  it('危険な URL スキーム（javascript: / vbscript: / data:text/html）の文字列を持たない', () => {
    const found = sources.flatMap(({ path, source }) =>
      stringLiterals(source).filter((text) => /^\s*(javascript|vbscript):|^\s*data:\s*text\/html/i.test(text)).map((text) => `${path}: ${text}`),
    );
    assert.deepEqual(found, []);
  });

  it('ネットワークアクセスは api.ts の fetch だけ。WebSocket・EventSource・XHR・sendBeacon・別の fetch はない', () => {
    const forbidden = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'importScripts'];
    const found = others(['api.ts']).flatMap(({ path, source }) => {
      const names = identifierNames(source);
      return forbidden.filter((name) => names.has(name)).map((name) => `${path} uses ${name}`);
    });
    assert.deepEqual(found, []);

    const apiNames = identifierNames(file('api.ts'));
    for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon']) assert.equal(apiNames.has(name), false, name);
  });

  it('API クライアントは、復号鍵・現在の URL（フラグメント）を参照できない（鍵をサーバーへ送る経路がない）', () => {
    const names = identifierNames(file('api.ts'));
    for (const name of ['keyString', 'location', 'hash', 'window', 'document', 'history']) {
      assert.equal(names.has(name), false, `api.ts が ${name} を参照している`);
    }
  });

  it('暗号文を消費する API（consume）を呼べるのは、受信者のボタン操作で動く open() だけ。読み込み時の load() などからは呼べない', () => {
    assert.deepEqual(functionsCalling(file('views/receive.ts'), 'consume'), ['open']);
    assert.deepEqual(functionsCalling(file('views/receive.ts'), 'getMeta'), ['load']);
    assert.deepEqual(functionsCalling(file('views/send.ts'), 'createPayload'), ['submit']);
    for (const { path, source } of others(['views/receive.ts'])) {
      assert.deepEqual(functionsCalling(source, 'consume'), [], `${path} が consume を呼んでいる`);
    }
  });

  it('読み込み時に実行される処理（mountReceiveView の本体と load）は、open() を呼ばない。open は「開く」ボタンのハンドラからだけ', () => {
    const receive = file('views/receive.ts');
    const atMount = plainCallsMadeBy(receive, 'mountReceiveView');
    assert.ok(atMount.includes('render') && atMount.includes('load'), `検査が機能している（mount 時は render / load を呼ぶ）: ${atMount.join(', ')}`);
    assert.equal(atMount.includes('open'), false, 'mount 時に open() を呼んでいる');

    const atLoad = plainCallsMadeBy(receive, 'load');
    assert.equal(atLoad.includes('open'), false, 'load() が open() を呼んでいる');
    assert.equal(atLoad.includes('consume'), false);
  });

  it('ブラウザには何も保存しない: localStorage・sessionStorage・indexedDB・Cookie・Cache・Service Worker を一切使わない', () => {
    const storageApis = ['localStorage', 'sessionStorage', 'indexedDB', 'cookie', 'caches', 'serviceWorker', 'getItem', 'setItem', 'removeItem'];
    const found = sources.flatMap(({ path, source }) => {
      const names = identifierNames(source);
      return storageApis.filter((name) => names.has(name)).map((name) => `${path} uses ${name}`);
    });
    assert.deepEqual(found, []);
  });

  it('navigator（クリップボード等）に触れるのは main.ts（環境の組み立て）だけ。画面は AppEnv.clipboard を通す', () => {
    const found = others(['main.ts']).filter(({ source }) => identifierNames(source).has('navigator')).map(({ path }) => path);
    assert.deepEqual(found, []);
    assert.equal(identifierNames(file('main.ts')).has('navigator'), true);
  });

  it('index.html: インラインのスクリプト・ハンドラ属性・style 属性がない。public/ に追加のスクリプトを置かない', () => {
    const html = readFileSync(join(ROOT, 'apps/frontend/index.html'), 'utf8');
    for (const [, attributes = '', body = ''] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
      assert.match(attributes, /\bsrc="/, 'すべての script は外部ファイル');
      assert.equal(body.trim(), '', 'インラインの本文がない');
    }
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i);
    assert.doesNotMatch(html, /\sstyle\s*=/i);
    assert.doesNotMatch(html, /<style\b/i);

    const publicFiles = readdirSync(join(ROOT, 'apps/frontend/public'));
    assert.deepEqual(publicFiles.filter((name) => /\.(js|mjs|cjs|html)$/.test(name)), [], 'public/ に配信されるスクリプトがない');
  });
});

describe('セキュリティポリシー: 追加した検査器の自己テスト', () => {
  it('識別子・文字列リテラルの収集は、コメントと文字列の中身を識別子として扱わない', () => {
    const names = identifierNames('const a = 1; // fetch\n/* location */ const s = "sessionStorage"; foo.bar(baz);');
    assert.deepEqual([...names].sort(), ['a', 'bar', 'baz', 'foo', 's']);

    assert.deepEqual(stringLiterals('const a = "javascript:alert(1)"; const b = `x${1}y`; // "no"'), ['javascript:alert(1)', 'x', 'y']);
  });

  it('plainCallsMadeBy: 関数自身の処理で呼ぶ素の関数だけを拾い、入れ子の関数（ハンドラ）の中身は含めない', () => {
    const source = 'function mount() { render(); void load(); const h = () => open(1); el.on(function () { open(2); }); obj.open(3); function inner() { open(4); } }';
    assert.deepEqual(plainCallsMadeBy(source, 'mount').sort(), ['load', 'render']);
    assert.deepEqual(plainCallsMadeBy('function other() { open(1); }', 'mount'), [], '別の関数は対象外');
    assert.deepEqual(plainCallsMadeBy('function mount() { open(1); }', 'mount'), ['open'], '本体で直接呼べば検出する');
  });

  it('setAttribute 系・fetch・consume の呼び出しを、含まれる関数ごとに検出できる', () => {
    assert.deepEqual(functionsCalling('function render() { el.setAttribute("onclick", x); }', 'setAttribute'), ['render']);
    assert.deepEqual(functionsCalling('function a() { env.api.consume(id); } function b() { env.api.consume(id); }', 'consume'), ['a', 'b']);
    assert.deepEqual(functionsCalling('function load() { return env.api.getMeta(id); }', 'consume'), []);
    assert.ok(identifierNames('async function f() { return fetch(url); }').has('fetch'));
    assert.equal(identifierNames('async function f() { return client.get(url); }').has('fetch'), false);
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
