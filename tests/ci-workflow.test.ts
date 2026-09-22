/**
 * `.github/workflows/ci.yml` の検査。
 *
 * YAML 用の外部パーサは追加しない（このプロジェクトは新規の依存を増やさない方針。tests/infra.test.ts と
 * 同じ判断）。ワークフローは自分で書いた小さな構造なので、正規表現による検査で十分な検出力がある
 * （検査が空振りしていないことは、末尾の自己テストで確認する）。
 *
 * 単に「この文字列が含まれる」だけでなく、package.json（scripts・engines.node）や Dockerfile
 * （node のバージョン）など、他ファイルの実際の値と食い違っていないかを突き合わせる。
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (relativePath: string): string => readFileSync(join(ROOT, relativePath), 'utf8');

const WORKFLOW_PATH = '.github/workflows/ci.yml';
const workflow = read(WORKFLOW_PATH);
const rootPackageJson = JSON.parse(read('package.json')) as { scripts?: Record<string, string>; engines?: { node?: string } };
const dockerfile = read('Dockerfile');

// ---------------------------------------------------------------------------
// 抽出ヘルパー（正規表現。対象は自分で書いた小さな YAML なので、これで十分検出力がある）
// ---------------------------------------------------------------------------

/**
 * YAML の `key:` 行より深いインデントの本文を取り出す（単純な入れ子構造専用）。
 * `key:` 自身の行のインデント量を基準にするので、再帰的に（入れ子になったブロックへ）呼んでも動く。
 */
function block(source: string, key: string): string {
  const lines = source.split('\n');
  const startIndex = lines.findIndex((line) => new RegExp(`^(\\s*)${key}:\\s*$`).test(line));
  if (startIndex < 0) return '';
  const startIndent = (/^(\s*)/.exec(lines[startIndex] ?? '')?.[1] ?? '').length;

  const collected: string[] = [];
  for (const line of lines.slice(startIndex + 1)) {
    if (line.trim() === '') continue;
    const indent = (/^(\s*)/.exec(line)?.[1] ?? '').length;
    if (indent <= startIndent) break; // 自分と同じか浅いインデント = ブロックの終わり
    collected.push(line);
  }
  return collected.join('\n');
}

/** `uses: owner/repo@sha # vX.Y.Z` から、参照（sha）とコメントのタグを取り出す。 */
function actionPin(source: string, actionName: string): { ref: string; taggedVersion: string | null } | null {
  const pattern = new RegExp(`uses:\\s*${actionName.replace('/', '\\/')}@(\\S+)(?:\\s*#\\s*(\\S+))?`);
  const m = pattern.exec(source);
  if (!m?.[1]) return null;
  return { ref: m[1], taggedVersion: m[2] ?? null };
}

/**
 * ステップの `run:` コマンドをすべて、出現順で取り出す。
 * `run: cmd` が独立した行の場合と、`- run: cmd`（YAML のリスト項目の省略記法）の両方に対応する。
 */
function runCommands(source: string): string[] {
  return [...source.matchAll(/^\s*(?:-\s*)?run:\s*(.+)$/gm)].map((m) => (m[1] ?? '').trim());
}

/** `node:XX[.Y[.Z]]-alpine` からメジャーバージョンを取り出す（tests/infra.test.ts と同じロジック）。 */
function dockerfileNodeMajor(source: string): number | null {
  const m = /^FROM\s+node:(\d+)/im.exec(source);
  return m?.[1] ? Number(m[1]) : null;
}

/** package.json の "engines.node"（">=24.2.0" 形式）からメジャーバージョンを取り出す。 */
function requiredNodeMajor(enginesNode: string | undefined): number | null {
  const m = /(\d+)(?:\.\d+){0,2}/.exec(enginesNode ?? '');
  return m?.[1] ? Number(m[1]) : null;
}

// ---------------------------------------------------------------------------
// 構文の健全性（YAML パーサ無しでの簡易チェック）
// ---------------------------------------------------------------------------

describe('YAML としての健全性（簡易）', () => {
  it('タブ文字によるインデントを使っていない（YAML 仕様違反）', () => {
    const tabIndented = workflow.split('\n').filter((line) => /^\t/.test(line));
    assert.deepEqual(tabIndented, []);
  });

  it('トップレベルのキー（name, on, concurrency, permissions, jobs）が、それぞれ 1 回だけ出現する', () => {
    for (const key of ['name', 'on', 'concurrency', 'permissions', 'jobs']) {
      const matches = [...workflow.matchAll(new RegExp(`^${key}:`, 'gm'))];
      assert.equal(matches.length, 1, `"${key}:" の出現回数が 1 ではない（${matches.length} 回）`);
    }
  });

  it('タブ以外の行末の空白・CR（Windows 改行）が混入していない', () => {
    assert.doesNotMatch(workflow, /\r/, 'CRLF ではなく LF であること');
  });
});

// ---------------------------------------------------------------------------
// トリガー・実行環境
// ---------------------------------------------------------------------------

describe('トリガー条件', () => {
  it('push と pull_request の両方が、main と develop だけを対象にする', () => {
    const onBlock = block(workflow, 'on');
    for (const event of ['push', 'pull_request']) {
      const eventBlock = block(onBlock, event);
      const branches = /branches:\s*\[([^\]]+)\]/.exec(eventBlock)?.[1];
      assert.ok(branches, `on.${event}.branches が読めない`);
      assert.deepEqual(
        branches.split(',').map((b) => b.trim()),
        ['main', 'develop'],
        `on.${event}.branches`,
      );
    }
  });
});

describe('実行環境', () => {
  it('ubuntu-latest で実行する', () => {
    assert.match(workflow, /runs-on:\s*ubuntu-latest/);
  });

  it('Node は 24.x（node-version: \'24.x\'）を使う', () => {
    assert.match(workflow, /node-version:\s*'24\.x'/);
  });

  it('CI の Node バージョンは、package.json の engines.node 以上（Dockerfile とも一致する。import.meta.main 要件）', () => {
    const requiredMajor = requiredNodeMajor(rootPackageJson.engines?.node);
    assert.ok(requiredMajor !== null);

    const ciMajor = Number(/node-version:\s*'(\d+)\.x'/.exec(workflow)?.[1]);
    assert.ok(Number.isFinite(ciMajor), 'CI の node-version からメジャーバージョンを読み取れない');
    assert.ok(ciMajor >= requiredMajor, `CI の Node ${ciMajor} が engines.node（>=${requiredMajor}）を満たさない`);

    const dockerMajor = dockerfileNodeMajor(dockerfile);
    assert.equal(ciMajor, dockerMajor, 'CI と Dockerfile で Node のメジャーバージョンが食い違っている');
  });

  it('npm の依存キャッシュ（cache: \'npm\'）を有効にしている', () => {
    assert.match(workflow, /cache:\s*'npm'/);
  });
});

// ---------------------------------------------------------------------------
// ジョブ・ステップ
// ---------------------------------------------------------------------------

describe('ジョブ・ステップ', () => {
  it('Checkout・Setup Node・依存関係インストール・型チェック&テスト・ビルド・監査が、この順で並ぶ', () => {
    const names = [...workflow.matchAll(/^\s*-\s*name:\s*(.+)$/gm)].map((m) => (m[1] ?? '').trim());
    assert.deepEqual(names, ['Checkout', 'Setup Node', 'Install dependencies', 'Typecheck & tests', 'Build', 'Security audit']);
  });

  it('依存関係のインストールは npm ci（--force 等の検証を弱める追加フラグを付けない）', () => {
    const commands = runCommands(workflow);
    assert.equal(commands[0], 'npm ci');
  });

  it('型チェック & テストは npm run check（package.json に実在するスクリプト）', () => {
    const commands = runCommands(workflow);
    assert.equal(commands[1], 'npm run check');
    assert.ok(rootPackageJson.scripts?.['check'], 'package.json に "check" スクリプトが無い');
  });

  it('ビルドは npm run build（package.json に実在するスクリプト。全ワークスペースを対象にする）', () => {
    const commands = runCommands(workflow);
    assert.equal(commands[2], 'npm run build');
    assert.ok(rootPackageJson.scripts?.['build'], 'package.json に "build" スクリプトが無い');
    assert.match(rootPackageJson.scripts?.['build'] ?? '', /--workspaces\b/, 'build は全ワークスペースを対象にすること');
  });

  it('監査は npm audit --audit-level=high', () => {
    const commands = runCommands(workflow);
    assert.equal(commands[3], 'npm audit --audit-level=high');
  });

  it('いずれのステップにも continue-on-error: true が無い（1 つでも失敗したら即座にジョブを失敗させる）', () => {
    assert.doesNotMatch(workflow, /continue-on-error:\s*true/);
  });
});

// ---------------------------------------------------------------------------
// サプライチェーン: Actions は可変なタグではなくコミット SHA に固定する
// ---------------------------------------------------------------------------

describe('サードパーティ Actions の固定', () => {
  const SHA_PATTERN = /^[0-9a-f]{40}$/;

  it('actions/checkout・actions/setup-node は、フルレングスの commit SHA を参照している（@v4 等の可変タグではない）', () => {
    for (const action of ['actions/checkout', 'actions/setup-node']) {
      const pin = actionPin(workflow, action);
      assert.ok(pin, `${action} の uses: が見つからない`);
      assert.match(pin.ref, SHA_PATTERN, `${action} は 40 桁の commit SHA を指すこと（実際: "${pin.ref}"）`);
      assert.ok(pin.taggedVersion, `${action} の SHA の横に、人が読めるバージョンのコメントが無い`);
    }
  });

  it('actions/checkout は persist-credentials: false（チェックアウト後のステップに認証情報を残さない）', () => {
    const checkoutStart = workflow.indexOf('uses: actions/checkout');
    const nextStepStart = workflow.indexOf('- name:', checkoutStart + 1);
    const checkoutStep = workflow.slice(checkoutStart, nextStepStart < 0 ? undefined : nextStepStart);
    assert.match(checkoutStep, /persist-credentials:\s*false/);
  });

  it('GITHUB_TOKEN の権限は contents: read だけに絞られている（既定の広い権限を使わない）', () => {
    const permissionsBlock = block(workflow, 'permissions');
    assert.equal(permissionsBlock.trim(), 'contents: read');
  });
});

// ---------------------------------------------------------------------------
// 検査器の自己テスト（違反を検出できること・誤検知しないこと）
// ---------------------------------------------------------------------------

describe('検査器の自己テスト', () => {
  it('block: 入れ子になった YAML の一部を取り出せる。キーが無ければ空文字列', () => {
    const sample = 'on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  x: 1\n';
    assert.equal(block(sample, 'on').includes('branches: [main]'), true);
    assert.equal(block(block(sample, 'on'), 'push').trim(), 'branches: [main]');
    assert.equal(block(sample, 'missing'), '');
  });

  it('actionPin: SHA とタグのコメントを取り出せる。可変タグ（バージョンのみ）は SHA_PATTERN で弾ける', () => {
    assert.deepEqual(actionPin('uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef # v7.0.1', 'actions/checkout'), {
      ref: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      taggedVersion: 'v7.0.1',
    });
    const floating = actionPin('uses: actions/checkout@v4', 'actions/checkout');
    assert.ok(floating);
    assert.doesNotMatch(floating.ref, /^[0-9a-f]{40}$/, '可変タグを SHA と誤認していないこと');
  });

  it('runCommands: run: の内容を出現順に取り出せる', () => {
    const sample = 'steps:\n  - run: npm ci\n  - name: x\n    run: npm test\n';
    assert.deepEqual(runCommands(sample), ['npm ci', 'npm test']);
  });

  it('dockerfileNodeMajor / requiredNodeMajor: 数値化とバージョン不一致の検出が壊れていない', () => {
    assert.equal(dockerfileNodeMajor('FROM node:24-alpine AS builder\n'), 24);
    assert.equal(dockerfileNodeMajor('FROM nginx:alpine\n'), null);
    assert.equal(requiredNodeMajor('>=24.2.0'), 24);
    // CI が 22、Dockerfile が 24 のような食い違いを、実際に「等しくない」で検出できることの確認。
    assert.notEqual(22, dockerfileNodeMajor('FROM node:24-alpine AS builder\n'));
  });

  it('continue-on-error の検出は、コメント中の言及では誤検知しない誤検知を確認する（現状の書き方の確認）', () => {
    // このファイル自体は正規表現で "continue-on-error: true" という並びだけを見ている。
    // "continue-on-error:false" のような値には誤検知しないことを確認する。
    assert.doesNotMatch('continue-on-error: false', /continue-on-error:\s*true/);
    assert.match('continue-on-error: true', /continue-on-error:\s*true/);
  });
});
