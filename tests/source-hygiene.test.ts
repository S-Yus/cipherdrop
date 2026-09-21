/**
 * ソースの衛生: 生の制御文字・不可視文字・双方向制御文字をリポジトリに入れない。
 *
 * 「Trojan Source」（CVE-2021-42574）は、双方向制御文字（U+202A〜U+202E, U+2066〜U+2069）をソースや
 * コメントに紛れ込ませ、人間の目に見えるコードとコンパイラが解釈するコードをずらす攻撃。
 * 「読めば検証できる」ことが価値のこのプロジェクトでは、見えない文字を一切許さない。
 * テストで危険な文字を入力に使うときは、エスケープ（u + 16 進）か String.fromCodePoint で書く。
 *
 * このファイル自身にも該当文字を書かない（コードポイントは数値表で持つ）。
 */
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** 許可する制御文字: タブ・LF・CR。 */
const ALLOWED_CONTROLS = new Set([0x09, 0x0a, 0x0d]);

/** 許可しないコードポイントの範囲 [下限, 上限, 名前]。 */
const FORBIDDEN_RANGES: ReadonlyArray<readonly [number, number, string]> = [
  [0x00, 0x1f, 'C0 制御文字（NUL・ESC など）'],
  [0x7f, 0x9f, 'DEL・C1 制御文字'],
  [0x00ad, 0x00ad, 'ソフトハイフン'],
  [0x061c, 0x061c, 'アラビア文字マーク'],
  [0x200b, 0x200f, 'ゼロ幅文字・方向マーク'],
  [0x2028, 0x202e, '行・段落区切り、双方向の埋め込み・上書き（LRE, RLE, PDF, LRO, RLO）'],
  [0x2060, 0x206f, '不可視の書式文字、双方向アイソレート（LRI, RLI, FSI, PDI）'],
  [0xfeff, 0xfeff, 'BOM・ゼロ幅ノーブレークスペース'],
  [0xfff9, 0xfffb, '注釈アンカー'],
];

/** 走査しないディレクトリ（依存物・生成物）。 */
const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'dist-test', 'coverage']);
const BINARY_FILE = /\.(png|jpe?g|gif|ico|webp|woff2?|ttf|otf|pdf|zip|gz)$/i;

interface Finding {
  file: string;
  line: number;
  column: number;
  codePoint: number;
}

const forbiddenReason = (unit: number): string | undefined => {
  if (ALLOWED_CONTROLS.has(unit)) return undefined;
  return FORBIDDEN_RANGES.find(([low, high]) => unit >= low && unit <= high)?.[2];
};

const label = (finding: Finding): string =>
  `${finding.file}:${finding.line}:${finding.column} U+${finding.codePoint.toString(16).toUpperCase().padStart(4, '0')}`;

/** 文字列中の該当文字を、行・列（UTF-16 コード単位、1 始まり）つきで返す。 */
function scanText(file: string, text: string): Finding[] {
  const findings: Finding[] = [];
  let line = 1;
  let column = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit === 0x0a) {
      line++;
      column = 0;
      continue;
    }
    column++;
    if (forbiddenReason(unit) !== undefined) findings.push({ file, line, column, codePoint: unit });
  }
  return findings;
}

/** root 以下のテキストファイル（依存物・生成物・バイナリを除く）。 */
function listTextFiles(root: string): string[] {
  const found: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) visit(join(directory, entry.name));
      } else if (entry.isFile() && !BINARY_FILE.test(entry.name)) {
        found.push(join(directory, entry.name));
      }
    }
  };
  visit(root);
  return found;
}

const relativePath = (root: string, path: string): string => relative(root, path).split(sep).join('/');

function findRawControlCharacters(root: string): Finding[] {
  return listTextFiles(root).flatMap((path) => scanText(relativePath(root, path), readFileSync(path, 'utf8')));
}

describe('ソースの衛生: 生の制御文字・不可視文字・双方向制御文字を含めない', () => {
  it('リポジトリのテキストファイル（ソース・テスト・設定・文書）に、該当文字が 1 つもない', () => {
    // 失敗時は「ファイル:行:列 U+XXXX」の一覧が出る。必要な文字はエスケープで書く。
    assert.deepEqual(findRawControlCharacters(ROOT).map(label), []);
  });

  it('走査の対象は十分に広い（主要なソース・設定・文書を含み、依存物を含まない）', () => {
    const files = listTextFiles(ROOT).map((path) => relativePath(ROOT, path));
    for (const expected of [
      'apps/backend/src/server.ts',
      'apps/frontend/src/file-name.ts',
      'apps/frontend/src/views/send.ts',
      'apps/frontend/index.html',
      'tests/security-policy.test.ts',
      'package.json',
      'README.md',
    ]) {
      assert.ok(files.includes(expected), `${expected} が走査対象に入っていない`);
    }
    assert.ok(files.length >= 40, `走査対象が少なすぎる（${files.length} 件）`);
    assert.equal(files.some((file) => file.split('/').includes('node_modules')), false);
  });

  it('検出器の自己検証: 分類ごとの代表文字を、位置つきで検出する', () => {
    const representatives: Array<[string, number]> = [
      ['NUL', 0x0000],
      ['ESC', 0x001b],
      ['DEL', 0x007f],
      ['C1 (NEL)', 0x0085],
      ['ソフトハイフン', 0x00ad],
      ['ALM', 0x061c],
      ['ゼロ幅スペース', 0x200b],
      ['ゼロ幅接合子', 0x200d],
      ['LRM', 0x200e],
      ['RLM', 0x200f],
      ['行区切り', 0x2028],
      ['LRE', 0x202a],
      ['RLO', 0x202e],
      ['単語結合子', 0x2060],
      ['LRI', 0x2066],
      ['RLI', 0x2067],
      ['FSI', 0x2068],
      ['PDI', 0x2069],
      ['BOM', 0xfeff],
      ['注釈アンカー', 0xfff9],
    ];
    for (const [name, codePoint] of representatives) {
      const found = scanText('sample.ts', `ab\nc${String.fromCodePoint(codePoint)}d`);
      assert.deepEqual(found, [{ file: 'sample.ts', line: 2, column: 2, codePoint }], name);
    }
  });

  it('検出器の自己検証: タブ・改行・CR・日本語・記号・ASCII は検出しない', () => {
    const benign = 'const a = 1;\n\tconst b = "受信データ — CipherDrop「確認」";\r\n{ } [ ] / \\ ~ \u{1F512}\n';
    assert.deepEqual(scanText('benign.ts', benign), []);
  });

  it('検出器の自己検証: 実ファイルを読み、ファイル・行・列を報告する。依存物のディレクトリは走査しない', () => {
    const dir = mkdtempSync(join(tmpdir(), 'source-hygiene-'));
    try {
      mkdirSync(join(dir, 'src'));
      mkdirSync(join(dir, 'node_modules'));
      const prefix = "const name = 'x";
      writeFileSync(join(dir, 'src', 'a.ts'), `const ok = 1;\n${prefix}${String.fromCodePoint(0x202e)}y';\n`);
      writeFileSync(join(dir, 'node_modules', 'ignored.js'), String.fromCodePoint(0x202e));
      writeFileSync(join(dir, 'clean.md'), '問題なし\n');

      assert.deepEqual(findRawControlCharacters(dir).map(label), [`src/a.ts:2:${prefix.length + 1} U+202E`]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
