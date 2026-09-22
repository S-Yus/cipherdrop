/**
 * B2B・OSS 展開向けの文書（PRIVACY.md・TERMS.md・SECURITY.md・docs/SECURITY_WHITEPAPER.md・
 * security.txt）の検査。
 *
 *   - 各文書が存在すること
 *   - 必須の暗号・セキュリティ用語が実際に含まれていること
 *   - 文書内のリンクが壊れていないこと（相対パスは実在するファイルを指し、見出しへのアンカーは
 *     実在する見出しのスラッグと一致する）
 *
 * リンク切れの検査は「相対パス・アンカー」だけを対象にする（決定的で、ネットワーク不要、CI で安定する）。
 * 外部 URL（https://…）は形式だけを検査し、実際に到達できるかはライブでは検証しない
 * （tests/infra.test.ts・tests/ci-workflow.test.ts と同じ、新規の外部依存・ネットワーク依存を
 * 増やさない方針。cloudflared のタグ・GitHub Actions の SHA 等と同様、値そのものはこのセッション内で
 * 個別に確認済み）。
 *
 * 見出しのスラッグ（`#見出し` のアンカーが指す ID）は GitHub の実際のアルゴリズムに基づく
 * （Unicode の文字・数字・結合文字・空白・アンダースコア・ハイフンだけを残し、他の記号を除去してから
 * 空白をハイフンに置換する）。これは github-slugger パッケージの正規表現と、実際に使っている見出し
 * すべてで出力が一致することを確認済み。パッケージ自体は依存に追加していない。
 */
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (relativePath: string): string => readFileSync(join(ROOT, relativePath), 'utf8');

const DOCS = {
  privacy: 'PRIVACY.md',
  terms: 'TERMS.md',
  security: 'SECURITY.md',
  whitepaper: 'docs/SECURITY_WHITEPAPER.md',
  securityTxt: 'apps/frontend/public/.well-known/security.txt',
} as const;

// ---------------------------------------------------------------------------
// 抽出ヘルパー
// ---------------------------------------------------------------------------

interface MdLink {
  text: string;
  target: string;
  line: number;
}

/** `[text](target)` 形式のリンクをすべて、出現順・行番号つきで取り出す。 */
function extractLinks(source: string): MdLink[] {
  const links: MdLink[] = [];
  const lines = source.split('\n');
  const pattern = /\[([^\]]*)\]\(([^)]+)\)/g;
  lines.forEach((line, index) => {
    for (const m of line.matchAll(pattern)) {
      links.push({ text: m[1] ?? '', target: m[2] ?? '', line: index + 1 });
    }
  });
  return links;
}

/**
 * Markdown の見出し（`#`〜`######`）を、フェンスコードブロック（``` ）の中身を除いて取り出す。
 * コードブロック中の `# コメント` を見出しと誤認しないようにするため。
 */
function extractHeadings(source: string): string[] {
  const headings: string[] = [];
  let inFence = false;
  for (const line of source.split('\n')) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (m?.[1]) headings.push(m[1]);
  }
  return headings;
}

/**
 * GitHub と同じ方式で見出しテキストをスラッグ（アンカー ID）に変換する。
 * 文字・数字・結合文字・空白・アンダースコア・ハイフン以外を除去し、小文字化してから空白をハイフンに
 * 置換する（連続するハイフンはそのまま。GitHub 自身も畳まない）。
 */
function slugify(heading: string): string {
  return heading
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '')
    .replace(/\s/g, '-');
}

/** リンク先が外部 URL（http/https/mailto 等のスキームを持つ）かどうか。 */
function isExternal(target: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(target);
}

interface LinkCheckResult {
  ok: boolean;
  reason?: string;
}

/**
 * 1 つのリンクを検査する。fromFile はリンクが書かれているファイルの、リポジトリルートからの相対パス。
 * 外部 URL は https:// あるいは mailto: の形式であることだけを見る（到達性はライブ検証しない）。
 */
function checkLink(fromFile: string, target: string): LinkCheckResult {
  if (isExternal(target)) {
    if (/^mailto:[^@\s]+@[^@\s]+$/.test(target)) return { ok: true };
    if (/^https:\/\/\S+$/.test(target)) return { ok: true };
    return { ok: false, reason: `外部リンクが https:// でも mailto: でもない: ${target}` };
  }

  const [pathPart = '', anchor] = target.split('#');
  const fromDir = dirname(join(ROOT, fromFile));
  const resolvedPath = pathPart === '' ? join(ROOT, fromFile) : resolve(fromDir, pathPart);

  if (!existsSync(resolvedPath)) {
    return { ok: false, reason: `参照先が存在しない: ${target}（解決後: ${relative(ROOT, resolvedPath)}）` };
  }

  if (anchor === undefined) return { ok: true };

  if (statSync(resolvedPath).isDirectory()) {
    return { ok: false, reason: `ディレクトリにアンカーは付けられない: ${target}` };
  }
  const headings = extractHeadings(readFileSync(resolvedPath, 'utf8'));
  const slugs = headings.map(slugify);
  if (!slugs.includes(anchor)) {
    return { ok: false, reason: `アンカー "#${anchor}" に一致する見出しが無い（${relative(ROOT, resolvedPath)} の見出し: ${slugs.join(', ')}）` };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// 文書の存在
// ---------------------------------------------------------------------------

describe('必須文書が存在する', () => {
  for (const [name, path] of Object.entries(DOCS)) {
    it(`${name}: ${path}`, () => {
      assert.ok(existsSync(join(ROOT, path)), `${path} が存在しない`);
    });
  }
});

// ---------------------------------------------------------------------------
// 必須用語
// ---------------------------------------------------------------------------

describe('必須の暗号・セキュリティ用語', () => {
  const REQUIRED_TERMS: Record<string, string[]> = {
    [DOCS.privacy]: ['ゼロ知識', 'AES-256-GCM', 'ゼロログ', 'Cookie', '鍵確認値'],
    [DOCS.terms]: ['一時的', '免責事項', '復元', '法令に違反'],
    [DOCS.security]: ['ゼロ知識', 'Responsible Disclosure', '脅威モデル', 'PGP', 'RFC 9116'],
    [DOCS.whitepaper]: ['ゼロ知識', 'AES-256-GCM', 'AES-GCM', '2 段階', 'Key Check Tag', '鍵確認値', 'SHA-256'],
  };

  for (const [path, terms] of Object.entries(REQUIRED_TERMS)) {
    describe(path, () => {
      const content = read(path);
      for (const term of terms) {
        it(`"${term}" を含む`, () => {
          assert.ok(content.includes(term), `${path} に "${term}" が見つからない`);
        });
      }
    });
  }

  it('鍵確認値の技術文書は、PBKDF2 等のパスワード鍵導出関数を「使わない」ことを明示している（実装との食い違い防止）', () => {
    // apps/frontend/src/crypto.ts は crypto.subtle.generateKey による CSPRNG 鍵生成のみを行い、
    // パスワードから鍵を導出する処理（PBKDF2 等）を一切持たない。ホワイトペーパーがこれと矛盾して
    // 「PBKDF2 を使っている」という誤った印象を与えていないかを検査する。
    const whitepaper = read(DOCS.whitepaper);
    assert.match(whitepaper, /PBKDF2/, 'PBKDF2 についての説明が無い（なぜ使わないかを書く想定）');
    assert.match(whitepaper, /PBKDF2[^\n]*使用しない|使用しない[^\n]*PBKDF2/, 'PBKDF2 を「使わない」と明示していない');

    const cryptoSource = read('apps/frontend/src/crypto.ts');
    assert.doesNotMatch(cryptoSource, /PBKDF2|pbkdf2/i, '実装側に PBKDF2 が実在しないこと（無いと書いた説明が正しいことの裏付け）');
  });

  it('法的文書（PRIVACY / TERMS）は、公開前に専門家のレビューが必要であることを明示している', () => {
    for (const path of [DOCS.privacy, DOCS.terms]) {
      assert.match(read(path), /専門家|弁護士/, `${path} に専門家レビューの注記が無い`);
    }
  });
});

// ---------------------------------------------------------------------------
// リンク切れ
// ---------------------------------------------------------------------------

describe('リンク切れが無い', () => {
  const allDocs = [DOCS.privacy, DOCS.terms, DOCS.security, DOCS.whitepaper, 'README.md'];

  for (const path of allDocs) {
    describe(path, () => {
      const links = extractLinks(read(path));

      it('検査対象のリンクが 1 本以上ある（空振り防止）', () => {
        assert.ok(links.length > 0, `${path} にリンクが 1 本も見つからない`);
      });

      for (const link of links) {
        it(`${link.line}行目: ${link.target}`, () => {
          const result = checkLink(path, link.target);
          assert.ok(result.ok, result.reason);
        });
      }
    });
  }
});

// ---------------------------------------------------------------------------
// security.txt（RFC 9116）
// ---------------------------------------------------------------------------

describe('.well-known/security.txt（RFC 9116）', () => {
  const content = read(DOCS.securityTxt);

  it('Contact フィールドを持つ（必須）', () => {
    assert.match(content, /^Contact:\s*\S+/m);
  });

  it('Expires フィールドを持ち、未来の日時を指している（必須。期限切れなら更新を促す意図で検査自体を落とす）', () => {
    const value = /^Expires:\s*(\S+)/m.exec(content)?.[1];
    assert.ok(value, 'Expires フィールドが無い');
    const expires = new Date(value);
    assert.ok(!Number.isNaN(expires.getTime()), `Expires の値が日時として解釈できない: ${value}`);
    assert.ok(expires.getTime() > Date.now(), `Expires (${value}) が過去になっている。更新すること`);
  });

  it('Policy が SECURITY.md を指している', () => {
    assert.match(content, /^Policy:\s*https:\/\/\S+SECURITY\.md\s*$/m);
  });

  it('ビルド後に apps/frontend/dist/.well-known/security.txt として配信される（public/ 配下にある）', () => {
    assert.equal(DOCS.securityTxt, 'apps/frontend/public/.well-known/security.txt');
  });
});

// ---------------------------------------------------------------------------
// 検査器の自己テスト
// ---------------------------------------------------------------------------

describe('検査器の自己テスト', () => {
  it('extractHeadings: フェンスコードブロック内の "#" をコメントを見出しと誤認しない', () => {
    const sample = '# 本物の見出し\n\n```bash\n# これはシェルのコメント\ncurl example\n```\n\n## もう 1 つの見出し\n';
    assert.deepEqual(extractHeadings(sample), ['本物の見出し', 'もう 1 つの見出し']);
  });

  it('extractHeadings: 見出し末尾の飾り "###" (ATX closing) を取り除く', () => {
    assert.deepEqual(extractHeadings('## 見出し ##\n'), ['見出し']);
  });

  it('slugify: 実際の見出し（日英混在・全角括弧・矢印・数字）で、GitHub の実際の挙動と一致する', () => {
    // github-slugger（Flet/github-slugger の regex.js）と同じ入力で照合済みの期待値。
    const cases: Array<[string, string]> = [
      ['信頼モデルと既知の制約', '信頼モデルと既知の制約'],
      ['Docker でのデプロイ', 'docker-でのデプロイ'],
      ['仕組み（確認 → 消費の 2 段階）', '仕組み確認--消費の-2-段階'],
      ['鍵確認値（Key Check Tag）', '鍵確認値key-check-tag'],
      ['English Summary', 'english-summary'],
    ];
    for (const [heading, expected] of cases) assert.equal(slugify(heading), expected, heading);
  });

  it('checkLink: 存在しないファイル・存在しないアンカーを検出できる（自己テスト）', () => {
    const missing = checkLink('README.md', 'no-such-file.md');
    assert.equal(missing.ok, false);

    const badAnchor = checkLink('SECURITY.md', 'README.md#no-such-heading-xyz');
    assert.equal(badAnchor.ok, false);
  });

  it('checkLink: 正しいファイル・正しいアンカー・外部 URL は通す（自己テスト）', () => {
    assert.equal(checkLink('PRIVACY.md', 'SECURITY.md').ok, true);
    assert.equal(checkLink('SECURITY.md', 'README.md#信頼モデルと既知の制約').ok, true);
    assert.equal(checkLink('README.md', 'https://example.com/x').ok, true);
    assert.equal(checkLink('README.md', 'mailto:security@example.com').ok, true);
  });

  it('checkLink: http（https ではない）や妙な形式の外部リンクは拒否する（自己テスト）', () => {
    assert.equal(checkLink('README.md', 'http://example.com').ok, false);
    assert.equal(checkLink('README.md', 'ftp://example.com').ok, false);
  });

  it('extractLinks: 1 行に複数リンクがあっても、両方とも行番号つきで取り出せる', () => {
    const links = extractLinks('本文 [a](x.md) と [b](y.md#z) がある行\n');
    assert.deepEqual(
      links.map((l) => `${l.line}:${l.text}:${l.target}`),
      ['1:a:x.md', '1:b:y.md#z'],
    );
  });
});
