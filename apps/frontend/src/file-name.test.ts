import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { FALLBACK_FILE_NAME, hasRiskyExtension, sanitizeFileName } from './file-name.ts';

describe('sanitizeFileName（送信者が決めた名前は信頼しない）', () => {
  const cases: Array<[string, string, string]> = [
    // [説明, 入力, 期待]
    ['通常の名前はそのまま', 'report.pdf', 'report.pdf'],
    ['日本語・全角記号・空白もそのまま', '契約書_最終版 (確定).pdf', '契約書_最終版 (確定).pdf'],
    ['ディレクトリ・トラバーサル', '../../etc/passwd', '_.._etc_passwd'],
    ['Windows のパス', 'C:\\Windows\\system32\\evil.exe', 'C__Windows_system32_evil.exe'],
    ['先頭のドット（隠しファイル化）', '.bashrc', 'bashrc'],
    ['ドットだけ', '..', FALLBACK_FILE_NAME],
    ['ドットと空白だけ', ' . . ', FALLBACK_FILE_NAME],
    ['空文字', '', FALLBACK_FILE_NAME],
    ['末尾のドット・空白（Windows が黙って削る）', 'name.txt. ', 'name.txt'],
    ['NUL 文字での拡張子隠し', 'invoice.pdf\u0000.exe', 'invoice.pdf.exe'],
    ['制御文字（改行・タブ・DEL・C1）', 'a\n\tb\u007fc\u0085d.txt', 'abcd.txt'],
    ['双方向制御文字（RLO で拡張子を偽装）', 'invoice_\u202Efdp.exe', 'invoice_fdp.exe'],
    ['ゼロ幅文字・BOM', 'a\u200bb\u2060c\ufeffd.pdf', 'abcd.pdf'],
    ['Windows でファイル名に使えない文字', 'a*b?c"d<e>f|g.txt', 'a_b_c_d_e_f_g.txt'],
    ['Windows の予約名（CON）', 'CON', '_CON'],
    ['Windows の予約名（拡張子つき・小文字）', 'con.txt', '_con.txt'],
    ['Windows の予約名（複数拡張子）', 'NUL.tar.gz', '_NUL.tar.gz'],
    ['Windows の予約名（COM1）', 'COM1', '_COM1'],
    ['予約名に似ているだけの名前は変更しない', 'console.txt', 'console.txt'],
    ['LPT10 は予約名ではない', 'LPT10.txt', 'LPT10.txt'],
  ];
  for (const [label, input, expected] of cases) {
    it(`${label}: ${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.equal(sanitizeFileName(input), expected);
    });
  }

  it('結果に、パス区切り・制御文字・双方向制御文字・先頭ドットが決して残らない（多数の悪意ある入力）', () => {
    const attacks = [
      '../../../x',
      '..\\..\\x',
      '/absolute/path',
      '\\\\server\\share\\x',
      '\u202Etxt.exe',
      '\u2066a\u2069.exe',
      'a\u0000\u0001\u001f.exe',
      '   .hidden',
      '...',
      'x/../../y',
    ];
    for (const attack of attacks) {
      const safe = sanitizeFileName(attack);
      assert.doesNotMatch(safe, /[\\/:*?"<>|]/u, attack);
      assert.doesNotMatch(safe, /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/u, attack);
      assert.doesNotMatch(safe, /^[\s.]/u, attack);
      assert.notEqual(safe, '');
    }
  });

  it('長すぎる名前は 120 コードポイント以内に切り詰め、短い拡張子は残す', () => {
    const long = sanitizeFileName(`${'a'.repeat(300)}.pdf`);
    assert.equal(Array.from(long).length, 120);
    assert.ok(long.endsWith('.pdf'));

    const longExtension = sanitizeFileName(`${'a'.repeat(200)}.${'b'.repeat(30)}`);
    assert.equal(Array.from(longExtension).length, 120, '長すぎる拡張子は拡張子として扱わない');
  });

  it('切り詰めでサロゲートペア（絵文字）を壊さない', () => {
    const emoji = sanitizeFileName(`${'😀'.repeat(200)}.txt`);
    assert.equal(Array.from(emoji).length, 120);
    assert.equal(Buffer.from(emoji, 'utf8').toString('utf8'), emoji, '不正なサロゲートが含まれない');
    assert.ok(emoji.endsWith('.txt'));
  });

  it('冪等: 無害化した名前をもう一度通しても変わらない', () => {
    for (const [, input] of cases) {
      const once = sanitizeFileName(input);
      assert.equal(sanitizeFileName(once), once, input);
    }
  });
});

describe('hasRiskyExtension', () => {
  const risky = ['a.exe', 'A.EXE', 'setup.msi', 'run.bat', 'x.ps1', 'page.html', 'image.svg', 'macro.docm', 'a.b.exe', 'trailing.exe '];
  const safe = ['a.pdf', 'A.PDF', 'photo.png', 'archive.tar.gz', 'noextension', 'exe', '.exe.pdf', 'report.docx'];
  for (const name of risky) it(`要注意: ${JSON.stringify(name)}`, () => assert.equal(hasRiskyExtension(name), true));
  for (const name of safe) it(`通常: ${JSON.stringify(name)}`, () => assert.equal(hasRiskyExtension(name), false));
});
