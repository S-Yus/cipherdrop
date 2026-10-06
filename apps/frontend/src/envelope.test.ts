import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { packFile, safeFileName, unpackFile } from './envelope.ts';

describe('ファイルエンベロープ', () => {
  it('名前・MIME・本体を往復できる', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255]);
    const unpacked = unpackFile(packFile('報告書.pdf', 'application/pdf', bytes));
    assert.ok(unpacked);
    assert.equal(unpacked.name, '報告書.pdf');
    assert.equal(unpacked.type, 'application/pdf');
    assert.deepEqual([...unpacked.bytes], [...bytes]);
  });

  it('空のファイルも往復できる', () => {
    const unpacked = unpackFile(packFile('empty.txt', '', new Uint8Array()));
    assert.equal(unpacked?.bytes.byteLength, 0);
  });

  it('形式が違う・壊れているものは null（例外にしない）', () => {
    const valid = new Uint8Array(packFile('a.txt', 'text/plain', new Uint8Array([1])));
    const broken = (mutate: (b: Uint8Array) => void) => {
      const copy = valid.slice();
      mutate(copy);
      return unpackFile(copy.buffer);
    };
    assert.equal(unpackFile(new Uint8Array([1, 2, 3]).buffer), null);
    assert.equal(broken((b) => (b[0] = 0)), null); // マジック違い
    assert.equal(broken((b) => new DataView(b.buffer).setUint32(4, 0xffffffff)), null); // ヘッダー長が範囲外
    assert.equal(broken((b) => (b[8] = 0x7b + 1)), null); // JSON として不正
    const notStrings = new TextEncoder().encode('{"name":1,"type":2}');
    const forged = new Uint8Array(8 + notStrings.byteLength);
    forged.set([0x43, 0x44, 0x46, 0x31]);
    new DataView(forged.buffer).setUint32(4, notStrings.byteLength);
    forged.set(notStrings, 8);
    assert.equal(unpackFile(forged.buffer), null);
  });
});

describe('safeFileName', () => {
  const cases: Array<[string, string]> = [
    ['report.pdf', 'report.pdf'],
    ['../../etc/passwd', 'passwd'],
    ['C:\\Windows\\evil.exe', 'evil.exe'],
    ['what?.txt', 'what_.txt'],
    ['.bashrc', 'bashrc'],
    ['invoice\u202Efdp.exe', 'invoicefdp.exe'], // 右から左への上書き文字で拡張子を偽装させない
    ['a\u0000b\nc', 'abc'],
    ['   ', 'cipherdrop-file'],
    ['...', 'cipherdrop-file'],
  ];
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => assert.equal(safeFileName(input), expected));
  }

  it('長すぎる名前は切り詰める', () => {
    assert.equal(safeFileName('a'.repeat(500)).length, 200);
  });
});
