import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { JSDOM } from 'jsdom';
import {
  CipherDropCryptoError,
  base64UrlDecode,
  base64UrlEncode,
  decryptData,
  encryptData,
  renderTextSafely,
} from './crypto.ts';

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function flipBit(buffer: ArrayBuffer, index: number): ArrayBuffer {
  const bytes = new Uint8Array(buffer);
  bytes[index] = (bytes[index] ?? 0) ^ 0x01;
  return bytes.buffer;
}

async function assertCryptoError(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof CipherDropCryptoError, 'CipherDropCryptoError であること');
    assert.equal(error.code, code);
    return true;
  });
}

describe('encryptData / decryptData: 往復', () => {
  const textSamples = [
    '',
    'hello',
    'こんにちは、CipherDrop 🔐 — 日本語・絵文字・結合文字 é',
    '﻿先頭が BOM の文字列',
    'line1\nline2\r\nline3\t<tab>',
    '<script>alert(1)</script><img src=x onerror=alert(1)>',
    'a'.repeat(100_000),
  ];

  for (const sample of textSamples) {
    it(`テキストは元の文字列にそのまま戻る (${JSON.stringify(sample.slice(0, 24))}, ${sample.length} 文字)`, async () => {
      const { encryptedData, iv, keyString } = await encryptData(sample);
      const decrypted = await decryptData(encryptedData, iv, keyString);
      assert.equal(typeof decrypted, 'string');
      assert.equal(decrypted, sample);
    });
  }

  it('ArrayBuffer は同じバイト列の ArrayBuffer として戻る（全 256 値・空・1MiB）', async () => {
    const allByteValues = Uint8Array.from({ length: 256 }, (_, i) => i).buffer;
    const empty = new ArrayBuffer(0);
    const large = toArrayBuffer(randomBytes(1024 * 1024));

    for (const original of [allByteValues, empty, large]) {
      const snapshot = Uint8Array.from(new Uint8Array(original));
      const { encryptedData, iv, keyString } = await encryptData(original);
      const decrypted = await decryptData(encryptedData, iv, keyString);

      assert.ok(decrypted instanceof ArrayBuffer, '文字列ではなく ArrayBuffer が返ること');
      assert.equal(decrypted.byteLength, original.byteLength);
      assert.deepEqual(new Uint8Array(decrypted), snapshot);
      assert.deepEqual(new Uint8Array(original), snapshot, '入力バッファを破壊しないこと');
    }
  });
});

describe('encryptData: 出力仕様', () => {
  it('鍵は base64url 43 文字(256bit)、IV は 12 バイト、暗号文は 平文 + タグ1B + GCMタグ16B', async () => {
    const text = 'hello'; // UTF-8 で 5 バイト
    const textResult = await encryptData(text);
    assert.match(textResult.keyString, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(textResult.iv.byteLength, 12);
    assert.equal(textResult.encryptedData.byteLength, 5 + 1 + 16);

    const binaryResult = await encryptData(new ArrayBuffer(1000));
    assert.equal(binaryResult.encryptedData.byteLength, 1000 + 1 + 16);

    const emptyResult = await encryptData('');
    assert.equal(emptyResult.encryptedData.byteLength, 0 + 1 + 16);
  });

  it('呼び出しごとに鍵・IV・暗号文がすべて異なる（同じ入力でも使い回さない）', async () => {
    const runs = await Promise.all(Array.from({ length: 200 }, () => encryptData('same message')));

    const keys = new Set(runs.map((r) => r.keyString));
    const ivs = new Set(runs.map((r) => Buffer.from(r.iv).toString('hex')));
    const ciphertexts = new Set(runs.map((r) => Buffer.from(r.encryptedData).toString('hex')));
    assert.equal(keys.size, runs.length);
    assert.equal(ivs.size, runs.length);
    assert.equal(ciphertexts.size, runs.length);
  });

  it('暗号文に平文がそのまま現れない', async () => {
    const marker = 'TOP-SECRET-MARKER-1234567890';
    const { encryptedData } = await encryptData(marker);
    assert.equal(Buffer.from(encryptedData).includes(marker), false);
  });

  it('不正な入力型は INVALID_PAYLOAD', async () => {
    const invalidInputs: unknown[] = [123, null, undefined, {}, [1, 2, 3], new Uint8Array(4)];
    for (const input of invalidInputs) {
      await assertCryptoError(encryptData(input as string), 'INVALID_PAYLOAD');
    }
  });
});

describe('AES-256-GCM であることの独立検証（node:crypto / OpenSSL との相互運用）', () => {
  it('encryptData の出力を OpenSSL 実装で復号できる（鍵 256bit・IV 96bit・タグ 128bit・AAD なし）', async () => {
    const { encryptedData, iv, keyString } = await encryptData('相互運用テスト');
    const key = Buffer.from(keyString, 'base64url');
    assert.equal(key.length, 32);

    const bytes = Buffer.from(encryptedData);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(bytes.subarray(bytes.length - 16));
    const plaintext = Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]);

    assert.equal(plaintext[0], 0x01, 'フォーマットタグ: テキスト');
    assert.equal(plaintext.subarray(1).toString('utf8'), '相互運用テスト');
  });

  it('OpenSSL 実装で作った暗号文を decryptData で復号できる', async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const body = Buffer.concat([Buffer.from([0x02]), Buffer.from([0xde, 0xad, 0xbe, 0xef])]);
    const encrypted = Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);

    const decrypted = await decryptData(toArrayBuffer(encrypted), new Uint8Array(iv), key.toString('base64url'));
    assert.ok(decrypted instanceof ArrayBuffer);
    assert.deepEqual(new Uint8Array(decrypted), Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
  });

  it('未知のフォーマットタグは UNSUPPORTED_FORMAT（認証は通るが解釈しない）', async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from([0x7f, 0x41])), cipher.final(), cipher.getAuthTag()]);

    await assertCryptoError(
      decryptData(toArrayBuffer(encrypted), new Uint8Array(iv), key.toString('base64url')),
      'UNSUPPORTED_FORMAT',
    );
  });

  it('テキストタグなのに UTF-8 として不正なデータは UNSUPPORTED_FORMAT（黙って置換しない）', async () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from([0x01, 0xff, 0xfe])), cipher.final(), cipher.getAuthTag()]);

    await assertCryptoError(
      decryptData(toArrayBuffer(encrypted), new Uint8Array(iv), key.toString('base64url')),
      'UNSUPPORTED_FORMAT',
    );
  });
});

describe('decryptData: 攻撃・誤用への耐性', () => {
  it('別の鍵では復号できない', async () => {
    const a = await encryptData('message A');
    const b = await encryptData('message B');
    await assertCryptoError(decryptData(a.encryptedData, a.iv, b.keyString), 'DECRYPTION_FAILED');
  });

  it('暗号文を 1 ビット改ざんすると（先頭・中間・認証タグ部のどこでも）復号できない', async () => {
    const { encryptedData, iv, keyString } = await encryptData('tamper me please');
    const last = encryptedData.byteLength - 1;
    for (const index of [0, Math.floor(last / 2), last]) {
      await assertCryptoError(decryptData(flipBit(encryptedData, index), iv, keyString), 'DECRYPTION_FAILED');
    }
  });

  it('IV を改ざんすると復号できない', async () => {
    const { encryptedData, iv, keyString } = await encryptData('iv tamper');
    const tamperedIv = new Uint8Array(iv);
    tamperedIv[0] = (tamperedIv[0] ?? 0) ^ 0x80;
    await assertCryptoError(decryptData(encryptedData, tamperedIv, keyString), 'DECRYPTION_FAILED');
  });

  it('暗号文の切り詰め・空データは復号できない', async () => {
    const { encryptedData, iv, keyString } = await encryptData('truncate me');
    for (const broken of [encryptedData.slice(0, encryptedData.byteLength - 1), encryptedData.slice(0, 16), new ArrayBuffer(0)]) {
      await assertCryptoError(decryptData(broken, iv, keyString), 'DECRYPTION_FAILED');
    }
  });

  it('12 バイト以外の IV は INVALID_IV', async () => {
    const { encryptedData, keyString } = await encryptData('iv length');
    for (const length of [0, 1, 11, 13, 16]) {
      await assertCryptoError(decryptData(encryptedData, new Uint8Array(length), keyString), 'INVALID_IV');
    }
    await assertCryptoError(decryptData(encryptedData, [1, 2, 3] as unknown as Uint8Array, keyString), 'INVALID_IV');
  });

  it('形式不正の鍵文字列は INVALID_KEY（長さ・文字種・パディング・# 付き・非正規表現）', async () => {
    const { encryptedData, iv, keyString } = await encryptData('key format');

    const lastIndex = BASE64URL_ALPHABET.indexOf(keyString.at(-1) ?? '');
    assert.equal(lastIndex % 4, 0, '正規の 43 文字鍵の末尾文字は余りビットが 0');
    const nonCanonical = keyString.slice(0, -1) + BASE64URL_ALPHABET.charAt(lastIndex + 1);

    const badKeys = [
      '',
      'short',
      keyString.slice(0, 42),
      `${keyString}A`,
      `#${keyString}`,
      `${keyString.slice(0, 42)}=`,
      `${keyString.slice(0, 42)}+`,
      `${keyString.slice(0, 42)}/`,
      ` ${keyString.slice(0, 42)}`,
      nonCanonical,
      undefined as unknown as string,
    ];
    for (const bad of badKeys) {
      await assertCryptoError(decryptData(encryptedData, iv, bad), 'INVALID_KEY');
    }
  });

  it('ArrayBuffer 以外の暗号文は INVALID_PAYLOAD', async () => {
    const { iv, keyString } = await encryptData('x');
    await assertCryptoError(decryptData(new Uint8Array(32) as unknown as ArrayBuffer, iv, keyString), 'INVALID_PAYLOAD');
  });

  it('エラーメッセージに鍵・平文・暗号文が含まれない', async () => {
    const secret = 'ULTRA-SECRET-PLAINTEXT';
    const a = await encryptData(secret);
    const b = await encryptData('other');
    // Promise は assert.rejects に渡す直前に生成する（先に起動すると handler 付与前に reject して unhandled になる）。
    const failures: Array<() => Promise<unknown>> = [
      () => decryptData(a.encryptedData, a.iv, b.keyString), // 鍵違い
      () => decryptData(flipBit(a.encryptedData, 0), a.iv, a.keyString), // 改ざん
      () => decryptData(a.encryptedData, a.iv, `#${a.keyString}`), // 形式不正
    ];
    for (const failure of failures) {
      await assert.rejects(failure(), (error: unknown) => {
        assert.ok(error instanceof Error);
        const text = `${error.name} ${error.message} ${error.stack ?? ''}`;
        for (const forbidden of [a.keyString, b.keyString, secret, Buffer.from(a.encryptedData).toString('base64')]) {
          assert.equal(text.includes(forbidden), false);
        }
        return true;
      });
    }
  });
});

describe('base64UrlEncode / base64UrlDecode', () => {
  const ascii = (text: string) => Uint8Array.from(Buffer.from(text, 'ascii'));

  // RFC 4648 §10 のテストベクター（base64url ではパディングを付けない）
  const vectors: Array<[string, string]> = [
    ['', ''],
    ['f', 'Zg'],
    ['fo', 'Zm8'],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg'],
    ['fooba', 'Zm9vYmE'],
    ['foobar', 'Zm9vYmFy'],
  ];
  for (const [plain, encoded] of vectors) {
    it(`RFC 4648 のベクター: ${JSON.stringify(plain)} ↔ ${JSON.stringify(encoded)}`, () => {
      assert.equal(base64UrlEncode(ascii(plain)), encoded);
      assert.deepEqual(base64UrlDecode(encoded), ascii(plain));
    });
  }

  it('標準 base64 の + と / は - と _ に置き換わり、往復できる', () => {
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf, 0xfe]); // 標準 base64 では "+/+//g=="
    assert.equal(base64UrlEncode(bytes), '-_-__g');
    assert.deepEqual(base64UrlDecode('-_-__g'), bytes);
  });

  it('任意のバイト列（全長 0〜64 のランダム）が往復し、Node の base64url と一致する', () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = Uint8Array.from(randomBytes(length));
      const encoded = base64UrlEncode(bytes);
      assert.equal(encoded, Buffer.from(bytes).toString('base64url'));
      assert.deepEqual(base64UrlDecode(encoded), bytes);
    }
  });

  it('base64url として不正・非正規な入力は例外ではなく null', () => {
    const invalid = [
      'Zg==', // パディング付き
      'Zm9v+', // 標準 base64 の文字
      'Zm/v',
      'Zm 9v', // 空白
      'Zm9v\n',
      'Z', // 長さ mod 4 == 1 は成立しない
      'Zh', // 余りビットが 0 でない（正規形は "Zg"）
      'Zm9', // 余りビットが 0 でない（正規形は "Zm8"）
      'Zm9v ',
      'ｚｍ９ｖ', // 全角
    ];
    for (const input of invalid) {
      assert.equal(base64UrlDecode(input), null, JSON.stringify(input));
    }
  });
});

describe('renderTextSafely: XSS 対策', () => {
  function createContainer(): HTMLElement {
    const dom = new JSDOM('<!doctype html><html><body><div id="out"></div></body></html>');
    const container = dom.window.document.getElementById('out');
    assert.ok(container);
    return container;
  }

  const attackStrings = [
    '<script>window.__pwned = 1</script>',
    '<img src=x onerror="window.__pwned = 1">',
    '"><svg onload=alert(1)>',
    '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
    '<a href="javascript:alert(1)">click</a>',
    '&lt;b&gt;entity&lt;/b&gt; &amp; &#x3C;script&#x3E;',
  ];

  for (const attack of attackStrings) {
    it(`HTML として解釈されず、テキストノード 1 つとして描画される: ${attack.slice(0, 40)}`, () => {
      const container = createContainer();
      renderTextSafely(container, attack);

      assert.equal(container.textContent, attack, '文字列がそのまま表示されること');
      assert.equal(container.querySelector('*'), null, '要素が 1 つも生成されないこと');
      assert.equal(container.childNodes.length, 1);
      assert.equal(container.firstChild?.nodeType, 3, 'TEXT_NODE');
    });
  }

  it('直列化するとタグはエスケープされている', () => {
    const container = createContainer();
    renderTextSafely(container, '<script>alert(1)</script>');
    assert.equal(container.innerHTML, '&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('既存の子要素を置き換え、追記しない', () => {
    const container = createContainer();
    container.append('old text', container.ownerDocument.createElement('b'));

    renderTextSafely(container, 'first');
    renderTextSafely(container, 'second');

    assert.equal(container.textContent, 'second');
    assert.equal(container.childNodes.length, 1);
  });

  it('空文字列でも例外にならない', () => {
    const container = createContainer();
    renderTextSafely(container, '');
    assert.equal(container.textContent, '');
  });
});
