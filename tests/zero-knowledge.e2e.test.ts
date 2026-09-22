/**
 * Zero-Knowledge の E2E 検証。
 *
 * 実際のクライアントコード（暗号化・復号）と実際のサーバー（HTTP）をつなぎ、
 * 「サーバーが観測できたもの」をすべて記録して、鍵と平文が一度も現れないことを確認する。
 *   - ネットワーク: サーバーが受信した生の TCP バイト列（リクエスト行・ヘッダー・本文のすべて）
 *   - ストレージ:   サーバーが保存した内容
 *   - ログ:         サーバーが出力したログ
 *
 * ファイル先頭の sendSecret / receiveSecret は、フロントエンド実装時にそのまま参考にできる利用サンプル
 * （fetch / URL / crypto.ts などブラウザにもある API だけで書いており、Buffer などの Node 専用 API は使わない）。
 */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { HEADER_CONSUME_SECRET, HEADER_CONSUME_VERIFIER, HEADER_IV, HEADER_KEY_CHECK, HEADER_TYPE } from '../apps/backend/src/server.ts';
import {
  CipherDropCryptoError,
  base64UrlDecode,
  base64UrlEncode,
  decryptData,
  encryptData,
  generateConsumeSecret,
  generateKeyCheckTag,
} from '../apps/frontend/src/crypto.ts';
import { RecordingStore, leakedForms, parseHttpRequests, startWorld } from './support/world.ts';

const SHARE_ORIGIN = 'https://cipherdrop.io';

// ---------------------------------------------------------------------------
// 利用サンプル: 送信者と受信者のブラウザが行う処理
// ---------------------------------------------------------------------------

/**
 * 送信者: 暗号化 → 暗号文・IV・鍵確認値・consumeVerifier だけを送信 → 共有 URL
 * （鍵と consumeSecret は # 以降に `.` 区切りで載せる）を組み立てる。
 * consumeSecret は復号鍵とは独立した、consume（1 回限りの取得・削除）の許可だけを表す秘密
 * （apps/frontend/src/crypto.ts の generateConsumeSecret 参照）。
 */
async function sendSecret(apiOrigin: string, payload: string | ArrayBuffer): Promise<string> {
  const { encryptedData, iv, keyString } = await encryptData(payload);
  const keyCheck = await generateKeyCheckTag(keyString); // 鍵から一方向に導出した短いタグ（鍵そのものではない）
  const { secretString, verifierHex } = await generateConsumeSecret();

  const response = await fetch(`${apiOrigin}/api/payload`, {
    method: 'POST',
    headers: {
      'content-type': 'application/octet-stream',
      [HEADER_IV]: base64UrlEncode(iv),
      [HEADER_TYPE]: typeof payload === 'string' ? 'text' : 'file', // 確認画面の表示用ヒント（暗号化されない）
      [HEADER_KEY_CHECK]: keyCheck,
      [HEADER_CONSUME_VERIFIER]: verifierHex, // サーバーへ送るのは consumeSecret の SHA-256 全体だけ
    },
    body: encryptedData,
  });
  assert.equal(response.status, 201);
  const { id } = (await response.json()) as { id: string };

  return `${SHARE_ORIGIN}/v/${id}#${keyString}.${secretString}`;
}

/**
 * 受信者: 共有 URL から ID・鍵・consumeSecret を取り出し、2 段階で取得して復号する。
 *   Stage 1 確認  … GET  /meta     ページ読み込み時。何も消費しない
 *   Stage 2 消費  … POST /consume  受信者が「開く」を押したときだけ。consumeSecret をヘッダーで送り、
 *                                   返す前にサーバー側で削除される
 * フラグメントを付けたまま fetch に渡しても、ブラウザと同様に HTTP リクエストへは載らない。
 *
 * 簡略化のため、ここでは meta.keyCheck の照合はしない（その安全機構は views/receive.ts の
 * 実装対象で、receive.test.ts / ui-flow.e2e.test.ts が検証している）。この関数は 2 段階 API 自体の
 * 利用例に絞っている。
 */
async function receiveSecret(apiOrigin: string, shareUrl: string): Promise<string | ArrayBuffer> {
  const link = new URL(shareUrl);
  const id = link.pathname.split('/').pop() ?? '';
  const [keyString, consumeSecretString] = link.hash.slice(1).split('.');
  if (keyString === undefined || consumeSecretString === undefined) throw new Error('invalid share fragment');

  const meta = await fetch(`${apiOrigin}/api/payload/${id}/meta${link.hash}`);
  if (meta.status !== 200) throw new Error(`fetch failed with status ${meta.status}`);

  const response = await fetch(`${apiOrigin}/api/payload/${id}/consume${link.hash}`, {
    method: 'POST',
    headers: { [HEADER_CONSUME_SECRET]: consumeSecretString },
  });
  if (response.status !== 200) throw new Error(`fetch failed with status ${response.status}`);

  const iv = base64UrlDecode(response.headers.get(HEADER_IV) ?? '');
  if (iv === null) throw new Error('invalid IV header');
  return decryptData(await response.arrayBuffer(), iv, keyString);
}

// ---------------------------------------------------------------------------
// 観測用の部品
// ---------------------------------------------------------------------------

/** 取得時に暗号文を 1 ビット書き換える、悪意あるサーバーのストア。 */
class TamperingStore extends RecordingStore {
  override async take(id: string, consumeSecret: Uint8Array) {
    const payload = await super.take(id, consumeSecret);
    if (payload === null) return null;
    const ciphertext = new Uint8Array(payload.ciphertext);
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 0x01;
    return { ...payload, ciphertext };
  }
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('E2E: Zero-Knowledge・1 回読み切り', () => {
  const message = 'マイナンバー 123456789012 / 口座 0123-4567 / top-secret-passphrase <img src=x onerror=alert(1)>';

  it('送信 → 受信で元の文章に戻り、2 回目は取得できない', async (t) => {
    const world = await startWorld(t);

    const shareUrl = await sendSecret(world.origin, message);
    assert.match(shareUrl, /^https:\/\/cipherdrop\.io\/v\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/);

    assert.equal(await receiveSecret(world.origin, shareUrl), message);
    assert.equal(world.store.size, 0, '取得後、サーバーには何も残らない');
    await assert.rejects(receiveSecret(world.origin, shareUrl), /status 404/);
  });

  it('サーバーが観測できる全データ（通信・保存・ログ）に、鍵も consumeSecret も平文も一度も現れない', async (t) => {
    const world = await startWorld(t);

    const shareUrl = await sendSecret(world.origin, message);
    const link = new URL(shareUrl);
    const [keyString, consumeSecretString] = link.hash.slice(1).split('.');
    assert.ok(keyString && consumeSecretString, '共有 URL のフラグメントを分解できること');
    const id = link.pathname.split('/').pop() ?? '';

    // 共有リンクを開いたブラウザがサーバーへ送るリクエスト:
    //  1. ページの取得（GET /v/{id}#{key}.{consumeSecret}）… このテスト用サーバーは API だけなので 404 だが、送信内容は記録される
    await fetch(`${world.origin}${link.pathname}${link.hash}`);
    //  2. ページ上の JS による確認（GET …/meta）と、受信者が「開く」を押したときの消費（POST …/consume）
    //     いずれもフラグメント付きのまま fetch に渡す
    assert.equal(await receiveSecret(world.origin, shareUrl), message);

    const observed = world.observedOnWire();
    const text = observed.toString('latin1');
    const stored = world.store.puts[0];
    assert.ok(stored);

    // 記録は本文（ランダムな暗号文）を含む生ストリームなので、「# が無い」のような 1 文字の検査を全体にかけると偶然一致で
    // 不安定になる。リクエストとして構造的にパースし、リクエスト行・ヘッダー部と本文を分けて検査する。
    const requests = parseHttpRequests(observed);

    // --- 陽性対照: 記録の仕組みが空振りしていないこと（見えるべきものは見えている）---
    // サーバーが受け取ったリクエストは、この 4 本だけ。パスに鍵はなく、クエリもフラグメントもない。
    assert.deepEqual(
      requests.map((r) => `${r.method} ${r.target}`),
      ['POST /api/payload', `GET /v/${id}`, `GET /api/payload/${id}/meta`, `POST /api/payload/${id}/consume`],
    );
    const [upload, , , consume] = requests;
    assert.ok(upload && consume);
    assert.deepEqual(new Uint8Array(upload.body), stored.ciphertext, 'アップロード本文は暗号文そのもの');
    assert.equal(upload.headers.get(HEADER_IV), base64UrlEncode(stored.iv), 'IV はヘッダーに現れる');
    assert.equal(upload.headers.get(HEADER_TYPE), 'text', '種別ヒントはヘッダーに現れる（表示専用の情報）');
    const expectedKeyCheck = await generateKeyCheckTag(keyString);
    assert.equal(upload.headers.get(HEADER_KEY_CHECK), expectedKeyCheck, '鍵確認値はヘッダーに現れる（鍵ではなく、鍵から導出した 8 桁の値）');
    assert.equal(stored.keyCheck, expectedKeyCheck, '保存された値も同じ（サーバーは意味を解釈せずそのまま保存する）');
    const expectedVerifierHex = createHash('sha256').update(Buffer.from(consumeSecretString, 'base64url')).digest('hex');
    assert.equal(upload.headers.get(HEADER_CONSUME_VERIFIER), expectedVerifierHex, 'consumeVerifier（SHA-256 全体）は作成リクエストのヘッダーに現れる');
    assert.equal(Buffer.from(stored.consumeVerifier).toString('hex'), expectedVerifierHex, '保存された値も同じ');
    assert.equal(consume.headers.get(HEADER_CONSUME_SECRET), consumeSecretString, 'consumeSecret 自体は消費リクエストのヘッダーにだけ現れる（正規の送信経路）');
    assert.deepEqual(requests.slice(1).map((r) => r.body.length), [0, 0, 0], '2 件目以降は本文を持たない');

    // --- 通信: 鍵はどんな形でも現れない（鍵確認値ヘッダーを含めて検査する）---
    const rawKey = Buffer.from(keyString, 'base64url');
    assert.equal(rawKey.length, 32);
    assert.deepEqual(leakedForms(observed, rawKey, '鍵'), []);
    const headSections = requests.map((r) => r.head).join('\n');
    assert.ok(!headSections.includes('#'), 'リクエスト行・ヘッダーにフラグメント区切りの # がない');
    assert.ok(!headSections.includes('?'), 'リクエスト行・ヘッダーにクエリがない');
    for (let i = 0; i + 12 <= keyString.length; i++) {
      assert.ok(!text.includes(keyString.slice(i, i + 12)), `鍵の一部 (${i}〜) が通信に現れている`);
    }
    // 上の leakedForms(observed, rawKey, …) は、通信の生バイト列全体（鍵確認値・consumeVerifier ヘッダーを
    // 含む）を対象にしている。これらのヘッダー自体も鍵から一方向に導出した短い値・ハッシュ値で、鍵の符号化ではない。
    assert.equal(expectedKeyCheck.length, 8);

    // --- 通信: consumeSecret は、消費リクエストのヘッダー「以外」には一度も現れない（正規の送信経路はそこだけ）---
    const rawConsumeSecret = Buffer.from(consumeSecretString, 'base64url');
    assert.equal(rawConsumeSecret.length, 32);
    const observedWithoutConsumeRequest = Buffer.concat(
      requests.filter((r) => r !== consume).map((r) => Buffer.concat([Buffer.from(r.head, 'latin1'), r.body])),
    );
    assert.deepEqual(leakedForms(observedWithoutConsumeRequest, rawConsumeSecret, 'consumeSecret'), [], '消費リクエスト以外の通信に現れている');

    // --- 通信: 平文もどんな形でも現れない ---
    assert.deepEqual(leakedForms(observed, Buffer.from(message), '平文'), []);
    for (const fragment of ['123456789012', 'top-secret-passphrase', '口座', 'onerror']) {
      assert.ok(!observed.includes(fragment), `平文の断片 "${fragment}" が通信に現れている`);
    }

    // --- 保存: サーバーが持っていたのは暗号文・IV・種別ヒント・鍵確認値・consumeVerifier（ハッシュ）だけで、
    //     鍵・consumeSecret 自体（生の値）・平文はない ---
    assert.equal(world.store.puts.length, 1);
    assert.deepEqual(Object.keys(stored).sort(), ['ciphertext', 'consumeVerifier', 'iv', 'keyCheck', 'type']);
    assert.equal(stored.type, 'text');
    const storedBytes = Buffer.concat([stored.ciphertext, stored.iv, Buffer.from(stored.keyCheck ?? '', 'utf8'), Buffer.from(stored.consumeVerifier)]);
    assert.deepEqual(leakedForms(storedBytes, rawKey, '鍵'), []);
    assert.deepEqual(leakedForms(storedBytes, rawConsumeSecret, 'consumeSecret（生の値）'), []);
    assert.deepEqual(leakedForms(storedBytes, Buffer.from(message), '平文'), []);

    // --- ログ: 鍵・consumeSecret・平文・ID のいずれも出ていない ---
    const logText = JSON.stringify(world.logs);
    for (const secret of [keyString, consumeSecretString, id, 'top-secret-passphrase', '123456789012']) {
      assert.ok(!logText.includes(secret), `ログに "${secret.slice(0, 8)}…" が含まれている`);
    }
  });

  it('（検出力の確認）鍵や consumeSecret をクエリに載せる実装ミスがあれば通信記録に現れ、サーバーは 400 で拒否する', async (t) => {
    const world = await startWorld(t);
    const shareUrl = await sendSecret(world.origin, message);
    const link = new URL(shareUrl);
    const [keyString, consumeSecretString] = link.hash.slice(1).split('.');
    assert.ok(keyString && consumeSecretString);
    const id = link.pathname.split('/').pop() ?? '';

    const buggyKey = await fetch(`${world.origin}/api/payload/${id}/consume?key=${keyString}`, { method: 'POST' }); // NG な実装
    assert.equal(buggyKey.status, 400);
    assert.ok(world.observedOnWire().includes(keyString), '鍵が漏れる実装なら、この検査方法で検出できる');

    // consumeSecret も同じ理由でヘッダーではなくクエリに載せてはならない（同じ dispatch() の
    // クエリ拒否ロジックに守られているので、鍵と同じ規則で弾かれることを確認する）。
    const buggySecret = await fetch(`${world.origin}/api/payload/${id}/consume?consumeSecret=${consumeSecretString}`, { method: 'POST' }); // NG な実装
    assert.equal(buggySecret.status, 400);
    assert.ok(world.observedOnWire().includes(consumeSecretString), 'consumeSecret が漏れる実装なら、この検査方法で検出できる');

    assert.equal(world.store.size, 1, 'どちらも拒否されたので暗号文は消費されていない');
    assert.equal(await receiveSecret(world.origin, shareUrl), message, '正しい手順ならまだ読める');
  });

  it('バイナリ（2MiB のファイル相当）も同様に往復でき、2 回目は取得できない', async (t) => {
    const world = await startWorld(t);
    const file = Uint8Array.from(randomBytes(2 * 1024 * 1024)).buffer;

    const shareUrl = await sendSecret(world.origin, file);
    const received = await receiveSecret(world.origin, shareUrl);

    assert.ok(received instanceof ArrayBuffer);
    assert.deepEqual(new Uint8Array(received), new Uint8Array(file));
    assert.equal(world.store.puts[0]?.type, 'file', 'ArrayBuffer は種別ヒント file で保存される');
    await assert.rejects(receiveSecret(world.origin, shareUrl), /status 404/);
  });

  it('リンクプレビュー・クローラーがリンク先を先に叩いても消えず、受信者は最後まで開ける（2 段階の要）', async (t) => {
    const world = await startWorld(t);
    const shareUrl = await sendSecret(world.origin, message);
    const link = new URL(shareUrl);
    const id = link.pathname.split('/').pop() ?? '';

    // チャットアプリのプレビュー生成・セキュリティスキャナ・プロキシの疎通確認が行うアクセス。
    // 旧仕様（GET で消滅）ならここで消えていた。
    for (let i = 0; i < 3; i++) {
      await fetch(`${world.origin}${link.pathname}`); // ページ（# 以降は元々送られない）
      await fetch(`${world.origin}${link.pathname}`, { method: 'HEAD' });
      await fetch(`${world.origin}/api/payload/${id}/meta`); // ページ内の JS を実行するスキャナ
      await fetch(`${world.origin}/api/payload/${id}`); // 旧仕様の URL（廃止済み）
      await fetch(`${world.origin}/api/payload/${id}/consume`); // GET では消費されない
    }
    assert.equal(world.store.size, 1, 'プレビューが何度来ても、データは残っている');

    assert.equal(await receiveSecret(world.origin, shareUrl), message, '受信者が「開く」を押せば読める');
    assert.equal(world.store.size, 0);
    await assert.rejects(receiveSecret(world.origin, shareUrl), /status 404/);
  });

  it('URL の鍵が違えば、暗号文を取得できても復号できない（サーバーは鍵を持たないので代わりに復号もできない）', async (t) => {
    const world = await startWorld(t);
    const shareUrl = await sendSecret(world.origin, message);
    const otherShareUrl = await sendSecret(world.origin, 'another secret');
    const otherKeyString = new URL(otherShareUrl).hash.slice(1).split('.')[0];
    const ownConsumeSecretString = new URL(shareUrl).hash.slice(1).split('.')[1];

    // consume 自体は成功させたい（consumeSecret は自分のものを使う）ので、鍵の部分だけを別物にすり替える。
    const wrongLink = `${shareUrl.split('#')[0]}#${otherKeyString}.${ownConsumeSecretString}`;
    await assert.rejects(receiveSecret(world.origin, wrongLink), (error: unknown) => {
      assert.ok(error instanceof CipherDropCryptoError);
      assert.equal(error.code, 'DECRYPTION_FAILED');
      return true;
    });
  });

  it('consumeSecret が違えば、鍵が正しくても取得すらできない（ID だけでは消費できないことの E2E 証明）', async (t) => {
    const world = await startWorld(t);
    const shareUrl = await sendSecret(world.origin, message);
    const otherShareUrl = await sendSecret(world.origin, 'another secret');
    const otherConsumeSecretString = new URL(otherShareUrl).hash.slice(1).split('.')[1];
    const ownKeyString = new URL(shareUrl).hash.slice(1).split('.')[0];

    // 鍵は自分のもの（正しい）のまま、consumeSecret の部分だけを別物にすり替える。
    const wrongLink = `${shareUrl.split('#')[0]}#${ownKeyString}.${otherConsumeSecretString}`;
    await assert.rejects(receiveSecret(world.origin, wrongLink), /status 404/, '鍵が正しくても、consumeSecret が違えば consume 自体が拒否される');
    assert.equal(world.store.size, 2, '誤った consumeSecret では、どちらの暗号文も削除されない（自分の分・otherShareUrl の分）');

    assert.equal(await receiveSecret(world.origin, shareUrl), message, '正しいリンクならまだ取得できる');
  });

  it('悪意あるサーバーが暗号文を改ざんしても、受信者は検出できる（内容を偽造できない）', async (t) => {
    const world = await startWorld(t, () => new TamperingStore({ sweepIntervalMs: 0 }));
    const shareUrl = await sendSecret(world.origin, message);

    await assert.rejects(receiveSecret(world.origin, shareUrl), (error: unknown) => {
      assert.ok(error instanceof CipherDropCryptoError);
      assert.equal(error.code, 'DECRYPTION_FAILED');
      return true;
    });
  });
});
