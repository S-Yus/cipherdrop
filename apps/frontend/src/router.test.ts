import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ID_PATTERN, resolveRoute } from './router.ts';

const ID = 'abcdefghijklmnopqrstuv';

describe('resolveRoute', () => {
  it('/ と /index.html は送信画面', () => {
    assert.deepEqual(resolveRoute('/'), { name: 'send' });
    assert.deepEqual(resolveRoute('/index.html'), { name: 'send' });
  });

  it('/v/{id} と末尾スラッシュつきは受取画面（ID を取り出す）', () => {
    assert.deepEqual(resolveRoute(`/v/${ID}`), { name: 'receive', id: ID });
    assert.deepEqual(resolveRoute(`/v/${ID}/`), { name: 'receive', id: ID });
  });

  it('/v/ 配下でも ID の形式が正しくなければ id は null（画面側で「リンクが正しくありません」）', () => {
    for (const bad of ['short', `${ID}x`, ID.slice(1), `${ID.slice(1)}.`, '', '%41'.repeat(8)]) {
      assert.deepEqual(resolveRoute(`/v/${bad}`), { name: 'receive', id: null }, JSON.stringify(bad));
    }
  });

  it('それ以外のパスは 404 画面', () => {
    for (const path of ['/v', `/v/${ID}/extra`, '/V/x', '/other', '/api/payload', `/x/v/${ID}`, '//']) {
      assert.deepEqual(resolveRoute(path), { name: 'not-found' }, path);
    }
  });

  it('ID の形式はバックエンドが発行する 128bit の base64url（22 文字）', () => {
    assert.match(ID, ID_PATTERN);
    assert.doesNotMatch(`${ID}A`, ID_PATTERN);
    assert.doesNotMatch(`${ID.slice(0, 21)}+`, ID_PATTERN);
  });
});
