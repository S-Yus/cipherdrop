# CipherDrop

Zero-Knowledge 設計の、**1 回読み切り・自動消滅**型のメッセージ／ファイル共有。
暗号化と復号はブラウザで完結し、サーバーは暗号文しか持たない。復号鍵は共有 URL の `#` 以降にだけ存在する。

```
https://cipherdrop.io/v/{id}#{key}
                       └──┬──┘ └─┬─┘
        サーバーに届く ◀───┘      └───▶ ブラウザの外には出ない（HTTP リクエストに含まれない）
```

## 仕組み

```
送信者のブラウザ                       サーバー                       受信者のブラウザ
 1. 鍵(256bit)と IV を生成
 2. AES-GCM で暗号化
 3. POST 暗号文 + IV ───────────────▶ 保存（暗号文と IV だけ）
    ◀──────────────── id ───────────
 4. https://cipherdrop.io/v/{id}#{key} を相手に共有 ─────────────────────▶ 5. # 以降は送信されない
                                                                             GET /api/payload/{id}
                                       削除してから返す ◀───────────────────┘
                                       ────────────────────────────────▶ 6. 鍵で復号・テキストとして描画
                                       （2 回目以降は 404）
```

| 情報 | ブラウザ | サーバー |
| --- | :---: | :---: |
| 平文 | ✔ | ✘ |
| 復号鍵 | ✔（URL の `#` 以降） | ✘ |
| 暗号文・IV・ID | ✔ | ✔（読まれた瞬間に削除） |
| 暗号文の大きさ・作成／取得の時刻 | ✔ | ✔（メタデータとして見える） |

## ディレクトリ構成

```
cipherdrop/
├── apps/
│   ├── frontend/                  # クライアント（暗号化・復号・安全な描画）
│   │   └── src/crypto.ts          #   encryptData / decryptData / renderTextSafely
│   └── backend/                   # API サーバー（ランタイム依存 0）
│       └── src/
│           ├── server.ts          #   POST /api/payload, GET /api/payload/:id
│           └── store.ts           #   暗号文ストア（take = 取得と削除が不可分）
├── tests/                         # アプリ横断のテスト
│   ├── zero-knowledge.e2e.test.ts #   E2E 証明 + フロントエンド向け利用サンプル
│   └── security-policy.test.ts    #   絶対遵守ルールをコードレベルで強制
├── tsconfig.base.json
└── package.json                   # npm workspaces
```

## 始め方

Node.js **24.2 以上**が必要（`.ts` をそのまま実行する Node のネイティブ TypeScript 対応と `import.meta.main` を使うため）。

```bash
npm ci               # 依存は完全固定（.npmrc の save-exact / package-lock.json）
npm run check        # 型チェック + 全テスト
npm run dev:backend  # http://127.0.0.1:8787 で起動（PORT / HOST で変更）
```

API を手で試す例（本物のクライアントは暗号化するが、サーバーから見ればただのバイト列）:

```bash
IV=$(head -c 12 /dev/urandom | basenc --base64url | tr -d '=')
curl -si -X POST http://127.0.0.1:8787/api/payload \
  -H 'Content-Type: application/octet-stream' -H "X-CipherDrop-IV: $IV" -H 'X-CipherDrop-TTL: 3600' \
  --data-binary "$(head -c 64 /dev/urandom | base64 -w0 | head -c 64)"
# → 201 {"id":"...","expiresAt":"..."}    curl -si http://127.0.0.1:8787/api/payload/<id> は 1 回目 200、2 回目 404
```

本番用は `npm run build -w @cipherdrop/backend` → `node apps/backend/dist/server.js`。

## API

| | |
| --- | --- |
| `POST /api/payload` | 本文: 暗号文（`application/octet-stream`）。ヘッダー: `X-CipherDrop-IV`（必須・base64url の 12 バイト）、`X-CipherDrop-TTL`（任意・秒。既定 86400、範囲 60〜604800）。→ `201 {"id","expiresAt"}` |
| `GET /api/payload/:id` | → `200` 暗号文 + `X-CipherDrop-IV`。**返す前にストアから削除する**。 |

| ステータス | `error` | 条件 |
| --- | --- | --- |
| 400 | `invalid_iv` / `invalid_ttl` / `invalid_ciphertext` / `query_not_allowed` | 形式不正（暗号文は 16 バイト以上）。**クエリ文字列は一切受け付けない** |
| 404 | `not_found` | 未発行・取得済み・期限切れ（区別しない） |
| 405 / 415 | `method_not_allowed` / `unsupported_media_type` | HEAD・DELETE 等では消費しない |
| 413 | `payload_too_large` | 既定 10 MiB 超 |
| 503 | `storage_full` | 保存容量の上限（既定 512 MiB） |

ID は 128bit の乱数（base64url 22 文字）。全レスポンスに `Cache-Control: no-store` などを付け、CORS は許可しない（同一オリジン運用）。

## 暗号仕様

- **AES-GCM 256bit**、認証タグ 128bit、Web Crypto API（`crypto.subtle`）のみ。外部ライブラリなし。
- **鍵は 1 メッセージにつき 1 つ**新規生成。IV（96bit）も呼び出しごとに CSPRNG で生成。
- 鍵の表現: base64url・パディング無し・43 文字。`decryptData` は厳格に検証する（非正規表現も拒否）。
- 平文の先頭に 1 バイトのフォーマットタグ（`0x01` テキスト / `0x02` バイナリ）を付けて暗号化する。認証対象なので
  サーバーは型を偽装できず、`decryptData` は `encryptData` に渡したのと同じ型（`string | ArrayBuffer`）を返す。
- 暗号文・IV はサーバー由来の信頼できない入力として扱う。改ざん・鍵違い・切り詰めはすべて `DECRYPTION_FAILED`。
  エラーに鍵・平文は含めない。

```ts
import { base64UrlDecode, base64UrlEncode, decryptData, encryptData, renderTextSafely } from './crypto.ts';

// 送信
const { encryptedData, iv, keyString } = await encryptData(message); // string | ArrayBuffer
const res = await fetch('/api/payload', {
  method: 'POST',
  headers: { 'Content-Type': 'application/octet-stream', 'X-CipherDrop-IV': base64UrlEncode(iv) },
  body: encryptedData,
});
const { id } = await res.json();
const shareUrl = `${location.origin}/v/${id}#${keyString}`; // 鍵は # の後ろにだけ置く

// 受信（location.hash は '#' から始まるので slice(1)）
const got = await fetch(`/api/payload/${id}`);
const plain = await decryptData(await got.arrayBuffer(), base64UrlDecode(got.headers.get('X-CipherDrop-IV') ?? '')!, location.hash.slice(1));
if (typeof plain === 'string') renderTextSafely(document.getElementById('out')!, plain); // innerHTML は使わない
```

`tests/zero-knowledge.e2e.test.ts` の `sendSecret` / `receiveSecret` は、Node 専用 API を使わない同等の実装サンプル。

## 絶対遵守ルールと、その検証

| ルール | 実装 | 検証 |
| --- | --- | --- |
| 鍵は `#` にだけ置き、サーバーに送らない | `encryptData` は鍵を返すだけ。サーバーはクエリを拒否 | **E2E**: サーバーが受信した生 TCP バイトを全記録し、鍵・平文が生／hex／base64／部分列のどれでも現れないこと、受信リクエストが 3 本だけでフラグメント・クエリが無いことを確認 |
| Web Crypto の AES-GCM 256、IV は毎回生成 | `crypto.ts` | OpenSSL（`node:crypto`）との相互運用、200 回で鍵・IV・暗号文がすべて異なること、外部 import が無いこと（ポリシーテスト） |
| 1 回読んだら即・物理削除 | `store.take()`（取得と削除が不可分。`get` は存在しない） | 削除が応答より先に終わっていること、50 並行 GET で成功が 1 回だけ、期限切れ・HEAD/DELETE/クエリ付きでの非消費 |
| XSS・ログ漏洩 | `renderTextSafely`（テキストノード）／ログは固定スキーマ型のみ | XSS 文字列が要素にならないこと（jsdom）。`innerHTML` 等・`eval`・`console.*` の使用を **AST で検査**してビルドを落とす。ログに ID・URL・クエリ・暗号文が出ないこと |

実装を意図的に壊して（削除しない・削除を遅延・クエリ許可・ログに URL・`innerHTML` 化 …）テストが落ちることも確認済み。

## 信頼モデルと既知の制約

**「サーバー管理者は復号できない」が成立する範囲を正確に理解しておくこと。**

1. **配信される JavaScript を信頼する前提。** 暗号化・復号のコードは、サーバー（cipherdrop.io）自身が毎回ブラウザに配信する。
   悪意ある（または侵害された）サーバーが改ざんした JS を配れば、鍵を盗める。保存データ（API・DB・ログ）からは復号できないが、
   「配信物が改ざんされない」ことまでは技術的に保証できない。→ 第 2 期以降: 厳格な CSP、SRI、ソース公開・再現可能ビルド、
   独立したクライアント配布などで対処する。
2. **GET で削除する。** 仕様どおり。リンクプレビュー／セキュリティスキャナ／プリフェッチが API を叩くと消えるため、
   UI は**受信者の明示的な操作（「表示する」ボタン）の後にだけ**取得すること。リバースプロキシの再試行は無効にすること
   （nginx: `proxy_next_upstream off`）。GET が再送されると 2 回目は 404 になり、受信者は読めなくなる。
   取得直後に通信が切れても暗号文は復元しない（安全側）。
3. **削除の意味。** ストアから削除してから応答する。メモリ／ディスクのゼロ埋めは保証しない（保持しているのは暗号文のみで、鍵は無い）。
4. **メタデータは見える。** 暗号文の大きさ、作成・取得時刻。パディングは未実装。
5. **インメモリ保存（MVP）。** 再起動すると未読の暗号文は消える。件数ではなく合計バイト数で上限を持つ。
6. **認証・レート制限は未実装。** ID を知っていれば誰でも「消費」できる（DoS）。ID は推測不能だが、公開前にレート制限を入れること。
7. **HTTPS 必須。** HTTP では `crypto.subtle` が使えず、配信物の改ざんも防げない。API サーバーは既定でループバックに bind する。
   TLS 終端・HSTS はリバースプロキシで行う。
8. **ブラウザのメモリ。** JavaScript では鍵・平文のメモリ消去を保証できない。

## 開発メモ

- TypeScript は **6.0.3 に固定**。7.x は JS コンパイラ API が `unstable/*` に移動しており、AST を使うポリシーテストや
  typescript-eslint が使えないため。
- Node が型を剥がして直接実行するため、`enum` / `namespace` / parameter property は使えない（`erasableSyntaxOnly` で強制）。
- `apps/frontend` の `tsconfig.json` は Node の型を含めない。`crypto.ts` にうっかり `Buffer` を使うと型エラーになる。

## 第 2 期以降

UI（Vite + Tailwind、クリック後に取得・表示、URL の `#` 消去、CSP + Trusted Types）／ファイル名・MIME の暗号化エンベロープ／
ファイルシステム or Redis（`GETDEL`）ストア／レート制限／パスワード保護／パディング。
