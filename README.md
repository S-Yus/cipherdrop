# CipherDrop

Zero-Knowledge 設計の、**1 回読み切り・自動消滅**型のメッセージ／ファイル共有。
暗号化と復号はブラウザで完結し、サーバーは暗号文しか持たない。復号鍵は共有 URL の `#` 以降にだけ存在する。

```
https://cipherdrop.io/v/{id}#{key}
                       └──┬──┘ └─┬─┘
        サーバーに届く ◀───┘      └───▶ ブラウザの外には出ない（HTTP リクエストに含まれない）
```

## 仕組み（確認 → 消費の 2 段階）

```
送信者のブラウザ                  サーバー                          受信者のブラウザ
 1. 鍵(256bit)・IV を生成
 2. AES-GCM で暗号化
 3. POST /api/payload ─────────▶ 暗号文 + IV + 種別ヒントを保存
    ◀────────────── id ────────
 4. https://cipherdrop.io/v/{id}#{key} を共有 ─────────────────────▶ 5. ページを開く（# 以降は送信されない）
                                                                       ┌ Stage 1 確認
                                 メタ情報だけ返す（何も消費しない）◀─── │ GET  …/meta
                                                                       │ 「一度開くと消滅します」の警告を表示
                                                                       └ 6. 「データを開く」ボタンを押す
                                 削除してから返す ◀───────────────────── Stage 2 消費: POST …/consume
                                 ────────────────────────────────▶ 7. 鍵で復号して表示（ファイルはダウンロード）
                                 （以降は meta も consume も 404）
```

**なぜ 2 段階か。** 旧仕様（GET で取得と同時に削除）では、チャットのリンクプレビュー・クローラー・セキュリティスキャナが
URL を GET しただけで、受信者が開く前にデータが消えていた。今は**副作用のある操作を `POST consume` だけ**にし、
GET（`meta`）・HEAD・OPTIONS など何を叩いても状態が変わらない。旧 `GET /api/payload/:id` は廃止した（どのメソッドでも 404）。

| 情報 | ブラウザ | サーバー |
| --- | :---: | :---: |
| 平文・ファイル名 | ✔ | ✘ |
| 復号鍵 | ✔（URL の `#` 以降） | ✘ |
| 暗号文・IV・ID | ✔ | ✔（消費された瞬間に削除） |
| 種別ヒント（text / file）・暗号文サイズ・作成／期限／取得の時刻 | ✔ | ✔（メタデータとして見える） |

種別ヒントは確認画面の表示専用で、**暗号化されず、信頼もされない**。描画・保存の分岐は、復号後（認証済み）の種別で決める。

## ディレクトリ構成

```
cipherdrop/
├── apps/
│   ├── frontend/                    # クライアント（Vite + TypeScript + Tailwind CSS）
│   │   ├── index.html               #   エントリー（インラインのスクリプト・スタイルなし）
│   │   ├── vite.config.ts           #   本番ビルドに厳格な CSP を埋め込む / dev の /api 中継
│   │   ├── public/favicon.svg
│   │   └── src/
│   │       ├── crypto.ts            #   encryptData / decryptData / encryptFile / decryptPayload / renderTextSafely
│   │       ├── api.ts               #   API クライアント（鍵を受け取れない・応答を検証する）
│   │       ├── dom.ts               #   DOM ビルダー（HTML 挿入なし・属性は許可リスト）
│   │       ├── ui.ts                #   デザイン部品（Tailwind 標準パレットのみ・等幅・通知・ボタン）
│   │       ├── file-name.ts         #   受信ファイル名の無害化
│   │       ├── download.ts          #   ダウンロード保存（常に octet-stream）
│   │       ├── views/send.ts        #   送信画面（/）
│   │       ├── views/receive.ts     #   受取・復号画面（/v/:id#key）
│   │       └── app.ts / main.ts     #   ヘッダーと画面の振り分け / ブラウザのエントリー
│   └── backend/                     # API サーバー（ランタイム依存 0）
│       └── src/
│           ├── server.ts            #   POST /api/payload, GET …/:id/meta, POST …/:id/consume
│           └── store.ts             #   暗号文ストア（stat = 副作用なし / take = 取得と削除が不可分）
├── tests/                           # アプリ横断のテスト
│   ├── zero-knowledge.e2e.test.ts   #   API 層の E2E（生 TCP を記録して鍵・平文の不在を証明）
│   ├── ui-flow.e2e.test.ts          #   UI 経由の E2E（実サーバー + 画面コード + 暗号）
│   ├── build-output.test.ts         #   `vite build` の配布物を検査（CSP・インライン・外部通信・CSS のデザイン規則）
│   ├── design-rules.test.ts         #   デザイン規則を強制（色・グラデーション・影・コピー・構成）
│   ├── source-hygiene.test.ts       #   生の制御文字・双方向制御文字（Trojan Source）の混入を禁止
│   └── security-policy.test.ts      #   絶対遵守ルールをコードレベル（AST）で強制
├── tsconfig.base.json
└── package.json                     # npm workspaces
```

## 始め方

Node.js **24.2 以上**が必要（`.ts` をそのまま実行する Node のネイティブ TypeScript 対応と `import.meta.main` を使うため）。

```bash
npm ci               # 依存は完全固定（.npmrc の save-exact / package-lock.json）
npm run check        # 型チェック + 全テスト
```

開発（ターミナルを 2 つ）:

```bash
npm run dev:backend    # API: http://127.0.0.1:8787（PORT / HOST で変更）
npm run dev:frontend   # UI:  http://127.0.0.1:5173（/api は 8787 へ中継されるので、ブラウザからは同一オリジン）
```

本番用ビルド（`apps/backend/dist` と `apps/frontend/dist` を生成）:

```bash
npm run build
```

API を手で試す例（本物のクライアントは暗号化するが、サーバーから見ればただのバイト列）:

```bash
IV=$(head -c 12 /dev/urandom | basenc --base64url | tr -d '=')
curl -s -X POST http://127.0.0.1:8787/api/payload \
  -H 'Content-Type: application/octet-stream' -H "X-CipherDrop-IV: $IV" \
  -H 'X-CipherDrop-Type: text' -H 'X-CipherDrop-TTL: 3600' \
  --data-binary "$(head -c 64 /dev/urandom | base64 -w0 | head -c 64)"
# → {"id":"<id>","expiresAt":"..."}
# curl -s http://127.0.0.1:8787/api/payload/<id>/meta                 → {"type":"text","size":64,"expiresAt":"..."}（何度でも。消えない）
# curl -s -X POST http://127.0.0.1:8787/api/payload/<id>/consume      → 1 回目 200（暗号文）、2 回目以降 404
```

## 画面

無駄を削ぎ落とした、堅牢なセキュリティツールの見た目にしている（ダーク固定）。開いた瞬間にメインタスクだけが見え、
ヒーロー・特長欄・フッターは置かない。文言は事実とアクションだけ。

**送信 (`/`)**
- 最上部に等幅のステータスバッジ `AES-256-GCM / Client-Side Encrypted`。
- 入力は「テキスト」「ファイル」のタブ。コードエディタ調の入力面（`bg-zinc-950 border-zinc-800 font-mono`）と、UTF-8 のバイト数表示
  （10 MB を超えたらその場で「上限超過」）。ファイルはドラッグ＆ドロップ（ファイル名も暗号化される）。
- 有効期限（1 時間・24 時間・7 日間）は素直な `<select>`。ボタンは「暗号化リンクを生成」。
- 生成後は URL を等幅で全文表示し、**`#` 以降（復号鍵）を強調**して「この鍵はサーバーを経由していません」と注記する。「リンクをコピー」で全体をコピー。

**受取・復号 (`/v/:id#key`)**
1. **Stage 1（確認）**: 読み込み時に `GET …/meta` だけを呼ぶ。種類・サイズ・有効期限・暗号方式を等幅で示し、amber の静かな通知（`border-amber-500/20 bg-amber-500/5`）で
   「**このデータは一度開くとサーバーから永久削除されます**」と事実だけを伝える。**ここでは何も消費しない。**
2. **Stage 2（消費・復号）**: 「データを復号して表示」（ファイルは「データを復号してダウンロード」）を押したときだけ `POST …/consume`。
   テキストは `renderTextSafely`（テキストノード）で等幅のコードブロックに表示し、**「コピー」「破棄」**をワンクリックで実行できる。
   「破棄」は表示中のデータ（テキスト・ファイルのバイト列）への参照を手放して画面から消去する（サーバー上のデータは取得時に削除済みなので、再表示はできない）。
   ファイルはダウンロードとして保存する。取得後はアドレスバーから鍵を消す。

**ブラウザには何も保存しない**（localStorage・sessionStorage・Cookie・IndexedDB を使わない。ポリシーテストで強制）。
キーボード操作・支援技術への配慮（フォーカス管理・`aria-live`）、モバイル対応、日本語の文節単位の改行。
外部フォント・CDN・解析は一切使わない（第三者への通信が発生しない）。

### デザイン規則（機械的に強制している）

| 領域 | 規則 |
| --- | --- |
| 色 | 背景 `bg-zinc-950`、面 `bg-zinc-900/50` + 1px `border-zinc-800`。アクセントは emerald（暗号化・安全の状態）と白（主要な操作）のみ。警告は amber、エラーは red で、どちらも 1px の枠と 5% の面だけ。グラデーション・影・リング・任意の色（`bg-[#…]`）・紫/青系は使わない |
| タイポグラフィ | 鍵・URL・サイズ・期限・入力面・ステータスは `font-mono`。見出しと説明文は sans-serif |
| コピー | 事実とアクションだけ。キャッチコピー・形容詞過剰な文言・感嘆符・絵文字・装飾記号を使わない |
| 構成 | 特長欄（リスト）・フッター・画像・h2 以下の節を作らない。ダーク固定（ライトモード・テーマ切替はない） |

`tests/design-rules.test.ts`（ソースの class 文字列と UI 文言を AST で検査）と `tests/build-output.test.ts`（実際にビルドされた CSS を検査）が上記を強制する。
テキストのコントラスト比は WCAG AA（4.5:1）を実描画で計測して満たしている（最小 6.38:1）。
**既知のトレードオフ**: 入力欄などの枠線（`zinc-800` / `zinc-700`）は、指定の見た目を優先しており、操作部品の境界に求められる 3:1（WCAG 1.4.11）には届かない。

## API

| | |
| --- | --- |
| `POST /api/payload` | 本文: 暗号文（`application/octet-stream`）。ヘッダー: `X-CipherDrop-IV`（必須・base64url の 12 バイト）、`X-CipherDrop-Type`（必須・`text` \| `file`）、`X-CipherDrop-TTL`（任意・秒。既定 86400、範囲 60〜604800）。→ `201 {"id","expiresAt"}` |
| `GET /api/payload/:id/meta` | → `200 {"type","size","expiresAt"}`（`size` は暗号文のバイト数）。**何も消費・変更しない**。存在しない・消費済み・期限切れは `404`。 |
| `POST /api/payload/:id/consume` | → `200` 暗号文 + `X-CipherDrop-IV`。**返す前にストアから完全に削除する**（アトミック）。存在しない・消費済み・期限切れは `404`。 |

| ステータス | `error` | 条件 |
| --- | --- | --- |
| 400 | `invalid_iv` / `invalid_type` / `invalid_ttl` / `invalid_ciphertext` / `query_not_allowed` | 形式不正（暗号文は 16 バイト以上）。**クエリ文字列は一切受け付けない** |
| 404 | `not_found` | 未発行・消費済み・期限切れ・旧 URL（区別しない） |
| 405 / 415 | `method_not_allowed` / `unsupported_media_type` | GET・HEAD 等で `consume` はできない（本体も返らない） |
| 413 | `payload_too_large` | 既定 10 MiB 超 |
| 503 | `storage_full` | 保存容量の上限（既定 512 MiB） |

ID は 128bit の乱数（base64url 22 文字）。全レスポンスに `Cache-Control: no-store` などを付け、CORS は許可しない（同一オリジン運用）。

## 暗号仕様

- **AES-GCM 256bit**、認証タグ 128bit、Web Crypto API（`crypto.subtle`）のみ。外部ライブラリなし。
- **鍵は 1 メッセージにつき 1 つ**新規生成。IV（96bit）も呼び出しごとに CSPRNG で生成。
- 鍵の表現: base64url・パディング無し・43 文字。`decryptData` は厳格に検証する（非正規表現も拒否）。
- 平文の先頭に 1 バイトのフォーマットタグを付けて暗号化する。認証対象なので、サーバーは型を偽装できない。

  | タグ | 種別 | 本体 |
  | --- | --- | --- |
  | `0x01` | テキスト | UTF-8 |
  | `0x02` | バイナリ | バイト列 |
  | `0x03` | ファイル | `[u16 BE 名前のバイト長][名前 UTF-8][ファイルのバイト列]`（**ファイル名も暗号文の内側**。UTF-8 で 1024 バイトまで） |

- 暗号文・IV はサーバー由来の信頼できない入力として扱う。改ざん・鍵違い・切り詰めはすべて `DECRYPTION_FAILED`。
  認証が通っても、封筒の構造（名前長・UTF-8）は境界を厳密に検査する。エラーに鍵・平文は含めない。
- 受信したファイル名は送信者が決めた信頼できない値。`sanitizeFileName` でパス区切り・制御文字・**双方向制御文字**・
  Windows 予約名・長大な名前を無害化してから表示・保存する。保存は常に `application/octet-stream`（送信者の MIME 型は使わない）。

```ts
import { decryptPayload, encryptData, encryptFile, renderTextSafely } from './crypto.ts';

const { encryptedData, iv, keyString } = await encryptData(message);                    // string | ArrayBuffer
const sealed = await encryptFile({ name: file.name, data: await file.arrayBuffer() });  // ファイル（名前ごと暗号化）
const shareUrl = `${location.origin}/v/${id}#${keyString}`;                              // 鍵は # の後ろにだけ置く

const payload = await decryptPayload(encrypted, iv, location.hash.slice(1));            // { type: 'text' | 'file' | 'binary', … }
if (payload.type === 'text') renderTextSafely(document.getElementById('out')!, payload.text); // innerHTML は使わない
```

`tests/zero-knowledge.e2e.test.ts` の `sendSecret` / `receiveSecret` は、Node 専用 API を使わない API 層の利用サンプル。

## 絶対遵守ルールと、その検証

| ルール | 実装 | 検証 |
| --- | --- | --- |
| 鍵は `#` にだけ置き、サーバーに送らない | `encryptData` は鍵を返すだけ。`api.ts` は鍵を受け取れず、ID も形式検証する。サーバーはクエリを拒否 | **E2E（API 層・UI 層）**: サーバーが受信した生 TCP バイトを全記録し、鍵・平文・ファイル名が生／hex／base64／部分列のどれでも現れないこと、受信リクエストが想定の本数だけでフラグメント・クエリ・Cookie が無いこと |
| Web Crypto の AES-GCM 256、IV は毎回生成 | `crypto.ts` | OpenSSL（`node:crypto`）との相互運用、200 回で鍵・IV・暗号文がすべて異なること、外部 import が無いこと |
| 1 回読んだら即・物理削除（かつ、開く前には消えない） | `store.take()`（取得と削除が不可分）。`stat()` は副作用なし・戻り値の型に暗号文を含まない。`consume` は POST のみ | 削除が応答より先、50 並行 consume で成功 1 回、**GET / HEAD / OPTIONS / 旧 URL を浴びせても消えない**。読み込み時の処理が `consume` を呼ばないこと（実行時 + AST） |
| XSS・ログ漏洩 | `renderTextSafely`（テキストノード）／DOM ビルダー（HTML 挿入なし・属性は許可リスト）／ログは固定スキーマ型のみ／厳格な CSP | XSS 文字列が要素にならないこと（jsdom・実ブラウザ）。`innerHTML` 等・`eval`・`console.*` を **AST で検査**。`setAttribute` は `dom.ts` だけ。**配布物にも** HTML 挿入 API・インライン・外部 URL が無いこと |

実装を意図的に壊して（削除しない・GET でも消費・読み込み時に自動消費・`innerHTML` 化・鍵を API へ渡す・CSP を外す・外部フォントを読む …）
テストが落ちることも確認済み。

## 配信（デプロイ）の要件

フロントエンド（`apps/frontend/dist`）とバックエンドを、TLS 終端するリバースプロキシの背後に置く。

1. **HTTPS 必須**（HTTP では `crypto.subtle` が使えず、配信物の改ざんも防げない）。HSTS を付ける。
2. **SPA フォールバック**: `/v/*` を含む、実在しないパスは `index.html` を返す。`index.html` は `Cache-Control: no-store`（または `no-cache`）、
   `assets/*`（ハッシュ付き）は長期キャッシュでよい。
3. **`/api/` をバックエンドへ中継**（既定 `127.0.0.1:8787`）。リクエストボディの上限は 10 MiB 以上。
   **再試行は無効にする**（nginx: `proxy_next_upstream off`）。
4. **レスポンスヘッダー**で `Content-Security-Policy: frame-ancestors 'none'`（または `X-Frame-Options: DENY`）を付ける。
   ビルド済み HTML の CSP は `<meta>` で埋め込まれているが、`<meta>` では `frame-ancestors` が効かない。
   `X-Content-Type-Options: nosniff` と `Referrer-Policy: no-referrer` も付ける（HTML 側にも `<meta name="referrer">` はある）。
5. アクセスログにリクエストボディ・クエリを出さない。IP アドレスはプロキシのログに残り得るので、保持方針を決める。

## 信頼モデルと既知の制約

**「サーバー管理者は復号できない」が成立する範囲を正確に理解しておくこと。**

1. **配信される JavaScript を信頼する前提。** 暗号化・復号のコードは、サーバー（cipherdrop.io）自身が毎回ブラウザに配信する。
   悪意ある（または侵害された）サーバーが改ざんした JS を配れば、鍵を盗める。保存データ（API・DB・ログ）からは復号できないが、
   「配信物が改ざんされない」ことまでは技術的に保証できない。CSP で配信物の挙動は縛っているが、根本対策ではない
   （ソース公開・再現可能ビルド・SRI・独立したクライアント配布などは今後の課題）。
2. **プレビュー・クローラーでは消えない。** 取得は `meta`（何も消費しない）と `consume`（POST・ボタン操作）に分かれている。
   ただし、**ページの JS を実行したうえでボタンまで自動でクリックする**種類のスキャナは消費し得る。
   取得直後に通信が切れても暗号文は復元しない（安全側）。POST の再送で 2 回目が 404 になり得るため、プロキシの再試行は無効にすること。
3. **鍵が誤っていると、データだけが失われ得る。** 欠け・余分な文字・形式不正は、消費する前に検出して止める。
   一方、形式は正しいが 1 文字違うような鍵は、消費後の復号失敗で初めて分かる（鍵確認値の導入は今後の検討）。
4. **メタデータは見える。** 暗号文のサイズ、種別ヒント（text / file）、作成・期限・取得の時刻。パディングは未実装。
5. **削除の意味。** ストアから削除してから応答する。メモリ／ディスクのゼロ埋めは保証しない（保持しているのは暗号文のみで、鍵は無い）。
6. **インメモリ保存（MVP）。** 再起動すると未読の暗号文は消える。件数ではなく合計バイト数で上限を持つ。
7. **認証・レート制限は未実装。** ID を知っていれば誰でも「消費」できる（DoS）。ID は推測不能だが、公開前にレート制限を入れること。
8. **受け取るファイルは信頼できない。** 名前の無害化・保存形式の固定・実行ファイルへの注意喚起はするが、悪意あるファイルそのものは防げない。
9. **ブラウザのメモリ。** JavaScript では鍵・平文のメモリ消去を保証できない。

## 開発メモ

- TypeScript は **6.0.3 に固定**。7.x は JS コンパイラ API が `unstable/*` に移動しており、AST を使うポリシーテストや
  typescript-eslint が使えないため。フロントエンドは Vite 8 + Tailwind CSS 4（ともに devDependencies。配布物に依存パッケージは含まれない）。
- Node が型を剥がして直接実行するため、`enum` / `namespace` / parameter property は使えない（`erasableSyntaxOnly` で強制）。
- `apps/frontend` の `tsconfig.json` は Node の型を含めない。ブラウザのコードに `Buffer` などを使うと型エラーになる。
- 画面のコードは `document` / `location` / `fetch` などのグローバルを直接使わず、`AppEnv`（`env.ts`）を通す。
  ブラウザでは `main.ts` が実物を、テストでは jsdom と偽物を渡すので、同じコードが両方で動く（`src/testing/`）。
- 画面は `dom.ts` のビルダーで組み立てる。文字列は常にテキストノードになり、`on*`・`style`・`srcdoc`・任意 URL の属性は設定できない。
- 色は Tailwind の標準パレット（zinc / emerald / amber / red）を class で直接指定する（独自の色トークンは持たない）。追加・変更は `ui.ts` に集約する。

## 今後

レート制限／パスワード保護／パディング／鍵確認値／ファイルシステムまたは Redis（`GETDEL`）ストア／SRI とソース公開／
複数ファイル（zip）／受信者向けの「人間確認」（自動クリックするスキャナ対策）。
