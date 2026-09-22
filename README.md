# CipherDrop

Zero-Knowledge 設計の、**1 回読み切り・自動消滅**型のメッセージ／ファイル共有。
暗号化と復号はブラウザで完結し、サーバーは暗号文しか持たない。復号鍵は共有 URL の `#` 以降にだけ存在する。

```
https://cipherdrop.io/v/{id}#{key}.{consumeSecret}
                       └──┬──┘ └────────┬────────┘
        サーバーに届く ◀───┘             └───▶ ブラウザの外には出ない（HTTP リクエストに含まれない）
```

`#` 以降には、復号鍵（`key`）とは独立した、consume（1 回限りの取得・削除）を許可するためだけの秘密
（`consumeSecret`）も `.` 区切りで載る。ID（`{id}`）は URL パスに載るためサーバーのログ等に残り得るが、
`#` 以降はどちらも残らない。詳細は「消費用秘密鍵」の節を参照。

## 仕組み（確認 → 消費の 2 段階）

```
送信者のブラウザ                  サーバー                          受信者のブラウザ
 1. 鍵(256bit)・consumeSecret(256bit)・IV を生成
 2. AES-GCM で暗号化。consumeSecret の SHA-256 を算出
 3. POST /api/payload ─────────▶ 暗号文 + IV + 種別ヒント
    （+ consumeSecret の SHA-256）  + consumeVerifier を保存
    ◀────────────── id ────────
 4. https://cipherdrop.io/v/{id}#{key}.{consumeSecret} を共有 ────▶ 5. ページを開く（# 以降は送信されない）
                                                                       ┌ Stage 1 確認
                                 メタ情報だけ返す（何も消費しない）◀─── │ GET  …/meta
                                                                       │ 「一度開くと消滅します」の警告を表示
                                                                       └ 6. 「データを開く」ボタンを押す
                                 consumeSecret を検証してから ◀─────── Stage 2 消費: POST …/consume
                                 削除してから返す                       （X-CipherDrop-Consume-Secret ヘッダー）
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
│   │   ├── public/.well-known/security.txt  # RFC 9116。/.well-known/security.txt として配信される
│   │   └── src/
│   │       ├── crypto.ts            #   encryptData / decryptData / encryptFile / decryptPayload / renderTextSafely
│   │       ├── api.ts               #   API クライアント（鍵を受け取れない・応答を検証する）
│   │       ├── dom.ts               #   DOM ビルダー（HTML 挿入なし・属性は許可リスト）
│   │       ├── ui.ts                #   デザイン部品（Tailwind 標準パレットのみ・等幅・通知・ボタン）
│   │       ├── file-name.ts         #   受信ファイル名の無害化
│   │       ├── download.ts          #   ダウンロード保存（常に octet-stream）
│   │       ├── views/send.ts        #   送信画面（/）
│   │       ├── views/receive.ts     #   受取・復号画面（/v/:id#key.consumeSecret）
│   │       └── app.ts / main.ts     #   ヘッダーと画面の振り分け / ブラウザのエントリー
│   └── backend/                     # API サーバー（ランタイム依存 0）
│       └── src/
│           ├── server.ts            #   POST /api/payload, GET …/:id/meta, POST …/:id/consume, GET …/ping
│           └── store.ts             #   暗号文ストア（stat = 副作用なし / take = 取得と削除が不可分）
├── deploy/                          # コンテナ内の配信設定（Dockerfile から COPY される）
│   ├── nginx.conf                   #   静的配信（8080）+ /api リバースプロキシ。非 root 前提
│   ├── security-headers.conf        #   HSTS・CSP 等。/api/ には付けない（バックエンド自身が付ける）
│   └── entrypoint.sh                #   nginx -t → nginx（背景）→ exec node（PID 1 の子として）
├── tests/                           # アプリ横断のテスト（それ自体も 1 つの npm workspace）
│   ├── zero-knowledge.e2e.test.ts   #   API 層の E2E（生 TCP を記録して鍵・平文の不在を証明）
│   ├── ui-flow.e2e.test.ts          #   UI 経由の E2E（実サーバー + 画面コード + 暗号）
│   ├── build-output.test.ts         #   `vite build` の配布物を検査（CSP・インライン・外部通信・CSS のデザイン規則）
│   ├── design-rules.test.ts         #   デザイン規則を強制（色・グラデーション・影・コピー・構成）
│   ├── source-hygiene.test.ts       #   生の制御文字・双方向制御文字（Trojan Source）の混入を禁止
│   ├── infra.test.ts                #   Dockerfile・nginx・docker-compose を静的に検査（CSP・バージョン等の整合）
│   ├── ci-workflow.test.ts          #   .github/workflows/ci.yml を静的に検査（Node バージョン・スクリプト名等の整合）
│   ├── docs-integrity.test.ts       #   法的・セキュリティ文書の存在・必須用語・リンク切れを検査
│   └── security-policy.test.ts      #   絶対遵守ルールをコードレベル（AST）で強制
├── docs/SECURITY_WHITEPAPER.md      # 暗号アーキテクチャ・2 段階消費 API・鍵確認値の技術詳細
├── PRIVACY.md / TERMS.md / SECURITY.md  # プライバシーポリシー / 利用規約 / 脆弱性報告窓口（いずれもドラフト）
├── .github/workflows/ci.yml         # main / develop への push・PR で npm run check → build → audit を実行
├── Dockerfile                       # マルチステージ（builder → runner）。USER node・HEALTHCHECK 付き
├── docker-compose.yml               # app（CipherDrop 本体）+ cloudflared（Cloudflare Tunnel）
├── .dockerignore
├── .env.example                     # docker-compose.yml が読む TUNNEL_TOKEN のひな形
├── tsconfig.base.json
└── package.json                     # npm workspaces（apps/* と tests）
```

## 始め方

Node.js **24.2 以上**が必要（`.ts` をそのまま実行する Node のネイティブ TypeScript 対応と `import.meta.main` を使うため）。

```bash
npm ci               # 依存は完全固定（.npmrc の save-exact / package-lock.json）
npm run check        # 型チェック + 全テスト（backend / frontend / tests の各ワークスペースを横断）
```

開発:

```bash
npm run dev   # backend（:8787）と frontend（:5173）を 1 コマンドで並列起動する
```

## CI

`.github/workflows/ci.yml` が `main` / `develop` への push・PR のたびに `npm ci` → `npm run check`
（型チェック + 全テスト）→ `npm run build`（全ワークスペース）→ `npm audit --audit-level=high` を実行する。
いずれか 1 つでも失敗すれば、そのステップ以降を実行せずジョブ全体を失敗として報告する（既定の GitHub Actions の
振る舞いで、`continue-on-error` は一切使っていない。`tests/ci-workflow.test.ts` がこれを検査している）。

- サードパーティの Actions（`actions/checkout`・`actions/setup-node`）は可変なバージョンタグ（`@v4` 等）ではなく
  コミット SHA に固定し、`GITHUB_TOKEN` の権限は `contents: read` だけに絞っている。
- Node のバージョン（`24.x`）は `package.json` の `engines.node`・`Dockerfile` の `node:24-alpine` と
  食い違っていないかを `tests/ci-workflow.test.ts` が突き合わせる（3 箇所がずれると壊れる：
  `import.meta.main` 要件。README「Docker でのデプロイ」参照）。
- このリポジトリの検証環境には GitHub Actions を実際に動かす手段が無いため、ワークフロー自体は
  [`actionlint`](https://github.com/rhysd/actionlint)（v1.7.12、リリースの SHA-256 を照合して取得した単体バイナリ）
  でも検査した。0 個の parse error / 0 個のルール違反（`shellcheck`・`pyflakes` の下位チェックは、それらの
  外部コマンドが無い環境のため無効化された状態での結果）。ただし `actionlint` は `with:` に渡すキー名の
  typo（例: `node-verzion`）までは検出しないことを確認したため、そこは `tests/ci-workflow.test.ts` 側の
  厳密な文字列一致で担保している。**実際に GitHub 上で 1 回はワークフローを動かして確認すること。**
- **このワークフローだけでは PR のマージは止まらない。** 失敗しても「チェックが赤くなる」だけで、GitHub が
  マージ自体をブロックするには、リポジトリの Settings → Branches で `main` / `develop` にブランチ保護を設定し、
  このジョブ（`Typecheck, test, build, audit`）を必須ステータスチェックに指定する必要がある（このリポジトリの
  設定はコードの外側にあるので、`ci.yml` を置くだけでは行われない）。

`dev` はシェルのジョブ制御（`&` / `wait`）で 2 つの `npm run dev --workspace ...` を同じプロセスグループで動かしている
（npm の `run-script` 自体には複数ワークスペースを並列実行する機能が無いため）。Ctrl+C は両方に届き、一緒に終了する。
ログを分けて見たい・個別に再起動したい場合は、従来どおり 2 つのターミナルで個別に起動できる:

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

# consumeSecret（消費の許可を示す秘密）は生バイト列を一時ファイルに置き、base64url 表現と
# SHA-256（consumeVerifier）の両方をそこから導出する（同じバイト列を 2 通りに使うため）。
SECRET_FILE=$(mktemp)
head -c 32 /dev/urandom > "$SECRET_FILE"
CONSUME_SECRET=$(basenc --base64url -w0 < "$SECRET_FILE" | tr -d '=')
CONSUME_VERIFIER=$(sha256sum "$SECRET_FILE" | cut -d' ' -f1)
rm -f "$SECRET_FILE"

curl -s -X POST http://127.0.0.1:8787/api/payload \
  -H 'Content-Type: application/octet-stream' -H "X-CipherDrop-IV: $IV" \
  -H 'X-CipherDrop-Type: text' -H 'X-CipherDrop-TTL: 3600' \
  -H "X-CipherDrop-Consume-Verifier: $CONSUME_VERIFIER" \
  --data-binary "$(head -c 64 /dev/urandom | base64 -w0 | head -c 64)"
# → {"id":"<id>","expiresAt":"..."}
# curl -s http://127.0.0.1:8787/api/payload/<id>/meta                                                     → {"type":"text","size":64,"expiresAt":"..."}（何度でも。消えない）
# curl -s -X POST http://127.0.0.1:8787/api/payload/<id>/consume -H "X-CipherDrop-Consume-Secret: $CONSUME_SECRET" → 1 回目 200（暗号文）、2 回目以降 404
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

**受取・復号 (`/v/:id#key.consumeSecret`)**
0. **フラグメントの即時消去**: ページ読み込み時、`#` 以降をオンメモリに読み込んだ直後・最初のネットワーク
   リクエストより前に `history.replaceState` でアドレスバー・履歴から消す（形式が不正なリンクでも消す）。
   以後はこの画面のメモリ上にしか存在しない。**既知のトレードオフ**: 消去前は「確認段階でリロードしても
   URL に残った鍵で再取得できる」復旧性があったが、消去後のリロードは元の共有リンクを開き直す必要がある
   （`POST …/consume` の通信エラーによる再試行は、URL ではなくこの画面のメモリ上の値を使うため影響しない）。
1. **Stage 1（確認）**: `GET …/meta` だけを呼ぶ。種類・サイズ・有効期限・暗号方式を等幅で示し、amber の静かな通知（`border-amber-500/20 bg-amber-500/5`）で
   「**このデータは一度開くとサーバーから永久削除されます**」と事実だけを伝える。**ここでは何も消費しない。**
   `meta.keyCheck` があり、URL の鍵から計算した値と一致しなければ、「開く」ボタン自体を出さず `POST …/consume` を発行しない
   （「鍵が一致しません」。詳細は「鍵確認値」の節）。
2. **Stage 2（消費・復号）**: 「データを復号して表示」（ファイルは「データを復号してダウンロード」）を押したときだけ、
   メモリ上の `consumeSecret` を `X-CipherDrop-Consume-Secret` ヘッダーに載せて `POST …/consume`（詳細は「消費用秘密鍵」の節）。
   テキストは `renderTextSafely`（テキストノード）で等幅のコードブロックに表示し、**「コピー」「破棄」**をワンクリックで実行できる。
   「破棄」は表示中のデータ（テキスト・ファイルのバイト列）への参照を手放して画面から消去する（サーバー上のデータは取得時に削除済みなので、再表示はできない）。
   ファイルはダウンロードとして保存する。

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
| `POST /api/payload` | 本文: 暗号文（`application/octet-stream`）。ヘッダー: `X-CipherDrop-IV`（必須・base64url の 12 バイト）、`X-CipherDrop-Type`（必須・`text` \| `file`）、`X-CipherDrop-TTL`（任意・秒。既定 86400、範囲 60〜604800）、`X-CipherDrop-Key-Check`（任意・16進小文字 8 桁。形式が不正なら黙って無視する）、`X-CipherDrop-Consume-Verifier`（**必須**・consumeSecret の SHA-256 全体・16進小文字 64 桁）。→ `201 {"id","expiresAt"}` |
| `GET /api/payload/:id/meta` | → `200 {"type","size","expiresAt","keyCheck"?}`（`size` は暗号文のバイト数。`keyCheck` は送信時に付いていた場合だけ現れる）。**何も消費・変更しない**。存在しない・消費済み・期限切れは `404`。 |
| `POST /api/payload/:id/consume` | ヘッダー: `X-CipherDrop-Consume-Secret`（**必須**・base64url の 32 バイト）。→ `200` 暗号文 + `X-CipherDrop-IV`。**consumeVerifier と一致した場合だけ、返す前にストアから完全に削除する**（アトミック・`crypto.timingSafeEqual` で比較）。存在しない・消費済み・期限切れ・consumeSecret 不一致は `404`（区別しない）。 |
| `GET /api/payload/ping` | → `200 {"status":"ok"}`。ヘルスチェック専用。ストアには一切触れない。Docker の `HEALTHCHECK` が叩く。 |

| ステータス | `error` | 条件 |
| --- | --- | --- |
| 400 | `invalid_iv` / `invalid_type` / `invalid_ttl` / `invalid_ciphertext` / `invalid_consume_verifier` / `content_length_mismatch` / `query_not_allowed` | 形式不正（暗号文は 16 バイト以上）。**クエリ文字列は一切受け付けない** |
| 404 | `not_found` | 未発行・消費済み・期限切れ・consumeSecret 不一致・旧 URL（区別しない） |
| 405 / 415 | `method_not_allowed` / `unsupported_media_type` | GET・HEAD 等で `consume` はできない（本体も返らない） |
| 413 | `payload_too_large` | 既定 10 MiB 超 |
| 503 | `storage_full` | 保存容量（バイト数・件数のいずれか）の上限（既定 512 MiB・10 万件）。`Content-Length` の時点で予約できなければ本文を読まずに返す |

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

### 鍵確認値（Key Check Tag）

共有リンクのコピペミス・途中欠損（形式は正しいが内容が違う鍵）を、**消費する前に**検出するための仕組み。

- `generateKeyCheckTag(keyStr)` = `SHA-256("cipherdrop-key-check-v1:" + keyStr)` の先頭 32bit（16進小文字 8 桁）。
- 送信画面は生成時にこれを計算し、`X-CipherDrop-Key-Check` としてサーバーへ送る（任意項目・後方互換）。
- 受取画面は Stage 1（`GET …/meta`）の直後、URL の鍵からローカルで同じ値を計算して照合する。**不一致が確実な場合だけ**
  「開く」ボタン自体を出さず、`POST …/consume` を発行する手段を作らない（誤検出の余地があるとき＝ meta に
  `keyCheck` が無い・計算自体が失敗した、は安全側に倒して通常どおり続行する）。
- **既知のトレードオフ**: これは絶対遵守ルール「復号鍵はサーバーに送らない」の例外ではないが、鍵の一方向関数の出力の
  一部（32bit）は新たにサーバーへ渡ることになる。256bit の鍵を 32bit 絞り込んでも残り 224bit の全数探索は非現実的
  なので、これが鍵の総当たりを実用的に助けることはない。ただし「サーバーは鍵について一切の情報を持たない」という
  意味の完全なゼロ知識ではなくなる。詳細な設計意図は `crypto.ts` の `generateKeyCheckTag` のコメントを参照。

```ts
import { decryptPayload, encryptData, encryptFile, generateConsumeSecret, parseShareFragment, renderTextSafely } from './crypto.ts';

const { encryptedData, iv, keyString } = await encryptData(message);                    // string | ArrayBuffer
const sealed = await encryptFile({ name: file.name, data: await file.arrayBuffer() });  // ファイル（名前ごと暗号化）
const { secretString, verifierHex } = await generateConsumeSecret();                    // consumeVerifier（送信）と consumeSecret（URL）
const shareUrl = `${location.origin}/v/${id}#${keyString}.${secretString}`;             // 鍵・consumeSecret は # の後ろにだけ置く

const fragment = parseShareFragment(location.hash.slice(1));                            // null なら形式不正（消費する前に止める）
const payload = await decryptPayload(encrypted, iv, fragment!.keyString);               // { type: 'text' | 'file' | 'binary', … }
if (payload.type === 'text') renderTextSafely(document.getElementById('out')!, payload.text); // innerHTML は使わない
```

`tests/zero-knowledge.e2e.test.ts` の `sendSecret` / `receiveSecret` は、Node 専用 API を使わない API 層の利用サンプル。

### 消費用秘密鍵（Consume Secret）

ID（`/v/{id}` の `{id}`、128bit）は URL パスに載るため、サーバーのアクセスログ・ブラウザ履歴などから
第三者に知られる可能性が、鍵（URL フラグメントにしか存在しない）より相対的に高い。**ID だけ**を知る
第三者が `POST …/consume` を叩けば、正規の受信者より先にデータを破棄できてしまう（結果的に DoS になる）
という構造的な弱点を閉じるための仕組み。

- 送信時、復号鍵（`encKey`）とは**完全に独立**した 256bit の CSPRNG 値（`consumeSecret`）を新規生成し、
  共有 URL のフラグメントに `#{encKey}.{consumeSecret}` として載せる（base64url は `.` を生成しないので、
  区切りに使っても曖昧さがない。JWT が `.` を使うのと同じ理由）。
- 作成リクエストでは、`consumeSecret` の **SHA-256 全体**（`consumeVerifier`、16進 64 桁）だけを
  `X-CipherDrop-Consume-Verifier` として送る。サーバーは `consumeVerifier` を保存するが、`consumeSecret`
  そのものを見ることはない。
- 消費リクエストでは、URL から取り出した `consumeSecret` を `X-CipherDrop-Consume-Secret` として送る。
  サーバーは受け取った値の SHA-256 を計算し、保存済みの `consumeVerifier` と `crypto.timingSafeEqual`
  （タイミング攻撃対策）で比較し、**一致した場合だけ** `take()` を実行する。
- 不一致・未発行・取得済み・期限切れは、**すべて同じ** `404`（区別しない）。ID だけを知る攻撃者に
  「このヘッダーさえ整えれば何かが存在するか分かる」というオラクルを与えない。

`crypto.ts` の `generateConsumeSecret` / `parseShareFragment`、`store.ts` の `take()` を参照。

## 絶対遵守ルールと、その検証

| ルール | 実装 | 検証 |
| --- | --- | --- |
| 鍵は `#` にだけ置き、サーバーに送らない | `encryptData` は鍵を返すだけ。`api.ts` は鍵を受け取れず、ID も形式検証する。サーバーはクエリを拒否 | **E2E（API 層・UI 層）**: サーバーが受信した生 TCP バイトを全記録し、鍵・平文・ファイル名が生／hex／base64／部分列のどれでも現れないこと、受信リクエストが想定の本数だけでフラグメント・クエリ・Cookie が無いこと（鍵確認値・consumeVerifier ヘッダーを含めて検査する。鍵そのものではなく、鍵の一方向関数の出力の一部だけを送る設計上のトレードオフは「鍵確認値」の節を参照） |
| Web Crypto の AES-GCM 256、IV は毎回生成 | `crypto.ts` | OpenSSL（`node:crypto`）との相互運用、200 回で鍵・IV・暗号文がすべて異なること、外部 import が無いこと |
| 1 回読んだら即・物理削除（かつ、開く前には消えない） | `store.take(id, consumeSecret)`（取得・consumeSecret の検証・削除が不可分）。`stat()` は副作用なし・戻り値の型に暗号文を含まない。`consume` は POST のみ | 削除が応答より先、50 並行 consume で成功 1 回、**GET / HEAD / OPTIONS / 旧 URL を浴びせても消えない**。読み込み時の処理が `consume` を呼ばないこと（実行時 + AST） |
| ID だけでは消費できない（consumeSecret の構造的分離） | `consumeSecret` は復号鍵と独立した 256bit の秘密で、URL フラグメントにしか存在しない。サーバーへ送るのは作成時に SHA-256 だけ、消費時に生の値だけ | **E2E**: 正しい ID・誤った consumeSecret の組では 404（削除されない）。誤り・未発行・期限切れのいずれも、ステータス・ヘッダー・本文まで区別できないこと |
| XSS・ログ漏洩 | `renderTextSafely`（テキストノード）／DOM ビルダー（HTML 挿入なし・属性は許可リスト）／ログは固定スキーマ型のみ／厳格な CSP | XSS 文字列が要素にならないこと（jsdom・実ブラウザ）。`innerHTML` 等・`eval`・`console.*` を **AST で検査**。`setAttribute` は `dom.ts` だけ。**配布物にも** HTML 挿入 API・インライン・外部 URL が無いこと |

実装を意図的に壊して（削除しない・GET でも消費・読み込み時に自動消費・`innerHTML` 化・鍵を API へ渡す・CSP を外す・外部フォントを読む …）
テストが落ちることも確認済み。

## 配信（デプロイ）

以前は「配信側（リバースプロキシ）が満たすべき要件」を文章で列挙していただけだったが、いまはルートの
`Dockerfile` / `docker-compose.yml` / `deploy/` 一式がそれをそのまま実装している。

1. **HTTPS 必須**（HTTP では `crypto.subtle` が使えず、配信物の改ざんも防げない）。HSTS を付ける
   → `deploy/security-headers.conf`（`max-age=31536000; includeSubDomains; preload`）。
2. **SPA フォールバック**: `/v/*` を含む、実在しないパスも `index.html` を返す。`index.html` は `Cache-Control: no-store`、
   `assets/*`（ハッシュ付き）は長期キャッシュ → `deploy/nginx.conf` の `location = /index.html` / `location /assets/`。
3. **`/api/` をバックエンドへ中継**。リクエストボディの上限はバックエンドの上限（10 MiB）以上。
   **再試行は無効にする** → `deploy/nginx.conf` の `location /api/`（`proxy_next_upstream off`）。
4. **レスポンスヘッダー**で `Content-Security-Policy`（`frame-ancestors 'none'` を含む）・`X-Content-Type-Options: nosniff`・
   `X-Frame-Options: DENY`・`Referrer-Policy: no-referrer` を付ける → `deploy/security-headers.conf`
   （`apps/frontend/vite.config.ts` が `<meta>` に埋め込む CSP と同じ内容 + `frame-ancestors`。`<meta>` では効かないため、
   ここが最終的な強制点になる）。バックエンド自身の応答（`/api/*`）にも同等のヘッダーを付けている
   （`apps/backend/src/server.ts` の `BASE_HEADERS`）。
5. アクセスログにリクエストボディ・クエリを出さない → `deploy/nginx.conf` はリクエスト行とステータスだけを
   標準出力へ出す既定のログ形式のまま。バックエンドのログは固定スキーマ型のみ（`server.ts` の `LogEvent`）。

両方が同じ CSP を主張し続けているかは、`tests/infra.test.ts` が機械的に突き合わせて検査する（食い違えばテストが落ちる）。

### Docker でのデプロイ

```bash
cp .env.example .env    # TUNNEL_TOKEN を設定する（下記）
docker compose up -d --build
curl http://127.0.0.1:8080/api/payload/ping    # {"status":"ok"} が返ればローカルで疎通している
```

- **`Dockerfile`**（2 段階ビルド）: Stage 1 (`builder`) で `apps/backend` と `apps/frontend` をビルドし、
  Stage 2 (`runner`) は最小限の `node:24-alpine` + `nginx`（静的配信 + `/api` リバースプロキシ）+ `tini`（PID 1）だけを積む。
  `apps/backend` はランタイム依存パッケージが 0 なので、`node_modules` は最終イメージに一切コピーしていない
  （実行時に存在する npm パッケージが 0 個）。`USER node`（非 root）で動かすため、nginx は 80 番ではなく 8080 番で
  待ち受け、PID・一時ファイルはすべて書き込み可能な `/tmp` 配下に置いている
  （[nginx 公式の非 root 用イメージ](https://github.com/nginx/docker-nginx-unprivileged) と同じ構成）。
  `HEALTHCHECK` は `GET /api/payload/ping`（ストアに触れないヘルスチェック専用エンドポイント）を叩く。
- **Node のバージョン**: `node:24-alpine` を使う（`node:22-alpine` は使っていない）。`import.meta.main` は
  Node v24.2.0 で追加された API（v22.18.0 にバックポート）で、本プロジェクトの `engines.node`（`>=24.2.0`）はこれに
  合わせて決めている。古い Node で動かすと、バックエンドのエントリポイント（`if (import.meta.main)`）が実行されず、
  サーバーが起動しないまま「動いているように見える」不具合になり得るため、`tests/infra.test.ts` が Dockerfile の
  イメージタグを `engines.node` と突き合わせて検査する。
- **`docker-compose.yml`**: `app`（このイメージ。診断用に `127.0.0.1:8080` にだけ公開し、`0.0.0.0` へは出さない）と
  `cloudflared`（Cloudflare Tunnel、バージョン固定）の 2 サービス。Cloudflare Tunnel はアウトバウンド接続だけで動くので、
  自宅サーバー・NAT の背後でもポート開放が要らない。`cloudflared` は `app` が healthy になるまで起動を待つ
  （`depends_on: condition: service_healthy`）。
- **`.env`**（`.env.example` からコピー、コミットしない）: `TUNNEL_TOKEN` は Cloudflare Zero Trust ダッシュボード →
  Networks → Tunnels → 接続方法「Docker」で発行されるトークン。トンネルの Public Hostname の送信先（Service）は
  `http://app:8080` に向ける（`app` はこの compose 内のサービス名）。

**検証の限界（正直に書いておく）**: このリポジトリを検証した環境には Docker デーモンが無く、`docker build` /
`docker run` を実際には実行できていない。確認できたのはあくまで静的な検査（`tests/infra.test.ts`: マルチステージの
段数・非 root 設定・ヘルスチェックの URL・CSP の一致・Node バージョンなどをファイルの中身から突き合わせる）と、
`package-lock.json` に `linux-x64-musl` / `linux-arm64-musl`（Tailwind の `@tailwindcss/oxide`・`lightningcss`・
`vite` の `@rolldown/binding`）の最適依存が含まれていること（= alpine=musl 環境でも `npm ci` が正しいネイティブ
バイナリを選べるはず、という根拠）まで。**実際に `docker compose up -d --build` を実行し、`curl` でヘルスチェックと
実際の送受信フローが動くことを確認してから本番投入すること。**

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
   形式は正しいが内容が違う（コピペミス・途中欠損）鍵も、**鍵確認値**（送信時に任意で付ける、鍵から一方向に導出した
   32bit のタグ）があれば消費する前に検出して止める。ただし鍵確認値は送信側が省略でき、旧データにも存在しないので、
   その場合は従来どおり消費後の復号失敗で初めて分かる（安全側の既定動作。詳細は「鍵確認値」の節）。
4. **メタデータは見える。** 暗号文のサイズ、種別ヒント（text / file）、作成・期限・取得の時刻、鍵確認値（あれば・鍵の
   一方向関数の出力の 32bit）。パディングは未実装。
5. **削除の意味。** ストアから削除してから応答する。メモリ／ディスクのゼロ埋めは保証しない（保持しているのは暗号文のみで、鍵は無い）。
6. **インメモリ保存（MVP）。** 再起動すると未読の暗号文は消える。合計バイト数・件数の両方で上限を持つ
   （`Content-Length` の時点で予約できなければ、本文を読まずに `503` にする）。
7. **ID だけでは「消費」できない（解決済み）。** かつては ID（128bit・URL パスに露出しうる）を知っていれば
   誰でも `consume` を叩けたが、現在は復号鍵と独立した `consumeSecret`（URL フラグメントにしか存在しない）
   の一致を要求する（「消費用秘密鍵」の節）。**認証（ユーザー識別）は引き続き未実装**で、IP 単位のレート制限
   （nginx の `limit_conn` / `limit_req`）はあるが、多数の IP からの分散した連投までは防げない。
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
- `tests/` も `apps/*` と同じく npm workspace（`@cipherdrop/tests`）。ルートの `dev` / `build` / `check` は
  `npm run <script> --workspaces` を使うので、追加するワークスペースには同名のスクリプトが必要
  （無いと `npm run build` のようにワークスペースを跨ぐコマンドがそこで失敗する）。
- ルートの `npm run dev` は `npm run <script> --workspaces` を使っていない。npm の `run-script` に複数ワークスペースを
  並列実行する機能が無い（`--parallel` のような公式フラグは存在しない）ため、シェルのジョブ制御
  （`cmd1 & cmd2 & wait`）で 2 つの `npm run dev --workspace ...` を同じプロセスグループで動かしている。
  Ctrl+C は両方に届く。

## 法的文書・セキュリティ開示

B2B 導入・OSS 展開に向けた文書一式。**いずれもドラフトであり、公開前に事業者情報（［　］の箇所）を
埋め、弁護士等の専門家によるレビューを受けること。**

| 文書 | 内容 |
| --- | --- |
| [`PRIVACY.md`](PRIVACY.md) | プライバシーポリシー。ゼロ知識設計による構造的な保証、収集しない情報（ゼロログ・Cookie 不使用）、保持するメタデータの範囲 |
| [`TERMS.md`](TERMS.md) | 利用規約。一時配信サービスとしての性質、禁止事項、免責事項、鍵紛失時の復元不可能性 |
| [`SECURITY.md`](SECURITY.md) | 脆弱性の報告窓口（Responsible Disclosure）・Safe Harbor・脅威モデルの要約。GitHub の Security タブから参照される |
| [`docs/SECURITY_WHITEPAPER.md`](docs/SECURITY_WHITEPAPER.md) | 技術者向けセキュリティ・ホワイトペーパー。暗号アーキテクチャ・2 段階消費 API・鍵確認値の仕様とトレードオフを詳解 |
| [`apps/frontend/public/.well-known/security.txt`](apps/frontend/public/.well-known/security.txt) | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) 準拠。`https://cipherdrop.io/.well-known/security.txt` として配信される |

これらの文書の存在・必須用語・リンク切れの有無は `tests/docs-integrity.test.ts` が機械的に検査する
（見出しへのアンカーは GitHub の実際のスラッグ生成規則と照合済み）。

## 今後

レート制限／パスワード保護／パディング／ファイルシステムまたは Redis（`GETDEL`）ストア／SRI とソース公開／
複数ファイル（zip）／受信者向けの「人間確認」（自動クリックするスキャナ対策）。
