# syntax=docker/dockerfile:1.7
#
# CipherDrop 本番イメージ。
#   Stage 1 (builder) : 依存関係の取得とビルド（apps/backend, apps/frontend）だけを行う。
#   Stage 2 (runner)  : 最小限の alpine + node（コンパイル済みバックエンド）+ nginx（静的配信・
#                        リバースプロキシ）。非 root ユーザーで動かす。
#
# apps/backend はランタイム依存パッケージが 0（node:* のみ、tests/security-policy.test.ts が強制）
# なので、runner ステージには node_modules を一切コピーしない。最終イメージに npm パッケージは
# 実行時に 1 つも存在しない。
#
# Node は 24.2.0 以上が必要（`import.meta.main` を使っている。README「始め方」参照）。
# 22-alpine ではこの API が無い/バックポート待ちのバージョンがあり得るため、engines.node に合わせて
# 24-alpine を使う。

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM node:24-alpine AS builder
WORKDIR /app

# 依存解決だけを先に行い、Docker のレイヤーキャッシュを効かせる
# （ソースだけの変更では、この重い npm ci をやり直さない）。
COPY package.json package-lock.json .npmrc ./
COPY apps/backend/package.json apps/backend/package.json
COPY apps/frontend/package.json apps/frontend/package.json
# tests/ の中身（*.test.ts）はビルド対象外だが、npm workspaces（package-lock.json が参照する
# 3 つ目のワークスペース）としてマニフェストの存在だけは要る。
COPY tests/package.json tests/package.json
RUN npm ci

COPY tsconfig.base.json ./
COPY apps/backend apps/backend
COPY apps/frontend apps/frontend
RUN npm run build --workspace @cipherdrop/backend \
 && npm run build --workspace @cipherdrop/frontend

# ---------------------------------------------------------------------------
# Stage 2: Runner
# ---------------------------------------------------------------------------
FROM node:24-alpine AS runner

# tini: コンテナの PID 1 として、シグナルをプロセスグループ全体（-g）へ転送し、ゾンビを回収する。
# nginx: 静的配信 + /api リバースプロキシ。非 root で動かすので、実体は deploy/nginx.conf で
#        8080 番・/tmp 配下の一時ファイルに変更してある（deploy/README 相当の説明はそちら）。
RUN apk add --no-cache nginx tini

WORKDIR /app
# ビルド成果物だけを取り込む（devDependencies・ソースの .ts・tests/ は含まれない）。
COPY --from=builder /app/apps/backend/dist ./apps/backend/dist
COPY --from=builder /app/apps/frontend/dist ./apps/frontend/dist
COPY deploy/nginx.conf /etc/nginx/nginx.conf
COPY deploy/security-headers.conf /etc/nginx/security-headers.conf
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENV NODE_ENV=production
# バックエンドは 127.0.0.1（ループバックのみ）で待ち受ける。外部に公開するのは nginx の 8080 番だけ。
ENV HOST=127.0.0.1
ENV PORT=8787

EXPOSE 8080

# 公式 node イメージには uid 1000 の "node" ユーザーが最初から用意されている。
USER node

# nginx（8080）を経由して、静的配信とバックエンドへの中継の両方が生きているかを確認する
# （GET /api/payload/ping はストアに触れないヘルスチェック専用エンドポイント）。
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/payload/ping || exit 1

ENTRYPOINT ["/sbin/tini", "-g", "--", "/entrypoint.sh"]
