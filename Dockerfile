# syntax=docker/dockerfile:1
# CipherDrop の本番イメージ。モノレポのルートをビルドコンテキストにして、npm workspaces のまま依存を解決する。
#   --target api     : API サーバー（apps/backend）
#   --target web     : 画面（apps/frontend）の静的配信と API へのリバースプロキシ（nginx）

# ---- build: TypeScript を dist/ にコンパイル ----
FROM node:24-bookworm-slim AS build
WORKDIR /app

COPY package.json package-lock.json .npmrc tsconfig.base.json ./
COPY apps/backend/package.json apps/backend/
COPY apps/frontend/package.json apps/frontend/
RUN npm ci --no-audit --no-fund

COPY apps/backend apps/backend
RUN npm run build -w @cipherdrop/backend

COPY apps/frontend apps/frontend
RUN npm run build -w @cipherdrop/frontend

# ---- api: ランタイム依存は 0 なので、dist と package.json だけを載せる ----
FROM node:24-bookworm-slim AS api
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080
WORKDIR /app

COPY --from=build /app/apps/backend/package.json ./package.json
COPY --from=build /app/apps/backend/dist ./dist

USER node
EXPOSE 8080

# GET /api/payload は 405 を返すだけで暗号文を消費しない（疎通確認に使って安全）
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+process.env.PORT+'/api/payload').then(r=>process.exit(r.status===405?0:1),()=>process.exit(1))"]

CMD ["node", "dist/server.js"]

# ---- web: 画面の静的ファイルを nginx（非 root・8080 番）で配信し、/api/ を API コンテナへ転送する ----
FROM nginxinc/nginx-unprivileged:1.28-alpine AS web
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY deploy/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/apps/frontend/dist /usr/share/nginx/html
EXPOSE 8080
