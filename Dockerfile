# syntax=docker/dockerfile:1
# CipherDrop API サーバー（apps/backend）の本番イメージ。
# モノレポのルートをビルドコンテキストにして、npm workspaces のまま依存を解決する。

# ---- build: TypeScript を dist/ にコンパイル ----
FROM node:24-bookworm-slim AS build
WORKDIR /app

COPY package.json package-lock.json .npmrc tsconfig.base.json ./
COPY apps/backend/package.json apps/backend/
COPY apps/frontend/package.json apps/frontend/
RUN npm ci --no-audit --no-fund

COPY apps/backend apps/backend
RUN npm run build -w @cipherdrop/backend

# ---- runtime: ランタイム依存は 0 なので、dist と package.json だけを載せる ----
FROM node:24-bookworm-slim AS runtime
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
