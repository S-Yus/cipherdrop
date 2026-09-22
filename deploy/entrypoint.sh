#!/bin/sh
# nginx（静的配信 + /api リバースプロキシ、8080 番）と Node バックエンド（127.0.0.1:8787）を
# 同じコンテナ内で起動する。
#
# シグナルの扱いは Dockerfile 側（ENTRYPOINT の `tini -g`）に任せる。tini がプロセスグループ全体へ
# SIGTERM を転送するので、この中で個別に trap/kill する必要はない。
#   - nginx        : 既定どおり SIGTERM で即座に終了する。ここでは静的配信とリバースプロキシだけを
#                     行い、状態を持たないので、接続を打ち切っても実害は小さい。
#   - バックエンド : server.ts 自身が SIGTERM を捕捉し、進行中の接続を待ってから終了する
#                     （最大 10 秒。apps/backend/src/server.ts の shutdown を参照）。コンテナは、
#                     この node プロセス（下の exec で PID 1 の子として居座る）が終了するまで生き続ける。
set -eu

# 設定が壊れていたら、バックグラウンドで静かに失敗させず、ここで即座に・大声で落とす。
nginx -t
nginx -g 'daemon off;' &

exec node apps/backend/dist/server.js
