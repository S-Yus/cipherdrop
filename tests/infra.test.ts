/**
 * 本番インフラ構成（Dockerfile・nginx・docker-compose・.dockerignore）の検査。
 *
 * このサンドボックスには Docker デーモンが無く、`docker build` / `docker run` は実行できない
 * （検証内容と既知の限界は README「Docker でのデプロイ」の末尾に明記している）。ここでは代わりに、
 * 各設定ファイルを静的に検査し、特に「複数ファイルにまたがる値が食い違っていないか」
 * （ヘルスチェックの URL、CSP の内容、Node のバージョン、アップロード上限）を機械的に確認する。
 *
 * YAML・Dockerfile 用の外部パーサは追加しない（このプロジェクトは新規の依存を増やさない方針）。
 * 構造がシンプルで自分で書いたファイルなので、行ベース・正規表現の検査で十分に検出力がある
 * （検査が空振りしていないことは、末尾の自己テストで確認する）。
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (relativePath: string): string => readFileSync(join(ROOT, relativePath), 'utf8');

const dockerfile = read('Dockerfile');
const dockerignore = read('.dockerignore');
const compose = read('docker-compose.yml');
const nginxConf = read('deploy/nginx.conf');
const securityHeaders = read('deploy/security-headers.conf');
const entrypoint = read('deploy/entrypoint.sh');
const serverSource = read('apps/backend/src/server.ts');
const viteConfigSource = read('apps/frontend/vite.config.ts');
const rootPackageJson = JSON.parse(read('package.json')) as { engines?: { node?: string } };

// ---------------------------------------------------------------------------
// 抽出ヘルパー（正規表現。対象は自分で書いた小さな設定ファイルなので、これで十分検出力がある）
// ---------------------------------------------------------------------------

/** Dockerfile の `FROM <image> [AS <name>]` 行をすべて取り出す。 */
function fromStages(source: string): Array<{ image: string; name: string | null }> {
  return [...source.matchAll(/^FROM\s+(\S+)(?:\s+AS\s+(\S+))?/gim)].map((m) => ({ image: m[1] ?? '', name: m[2] ?? null }));
}

/** `node:XX[.Y[.Z]]-alpine` のようなイメージ参照からメジャーバージョン（数値）を取り出す。 */
function nodeMajorVersion(image: string): number | null {
  const m = /^node:(\d+)/.exec(image);
  return m?.[1] ? Number(m[1]) : null;
}

/** package.json の "engines.node" 等（">=24.2.0" 形式）からメジャーバージョンを取り出す。 */
function requiredNodeMajor(enginesNode: string | undefined): number | null {
  const m = /(\d+)(?:\.\d+){0,2}/.exec(enginesNode ?? '');
  return m?.[1] ? Number(m[1]) : null;
}

/** server.ts の `const NAME = '...';` という単純な文字列リテラル定数を取り出す。 */
function stringConst(source: string, name: string): string | null {
  const m = new RegExp(`const ${name}\\s*=\\s*'([^']*)'`).exec(source);
  return m?.[1] ?? null;
}

/**
 * vite.config.ts の CONTENT_SECURITY_POLICY 配列（各要素が "default-src 'none'" のような二重引用符の
 * 文字列リテラル。内側の単引用符は CSP のキーワード）から directive の集合を取り出す。
 */
function viteCspDirectives(source: string): Set<string> {
  const block = /CONTENT_SECURITY_POLICY\s*=\s*\[([\s\S]*?)\]/.exec(source)?.[1] ?? '';
  return new Set([...block.matchAll(/"([^"]+)"/g)].map((m) => m[1] ?? ''));
}

/** nginx の `add_header Content-Security-Policy "...";` の中身から directive の集合を取り出す。 */
function nginxCspDirectives(source: string): Set<string> {
  const value = /add_header\s+Content-Security-Policy\s+"([^"]+)"/.exec(source)?.[1] ?? '';
  return new Set(
    value
      .split(';')
      .map((part) => part.trim())
      .filter(Boolean),
  );
}

/** `client_max_body_size 11m;` のような nginx のサイズ指定をバイト数に変換する。 */
function nginxSizeToBytes(value: string): number {
  const m = /^(\d+)([kKmMgG]?)$/.exec(value.trim());
  if (!m?.[1]) throw new Error(`unrecognized nginx size: ${value}`);
  const n = Number(m[1]);
  const unit = (m[2] ?? '').toLowerCase();
  const multiplier = unit === 'k' ? 1024 : unit === 'm' ? 1024 * 1024 : unit === 'g' ? 1024 * 1024 * 1024 : 1;
  return n * multiplier;
}

// ---------------------------------------------------------------------------
// Dockerfile
// ---------------------------------------------------------------------------

describe('Dockerfile: マルチステージ構成', () => {
  it('ちょうど 2 段（builder → runner）で、それぞれ名前が付いている', () => {
    const stages = fromStages(dockerfile);
    assert.equal(stages.length, 2, `FROM の数が 2 ではない: ${JSON.stringify(stages)}`);
    assert.deepEqual(stages.map((s) => s.name?.toLowerCase()), ['builder', 'runner']);
  });

  it('両ステージとも node:<engines.node 以上>-alpine を使う（node:22-alpine は import.meta.main を欠く場合があり不可）', () => {
    const requiredMajor = requiredNodeMajor(rootPackageJson.engines?.node);
    assert.ok(requiredMajor !== null, 'package.json の engines.node が読めていること');

    const stages = fromStages(dockerfile);
    assert.ok(stages.length > 0);
    for (const { image } of stages) {
      assert.match(image, /-alpine$/, `alpine イメージであること: ${image}`);
      const major = nodeMajorVersion(image);
      assert.ok(major !== null, `node:<major> の形式であること: ${image}`);
      assert.ok(major >= (requiredMajor ?? 0), `${image} は engines.node（>=${requiredMajor}）を満たさない`);
    }
  });

  it('runner ステージは node_modules を一切コピーしない（backend はランタイム依存 0 なので不要）', () => {
    const runnerStart = dockerfile.search(/^FROM .* AS runner/im);
    assert.ok(runnerStart >= 0);
    const runnerSection = dockerfile.slice(runnerStart);
    assert.doesNotMatch(runnerSection, /node_modules/);
  });

  it('非 root（USER node）で実行し、リモート URL を直接取り込む ADD は使わない', () => {
    assert.match(dockerfile, /^USER\s+node\s*$/im);
    assert.doesNotMatch(dockerfile, /^ADD\s+https?:\/\//im, 'リモート URL からの ADD は使わない（サプライチェーンリスク）');
  });

  it('HEALTHCHECK があり、対象は server.ts の PING_PATH と完全に一致する URL', () => {
    // Dockerfile の行末 `\` による継続行も含めて、命令 1 つ分をまとめて取り出す。
    const healthcheck = /^HEALTHCHECK\b(?:.*\\\r?\n)*.*$/im.exec(dockerfile)?.[0];
    assert.ok(healthcheck, 'HEALTHCHECK 命令が無い');
    assert.match(healthcheck, /--interval=/);
    assert.match(healthcheck, /--timeout=/);
    assert.match(healthcheck, /--retries=/);

    const pingPath = stringConst(serverSource, 'PING_PATH');
    assert.ok(pingPath, 'server.ts から PING_PATH を読み取れること');
    assert.ok(healthcheck.includes(`http://127.0.0.1:8080${pingPath}`), `HEALTHCHECK が ${pingPath} を指していない: ${healthcheck}`);
  });

  it('ENTRYPOINT は tini を PID 1 とし、プロセスグループ（-g）へシグナルを転送する', () => {
    assert.match(dockerfile, /ENTRYPOINT\s*\[\s*"\/sbin\/tini"\s*,\s*"-g"/);
  });

  it('ビルドコンテキストのファイルは Dockerfile が明示的に COPY するものだけ（ワイルドカード COPY はしない）', () => {
    const copies = [...dockerfile.matchAll(/^COPY\s+(?!--from)(\S+)/gim)].map((m) => m[1] ?? '');
    assert.ok(copies.length > 0);
    for (const source of copies) assert.doesNotMatch(source, /\*/, `COPY にワイルドカードを使っている: ${source}`);
  });
});

describe('.dockerignore', () => {
  it('node_modules・.git・.env・dist をビルドコンテキストから除外する', () => {
    for (const pattern of ['node_modules', '.git', '.env', 'dist']) {
      assert.ok(dockerignore.split('\n').some((line) => line.trim() === pattern), `.dockerignore に "${pattern}" が無い`);
    }
  });

  it('.env.example は除外しない（Dockerfile はこれを読まないが、誤って除外ルールを広げていないことの確認）', () => {
    assert.match(dockerignore, /^!\.env\.example$/m);
  });
});

// ---------------------------------------------------------------------------
// nginx
// ---------------------------------------------------------------------------

describe('deploy/nginx.conf: 非 root・8080 番での静的配信 + /api 中継', () => {
  it('80 番ではなく 8080 番で待ち受ける（非 root は 1024 未満のポートを bind できない）', () => {
    assert.match(nginxConf, /listen\s+8080;/);
    assert.doesNotMatch(nginxConf, /listen\s+80;/);
  });

  it('user ディレクティブが無い（非 root プロセスは setuid できず、あると起動に失敗する）', () => {
    assert.doesNotMatch(nginxConf, /^\s*user\s+\S+;/m);
  });

  it('pid・すべての一時ファイルパスが /tmp 配下（既定の /var/run・/var/cache/nginx は非 root で書けない）', () => {
    assert.match(nginxConf, /^\s*pid\s+\/tmp\//m);
    for (const directive of ['client_body_temp_path', 'proxy_temp_path', 'fastcgi_temp_path', 'uwsgi_temp_path', 'scgi_temp_path']) {
      assert.match(nginxConf, new RegExp(`${directive}\\s+/tmp/`), `${directive} が /tmp 配下でない`);
    }
  });

  it('/api/ はバックエンド（127.0.0.1:8787）へ中継し、再送しない（消費 API の 2 回目は 404 になるため）', () => {
    const apiBlock = /location\s+\/api\/\s*\{([\s\S]*?)\n\s*\}/.exec(nginxConf)?.[1] ?? '';
    assert.ok(apiBlock, '/api/ の location ブロックが見つからない');
    assert.match(apiBlock, /proxy_pass\s+http:\/\/127\.0\.0\.1:8787;/);
    assert.match(apiBlock, /proxy_next_upstream\s+off;/);
  });

  it('/api/ にはセキュリティヘッダーを二重に付けない（バックエンド自身の応答ヘッダーを上書き・重複させない）', () => {
    const apiBlock = /location\s+\/api\/\s*\{([\s\S]*?)\n\s*\}/.exec(nginxConf)?.[1] ?? '';
    assert.doesNotMatch(apiBlock, /security-headers\.conf/);
    assert.doesNotMatch(apiBlock, /add_header/);
  });

  it('静的配信の location（/assets/・= /index.html・/）はすべて security-headers.conf を include する', () => {
    for (const location of ['location /assets/', 'location = /index.html', 'location / ']) {
      const start = nginxConf.indexOf(location);
      assert.ok(start >= 0, `${location} ブロックが見つからない`);
      const block = /\{([\s\S]*?)\n\s*\}/.exec(nginxConf.slice(start))?.[1] ?? '';
      assert.match(block, /include\s+\/etc\/nginx\/security-headers\.conf;/, `${location} が security-headers.conf を include していない`);
    }
  });

  it('SPA フォールバック: 実在しないパスは index.html を返す', () => {
    assert.match(nginxConf, /try_files\s+\$uri\s+\$uri\/\s+\/index\.html;/);
  });

  it('アップロード上限（client_max_body_size）は、バックエンドの上限（DEFAULT_MAX_PAYLOAD_BYTES）以上', () => {
    const nginxLimit = /client_max_body_size\s+(\S+);/.exec(nginxConf)?.[1];
    assert.ok(nginxLimit, 'client_max_body_size が見つからない');

    const backendLimitExpr = /DEFAULT_MAX_PAYLOAD_BYTES\s*=\s*([^;]+);/.exec(serverSource)?.[1];
    assert.ok(backendLimitExpr, 'server.ts から DEFAULT_MAX_PAYLOAD_BYTES を読み取れること');
    // eslint 等を通さない単純な算術式（"10 * 1024 * 1024" 等）なので、Function ではなく手計算で評価する。
    const backendLimitBytes = backendLimitExpr
      .split('*')
      .map((part) => Number(part.trim()))
      .reduce((a, b) => a * b, 1);
    assert.ok(Number.isFinite(backendLimitBytes) && backendLimitBytes > 0, `DEFAULT_MAX_PAYLOAD_BYTES を数値化できない: ${backendLimitExpr}`);

    assert.ok(nginxSizeToBytes(nginxLimit) >= backendLimitBytes, `nginx の上限 (${nginxLimit}) がバックエンドの上限 (${backendLimitBytes}B) を下回っている`);
  });
});

describe('deploy/nginx.conf: DoS 対策（接続数・リクエスト頻度の制限、低速接続のタイムアウト）', () => {
  it('IP単位の接続数制限（limit_conn_zone）とリクエスト頻度制限（limit_req_zone）を、$binary_remote_addr で定義している', () => {
    assert.match(nginxConf, /limit_conn_zone\s+\$binary_remote_addr\s+zone=\w+:\d+[kKmMgG];/);
    assert.match(nginxConf, /limit_req_zone\s+\$binary_remote_addr\s+zone=\w+:\d+[kKmMgG]\s+rate=\d+r\/[sm];/);
  });

  it('定義したゾーンを、実際に limit_conn / limit_req で適用している（定義しただけで使わない抜けを防ぐ）', () => {
    const connZone = /limit_conn_zone\s+\$binary_remote_addr\s+zone=(\w+):/.exec(nginxConf)?.[1];
    const reqZone = /limit_req_zone\s+\$binary_remote_addr\s+zone=(\w+):/.exec(nginxConf)?.[1];
    assert.ok(connZone, 'limit_conn_zone のゾーン名を読み取れること');
    assert.ok(reqZone, 'limit_req_zone のゾーン名を読み取れること');
    assert.match(nginxConf, new RegExp(`limit_conn\\s+${connZone}\\s+\\d+;`), 'limit_conn_zone を定義したゾーンが limit_conn で使われていない');
    assert.match(nginxConf, new RegExp(`limit_req\\s+zone=${reqZone}\\b`), 'limit_req_zone を定義したゾーンが limit_req で使われていない');
  });

  it('client_body_timeout・send_timeout・client_header_timeout を設定している（Slowloris など低速接続攻撃の自動切断）', () => {
    assert.match(nginxConf, /client_body_timeout\s+\d+s;/);
    assert.match(nginxConf, /send_timeout\s+\d+s;/);
    assert.match(nginxConf, /client_header_timeout\s+\d+s;/);
  });
});

describe('deploy/nginx.conf: 安全なアクセスログ（ペイロード ID を含む URI・クエリ文字列を記録しない）', () => {
  it('log_format の中身に、URI・クエリ文字列を含む変数を使っていない', () => {
    const format = /log_format\s+\w+\s+([\s\S]*?);/.exec(nginxConf)?.[1] ?? '';
    assert.ok(format.length > 0, 'log_format が見つからない');
    for (const variable of ['$request_uri', '$query_string', '$args', '$uri', '$document_uri']) {
      assert.equal(format.includes(variable), false, `${variable} を log_format に含めてはならない（ペイロード ID が残る）`);
    }
    // $request は "METHOD URI HTTP/x.x" の結合（URI を含む）。$request_method・$request_time とは別物として
    // 明示的に除外する（前方一致で $request_method 等まで拾ってしまわないよう、後続に識別子が無い場合だけ検出する）。
    assert.doesNotMatch(format, /\$request(?![A-Za-z_])/, '$request（URI を含む）を log_format に含めてはならない');
  });

  it('カスタムした log_format を、実際に access_log で使っている（定義しただけで既定の combined のままという抜けを防ぐ）', () => {
    const formatName = /log_format\s+(\w+)\s/.exec(nginxConf)?.[1];
    assert.ok(formatName, 'log_format の名前を読み取れること');
    assert.match(nginxConf, new RegExp(`access_log\\s+\\S+\\s+${formatName};`), `access_log が ${formatName} を指定していない`);
  });
});

describe('deploy/security-headers.conf: エンタープライズ基準のヘッダー', () => {
  it('HSTS・nosniff・DENY・no-referrer・CSP のすべてを、always 付きで指定している', () => {
    const expected: Array<[string, RegExp]> = [
      ['HSTS', /add_header\s+Strict-Transport-Security\s+"max-age=31536000;\s*includeSubDomains;\s*preload"\s+always;/],
      ['X-Content-Type-Options', /add_header\s+X-Content-Type-Options\s+"nosniff"\s+always;/],
      ['X-Frame-Options', /add_header\s+X-Frame-Options\s+"DENY"\s+always;/],
      ['Referrer-Policy', /add_header\s+Referrer-Policy\s+"no-referrer"\s+always;/],
      ['CSP', /add_header\s+Content-Security-Policy\s+"[^"]+"\s+always;/],
    ];
    for (const [name, pattern] of expected) assert.match(securityHeaders, pattern, `${name} が期待どおりでない`);
  });

  it('CSP は vite.config.ts が <meta> に埋め込むものと同じ内容 + frame-ancestors（<meta> では効かないため）', () => {
    const viteDirectives = viteCspDirectives(viteConfigSource);
    const nginxDirectives = nginxCspDirectives(securityHeaders);

    assert.ok(viteDirectives.size > 5, 'vite.config.ts から CSP を読み取れていること（空振り防止）');
    for (const directive of viteDirectives) {
      assert.ok(nginxDirectives.has(directive), `nginx 側に "${directive}" が無い（<meta> の CSP と食い違っている）`);
    }
    assert.ok(nginxDirectives.has("frame-ancestors 'none'"), 'nginx 側は frame-ancestors を持つべき（<meta> にはできない制約）');
    assert.equal(nginxDirectives.size, viteDirectives.size + 1, 'frame-ancestors 以外に差分があってはならない');
  });
});

// ---------------------------------------------------------------------------
// entrypoint.sh
// ---------------------------------------------------------------------------

describe('deploy/entrypoint.sh', () => {
  it('nginx の設定を起動前に検証し（nginx -t）、失敗を握りつぶさない（set -eu）', () => {
    assert.match(entrypoint, /^set\s+-eu\s*$/m);
    assert.match(entrypoint, /^nginx\s+-t\s*$/m);
  });

  it('最後に node を exec する（シグナルが直接 node プロセスへ届き、シェルを介さない）', () => {
    const lines = entrypoint
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '' && !line.startsWith('#'));
    assert.equal(lines.at(-1), 'exec node apps/backend/dist/server.js');
  });

  it('nginx はバックグラウンドで起動する（node の exec より前に、生存を妨げない）', () => {
    assert.match(entrypoint, /^nginx -g 'daemon off;' &$/m);
  });
});

// ---------------------------------------------------------------------------
// docker-compose.yml
// ---------------------------------------------------------------------------

describe('docker-compose.yml: CipherDrop 本体 + Cloudflare Tunnel', () => {
  it('app サービスは Dockerfile からビルドし、公開ポートはループバックのみ（0.0.0.0 には出さない）', () => {
    assert.match(compose, /app:\s*\n\s*build:\s*\n\s*context:\s*\.\s*\n\s*dockerfile:\s*Dockerfile/);
    assert.match(compose, /"127\.0\.0\.1:8080:8080"/);
    assert.doesNotMatch(compose, /"0\.0\.0\.0:8080:8080"/);
    assert.doesNotMatch(compose, /^\s*-\s*"?8080:8080"?\s*$/m, 'すべてのインターフェースに公開する短縮記法を使っていない');
  });

  it('cloudflared のイメージタグは固定されている（:latest ではない）', () => {
    const image = /cloudflared:\s*\n?\s*image:\s*(\S+)/.exec(compose)?.[1] ?? /image:\s*(cloudflare\/cloudflared:\S+)/.exec(compose)?.[1];
    assert.ok(image, 'cloudflared の image が見つからない');
    assert.doesNotMatch(image, /:latest$/);
    assert.match(image, /^cloudflare\/cloudflared:\d{4}\.\d+\.\d+$/, `固定版のタグ（YYYY.M.N）であること: ${image}`);
  });

  it('cloudflared は app が healthy になるまで待つ（depends_on + condition: service_healthy）', () => {
    const cloudflaredBlock = compose.slice(compose.indexOf('cloudflared:'));
    assert.match(cloudflaredBlock, /depends_on:\s*\n\s*app:\s*\n\s*condition:\s*service_healthy/);
  });

  it('TUNNEL_TOKEN はプレースホルダ参照だけで、実際のトークンらしき値をファイルに書いていない', () => {
    assert.match(compose, /TUNNEL_TOKEN:\s*\$\{TUNNEL_TOKEN/);
    // 実物のトークンは長い base64 風の文字列になりがちだが、ここにあるのは変数参照の構文だけであること。
    assert.doesNotMatch(compose, /TUNNEL_TOKEN:\s*[A-Za-z0-9+/]{40,}/);
  });
});

// ---------------------------------------------------------------------------
// 検査器の自己テスト（違反を検出できること・誤検知しないこと）
// ---------------------------------------------------------------------------

describe('検査器の自己テスト', () => {
  it('fromStages: FROM ... AS ... を複数行から取り出せる（大文字小文字・タグ違いを含む）', () => {
    const sample = 'FROM node:24-alpine AS builder\nRUN echo hi\nfrom node:24-alpine as runner\n';
    assert.deepEqual(fromStages(sample), [
      { image: 'node:24-alpine', name: 'builder' },
      { image: 'node:24-alpine', name: 'runner' },
    ]);
  });

  it('nodeMajorVersion / requiredNodeMajor: 数値化と比較が壊れていない', () => {
    assert.equal(nodeMajorVersion('node:22-alpine'), 22);
    assert.equal(nodeMajorVersion('node:24.2-alpine'), 24);
    assert.equal(nodeMajorVersion('nginx:alpine'), null);
    assert.equal(requiredNodeMajor('>=24.2.0'), 24);
    assert.ok(22 < (requiredNodeMajor('>=24.2.0') ?? 0), 'node:22-alpine は >=24.2.0 を満たさない、と検出できること');
  });

  it('viteCspDirectives / nginxCspDirectives: ずれを実際に検出できる（自己テスト）', () => {
    const vite = viteCspDirectives(`const CONTENT_SECURITY_POLICY = [\n  "default-src 'none'",\n  "script-src 'self'",\n].join('; ');`);
    assert.deepEqual([...vite].sort(), ["default-src 'none'", "script-src 'self'"]);

    const matching = nginxCspDirectives(`add_header Content-Security-Policy "default-src 'none'; script-src 'self'; frame-ancestors 'none'" always;`);
    assert.deepEqual([...matching].sort(), ["default-src 'none'", "frame-ancestors 'none'", "script-src 'self'"]);

    // 意図的に 1 つ欠けさせた場合 → 不一致を検出できることの確認
    const broken = nginxCspDirectives(`add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;`);
    assert.equal(broken.has("script-src 'self'"), false, 'script-src の欠落を検出できていない');
  });

  it('nginxSizeToBytes: k/m/g 単位を正しくバイトへ変換する', () => {
    assert.equal(nginxSizeToBytes('11m'), 11 * 1024 * 1024);
    assert.equal(nginxSizeToBytes('512k'), 512 * 1024);
    assert.equal(nginxSizeToBytes('1g'), 1024 * 1024 * 1024);
    assert.equal(nginxSizeToBytes('100'), 100);
    // 意図的に小さすぎる値を渡すと、実際の比較テストが「下回っている」と検出できることの確認。
    assert.ok(nginxSizeToBytes('1k') < 10 * 1024 * 1024);
  });

  it('stringConst: 単純な文字列定数を取り出せる。無い名前は null', () => {
    assert.equal(stringConst(`const PING_PATH = '/api/payload/ping';`, 'PING_PATH'), '/api/payload/ping');
    assert.equal(stringConst(`const OTHER = 'x';`, 'PING_PATH'), null);
  });
});
