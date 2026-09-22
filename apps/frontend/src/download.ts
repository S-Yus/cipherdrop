import { sanitizeFileName } from './file-name.ts';

export interface DownloadEnv {
  doc: Document;
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
  setTimeout(handler: () => void, ms: number): unknown;
}

/** ブラウザがダウンロードを開始するまで、オブジェクト URL を保持する時間。 */
const REVOKE_AFTER_MS = 30_000;

/**
 * 復号したファイルをブラウザのダウンロードとして保存する。
 *
 * - Blob の種別は常に `application/octet-stream`。送信者が申告した MIME 型は使わない。
 *   `text/html` や `image/svg+xml` として扱うと、アプリと同じオリジンでスクリプトが動きかねない。
 * - アプリのオリジンでファイルを「開く」ことはしない（window.open・iframe・画面内表示をしない）。ダウンロードだけ。
 * - ファイル名は送信者が決めた信頼できない値なので、必ず無害化する。
 */
export function saveFile(env: DownloadEnv, name: string, data: ArrayBuffer): void {
  const url = env.createObjectURL(new Blob([data], { type: 'application/octet-stream' }));
  if (!url.startsWith('blob:')) {
    env.revokeObjectURL(url);
    throw new Error('download: unexpected object URL scheme');
  }

  const anchor = env.doc.createElement('a');
  anchor.href = url;
  anchor.download = sanitizeFileName(name);
  anchor.rel = 'noopener noreferrer';
  anchor.hidden = true;

  env.doc.body.append(anchor);
  anchor.click();
  anchor.remove();

  env.setTimeout(() => env.revokeObjectURL(url), REVOKE_AFTER_MS);
}
