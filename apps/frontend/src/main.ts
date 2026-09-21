/**
 * ブラウザのエントリーポイント。グローバル（document / location / fetch …）に触れるのはここだけで、
 * 画面のコードには AppEnv として渡す（テストでは jsdom と偽物を渡す）。
 */
import { createApiClient } from './api.ts';
import { mountApp } from './app.ts';
import { saveFile } from './download.ts';

const root = document.getElementById('app');
if (root === null) throw new Error('#app element not found');

/** localStorage は、プライベートモード等で参照しただけで例外になることがある。 */
function safeLocalStorage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

mountApp({
  doc: document,
  root,
  location,
  history,
  clipboard: navigator.clipboard ?? null, // 非セキュアコンテキストでは undefined
  api: createApiClient(),
  saveFile: (name, data) =>
    saveFile(
      {
        doc: document,
        createObjectURL: (blob) => URL.createObjectURL(blob),
        revokeObjectURL: (url) => URL.revokeObjectURL(url),
        setTimeout: (handler, ms) => window.setTimeout(handler, ms),
      },
      name,
      data,
    ),
  storage: safeLocalStorage(),
  prefersDark: () => window.matchMedia('(prefers-color-scheme: dark)').matches,
  now: () => Date.now(),
  setTimeout: (handler, ms) => window.setTimeout(handler, ms),
  clearTimeout: (handle) => window.clearTimeout(handle as number),
});
