import type { ApiClient } from './api.ts';

/**
 * 画面が外の世界に触れるための窓口。
 *
 * 画面コードは `document` / `location` / `fetch` / `navigator.clipboard` などのグローバルを直接使わず、必ずここを通す。
 * ブラウザでは main.ts が実物を渡し、テストでは jsdom と偽物（記録用）を渡す。同じコードが両方で動く。
 */
export interface AppEnv {
  doc: Document;
  root: HTMLElement;
  location: { readonly origin: string; readonly pathname: string; readonly hash: string };
  history: { replaceState(data: unknown, unused: string, url?: string | URL | null): void };
  /** クリップボード API。使えない環境（非セキュアコンテキスト等）では null。 */
  clipboard: { writeText(text: string): Promise<void> } | null;
  api: ApiClient;
  /** 復号したファイルをダウンロードとして保存する（download.ts の saveFile）。 */
  saveFile(name: string, data: ArrayBuffer): void;
  now(): number;
  setTimeout(handler: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export interface ViewHandle {
  destroy(): void;
}
