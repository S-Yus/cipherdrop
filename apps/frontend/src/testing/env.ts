/**
 * 画面のテスト支援（jsdom 上で、本番と同じ画面コードを動かす）。
 * AppEnv を偽物で組み立て、API 呼び出し・クリップボード書き込み・ファイル保存・タイマーを記録する。
 * ブラウザのビルドには含まれない（tsconfig と セキュリティポリシーの検査の対象外）。
 */
import { JSDOM } from 'jsdom';
import { ApiError } from '../api.ts';
import type { ApiClient, PayloadMeta } from '../api.ts';
import type { AppEnv } from '../env.ts';

export const NOW = Date.UTC(2026, 8, 22, 12, 0, 0);
export const SAMPLE_ID = 'abcdefghijklmnopqrstuv'; // 22 文字（形式は正しい）

export interface TestEnvOptions {
  /** 表示するページの URL。既定は https://cipherdrop.io/ 。 */
  url?: string;
  /** 上書きする API。指定しなかったメソッドは、既定の振る舞い（作成は成功、meta / consume は 404）になる。 */
  api?: Partial<ApiClient>;
  clipboard?: 'ok' | 'fail' | 'none';
  saveFileThrows?: boolean;
}

export type ApiCall =
  | { method: 'createPayload'; args: Parameters<ApiClient['createPayload']> }
  | { method: 'getMeta'; args: [string] }
  | { method: 'consume'; args: [string] };

export function createTestEnv(options: TestEnvOptions = {}) {
  const dom = new JSDOM('<!doctype html><html lang="ja"><head><title></title></head><body><div id="app"></div></body></html>', {
    url: options.url ?? 'https://cipherdrop.io/',
  });
  const { window } = dom;
  const doc = window.document;
  const root = doc.getElementById('app');
  if (root === null) throw new Error('test setup: #app is missing');

  const calls: ApiCall[] = [];
  const api: ApiClient = {
    async createPayload(input) {
      calls.push({ method: 'createPayload', args: [input] });
      if (options.api?.createPayload) return options.api.createPayload(input);
      return { id: SAMPLE_ID, expiresAt: new Date(NOW + input.ttlSeconds * 1000) };
    },
    async getMeta(id) {
      calls.push({ method: 'getMeta', args: [id] });
      if (options.api?.getMeta) return options.api.getMeta(id);
      throw new ApiError('not_found', 404);
    },
    async consume(id) {
      calls.push({ method: 'consume', args: [id] });
      if (options.api?.consume) return options.api.consume(id);
      throw new ApiError('not_found', 404);
    },
  };

  const saved: Array<{ name: string; data: ArrayBuffer }> = [];
  const clipboardWrites: string[] = [];
  const timers = new Map<number, () => void>();
  let nextTimer = 1;
  let now = NOW;

  const env: AppEnv = {
    doc,
    root,
    location: window.location,
    history: window.history,
    clipboard:
      options.clipboard === 'none'
        ? null
        : {
            async writeText(text) {
              if (options.clipboard === 'fail') throw new Error('denied');
              clipboardWrites.push(text);
            },
          },
    api,
    saveFile(name, data) {
      if (options.saveFileThrows) throw new Error('blocked');
      saved.push({ name, data });
    },
    now: () => now,
    setTimeout(handler) {
      const id = nextTimer++;
      timers.set(id, handler);
      return id;
    },
    clearTimeout(handle) {
      timers.delete(handle as number);
    },
  };

  return {
    env,
    dom,
    window,
    doc,
    root,
    calls,
    saved,
    clipboardWrites,
    /** 予約されているタイマーをすべて実行する（コピー表示の復帰など）。 */
    runTimers() {
      const pending = [...timers.values()];
      timers.clear();
      for (const handler of pending) handler();
    },
    setNow(value: number) {
      now = value;
    },
    /** 画面の本文領域（<main>）。 */
    get main(): HTMLElement {
      return query(doc, 'main');
    },
  };
}

export function meta(type: 'text' | 'file', size = 100, expiresInMs = 23 * 3_600_000): PayloadMeta {
  return { type, size, expiresAt: new Date(NOW + expiresInMs) };
}

// ---- DOM 操作 -------------------------------------------------------------------------------

export function query<T extends Element = HTMLElement>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (element === null) throw new Error(`test: element not found: ${selector}`);
  return element;
}

export function has(root: ParentNode, selector: string): boolean {
  return root.querySelector(selector) !== null;
}

/** 条件が満たされるまで待つ（非同期の画面更新用）。任意の sleep より確実で、失敗時は原因が分かる。 */
export async function waitFor<T>(condition: () => T | null | undefined | false, timeoutMs = 3000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = condition();
    if (value) return value;
    if (Date.now() > deadline) throw new Error('test: waitFor timed out');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export function click(element: Element): void {
  const view = element.ownerDocument.defaultView;
  if (view === null) throw new Error('test: detached element');
  element.dispatchEvent(new view.MouseEvent('click', { bubbles: true, cancelable: true }));
}

/** 入力欄に値を入れて input イベントを発火する。 */
export function typeInto(element: HTMLTextAreaElement | HTMLInputElement, value: string): void {
  element.value = value;
  element.dispatchEvent(new (element.ownerDocument.defaultView as Window & typeof globalThis).Event('input', { bubbles: true }));
}

export function press(element: Element, key: string): KeyboardEvent {
  const view = element.ownerDocument.defaultView as Window & typeof globalThis;
  const event = new view.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true });
  element.dispatchEvent(event);
  return event;
}

/** ファイルのドラッグ＆ドロップを再現する（jsdom には DataTransfer がないので dataTransfer を直接付ける）。 */
export function dropFiles(element: Element, files: File[]): void {
  const view = element.ownerDocument.defaultView as Window & typeof globalThis;
  const event = new view.Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'dataTransfer', { value: { files } });
  element.dispatchEvent(event);
}

export function makeFile(name: string, content: Uint8Array | string): File {
  return new File([typeof content === 'string' ? content : new Uint8Array(content)], name);
}
