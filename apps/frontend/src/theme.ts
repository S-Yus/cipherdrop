/** ライト/ダークの切替。選択は localStorage に保存し、未選択のときは OS の設定に従う（CSS 側）。 */

export type Theme = 'light' | 'dark';

export const THEME_STORAGE_KEY = 'cipherdrop-theme';

export interface ThemeStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** localStorage は使えない環境（プライベートモード等）があるので、すべて try/catch で包む。 */
export function readStoredTheme(storage: ThemeStorage | null): Theme | null {
  try {
    const value = storage?.getItem(THEME_STORAGE_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

export function storeTheme(storage: ThemeStorage | null, theme: Theme): void {
  try {
    storage?.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // 保存できなくても、この画面での切替は有効。
  }
}

/** 現在の見た目（明示選択があればそれ、なければ OS の設定）。 */
export function effectiveTheme(doc: Document, prefersDark: () => boolean): Theme {
  const explicit = doc.documentElement.dataset['theme'];
  if (explicit === 'light' || explicit === 'dark') return explicit;
  return prefersDark() ? 'dark' : 'light';
}

export function applyTheme(doc: Document, theme: Theme): void {
  doc.documentElement.dataset['theme'] = theme;
}
