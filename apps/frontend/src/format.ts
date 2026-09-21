/** 表示用の整形。すべて純粋関数（時刻・ロケールは引数で受け取る）。 */

const UNITS = ['B', 'KB', 'MB', 'GB'] as const;

/** バイト数を人が読みやすい形に（1024 区切り）。例: 1536 → "1.5 KB"、10485760 → "10 MB"。 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${Number(value.toFixed(digits))} ${UNITS[unit]}`;
}

/** 期限までの残り時間。例: "23時間 59分"、"6日 23時間"、"1分未満"。 */
export function formatRemaining(remainingMs: number): string {
  if (remainingMs <= 0) return '期限切れ';

  const minutes = Math.floor(remainingMs / 60_000);
  if (minutes < 1) return '1分未満';
  if (minutes < 60) return `${minutes}分`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}時間${minutes % 60 > 0 ? ` ${minutes % 60}分` : ''}`;

  const days = Math.floor(hours / 24);
  return `${days}日${hours % 24 > 0 ? ` ${hours % 24}時間` : ''}`;
}

/** 日時（ローカルタイムゾーン）。例: "2026/09/23 22:10"。timeZone はテスト用。 */
export function formatDateTime(date: Date, timeZone?: string): string {
  return new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    ...(timeZone === undefined ? {} : { timeZone }),
  }).format(date);
}
