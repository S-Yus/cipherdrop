/**
 * 送信画面の上限値と選択肢。バックエンドの制約（既定: 暗号文 1 件 10 MiB、TTL 60 秒〜7 日）の範囲内に収める。
 * tests/ui-flow.e2e.test.ts が、バックエンドの値との整合を機械的に検査している。
 */

/**
 * 送れる内容（ファイル本体またはメッセージの UTF-8）の最大バイト数。画面には「10 MB」と表示される
 * （formatBytes は 1024 換算。バックエンドの上限 10 MiB = 10,485,760 と同じ単位）。
 * エンベロープ（タグ 1 + 名前長 2 + 名前 最大 1024）と GCM 認証タグ 16 バイトの分として、4 KiB の余裕を残している。
 */
export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024 - 4096;

export const TTL_OPTIONS: ReadonlyArray<{ readonly seconds: number; readonly label: string }> = [
  { seconds: 3_600, label: '1時間' },
  { seconds: 86_400, label: '24時間' },
  { seconds: 604_800, label: '7日間' },
];

export const DEFAULT_TTL_SECONDS = 86_400;
