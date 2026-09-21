/**
 * 暗号文ストア。
 *
 * サーバーが保持してよいのは「暗号文・IV・有効期限・表示用の種別ヒント」だけ。
 * 平文も鍵も、このプロセスには存在しない。
 *
 * 暗号文がストアの外へ出る経路は take()（取得と削除が不可分）だけにしている。
 * 「削除せずに暗号文を読む」get() を用意しないことで、1 回読み切り（Self-Destruct）を
 * API の形そのもので保証する。
 *
 * 受信者に事前確認（メタ情報の表示）をさせるための stat() は、状態を一切変えず、
 * 戻り値の型にも暗号文・IV を含めない。リンクプレビューやクローラーが叩いても何も失われない。
 *
 * 実装を差し替える場合も take() の原子性は必須:
 *   - Redis:      GETDEL（Redis >= 6.2）/ 書き込みは SET ... EX / stat は STRLEN + TTL
 *   - ファイル:   rename() で専有してから読み、unlink() する
 */

/** 表示用の種別。暗号化されないヒントで、信頼できる種別は暗号文の内部（認証済みタグ）にある。 */
export type PayloadType = 'text' | 'file';

export interface StoredPayload {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  type: PayloadType;
}

/** 暗号文の中身に触れずに公開してよい情報だけ。暗号文・IV は含めない。 */
export interface PayloadMeta {
  type: PayloadType;
  /** 暗号文のバイト数。 */
  size: number;
  /** 有効期限（epoch ms）。 */
  expiresAt: number;
}

export interface PayloadStore {
  /** 保存する。有効期限は ttlSeconds 後（時刻の基準は保存側が持つ）。既存 ID は上書きしない。 */
  put(id: string, payload: StoredPayload, ttlSeconds: number): Promise<{ expiresAt: number }>;
  /**
   * メタ情報だけを返す。削除も有効期限の変更もしない（副作用なし）。
   * 存在しない・期限切れ・取得済みはすべて null（区別しない）。
   */
  stat(id: string): Promise<PayloadMeta | null>;
  /**
   * 取得と削除を不可分に行う。存在しない・期限切れ・取得済みはすべて null（区別しない）。
   * 戻り値を返した時点で、ストアからは既に完全に削除されている。
   */
  take(id: string): Promise<StoredPayload | null>;
}

/** 保存容量の上限に達している。 */
export class StoreFullError extends Error {
  constructor() {
    super('Payload store is full.');
    this.name = 'StoreFullError';
  }
}

export interface InMemoryStoreOptions {
  /** 現在時刻（epoch ms）。テストで差し替える。 */
  now?: () => number;
  /** 暗号文 + IV の合計バイト数の上限。超える保存は StoreFullError。 */
  maxTotalBytes?: number;
  /** 期限切れの掃除間隔（ms）。0 で無効。 */
  sweepIntervalMs?: number;
}

const DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const DEFAULT_SWEEP_INTERVAL_MS = 30_000;

interface Entry {
  payload: StoredPayload;
  expiresAt: number;
  bytes: number;
}

/**
 * プロセス内メモリに保存する実装（MVP 用）。再起動すると未読の暗号文はすべて失われる。
 */
export class InMemoryPayloadStore implements PayloadStore {
  readonly #entries = new Map<string, Entry>();
  readonly #now: () => number;
  readonly #maxTotalBytes: number;
  #totalBytes = 0;
  #sweeper: ReturnType<typeof setInterval> | undefined;

  constructor(options: InMemoryStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;

    const sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    if (sweepIntervalMs > 0) {
      this.#sweeper = setInterval(() => this.purgeExpired(), sweepIntervalMs);
      this.#sweeper.unref(); // 掃除タイマーがプロセスの終了を妨げないように
    }
  }

  async put(id: string, payload: StoredPayload, ttlSeconds: number): Promise<{ expiresAt: number }> {
    if (this.#entries.has(id)) {
      throw new Error('Payload id collision.'); // 128bit の乱数 ID では起きない。黙って上書きするよりも失敗させる。
    }

    const bytes = payload.ciphertext.byteLength + payload.iv.byteLength;
    if (this.#totalBytes + bytes > this.#maxTotalBytes) {
      this.purgeExpired(); // 期限切れで空きが作れるなら先に回収する
      if (this.#totalBytes + bytes > this.#maxTotalBytes) throw new StoreFullError();
    }

    const expiresAt = this.#now() + ttlSeconds * 1000;
    this.#entries.set(id, { payload, expiresAt, bytes });
    this.#totalBytes += bytes;
    return { expiresAt };
  }

  async stat(id: string): Promise<PayloadMeta | null> {
    // 読み取り専用。期限切れでもここでは削除しない（削除は take / purgeExpired / put の役目）。
    const entry = this.#entries.get(id);
    if (entry === undefined || entry.expiresAt <= this.#now()) return null;
    return { type: entry.payload.type, size: entry.payload.ciphertext.byteLength, expiresAt: entry.expiresAt };
  }

  async take(id: string): Promise<StoredPayload | null> {
    const entry = this.#entries.get(id);
    if (entry === undefined) return null;

    // 先に削除する。get → delete の間に await を挟まないので、並行する take() が同じエントリを
    // 観測することは起こり得ない（＝どれだけ同時にアクセスされても成功するのは 1 回だけ）。
    this.#entries.delete(id);
    this.#totalBytes -= entry.bytes;

    return entry.expiresAt > this.#now() ? entry.payload : null;
  }

  /** 期限切れを削除し、削除した件数を返す。取得されない暗号文をメモリに残さないための掃除。 */
  purgeExpired(): number {
    const now = this.#now();
    let purged = 0;
    for (const [id, entry] of this.#entries) {
      if (entry.expiresAt <= now) {
        this.#entries.delete(id);
        this.#totalBytes -= entry.bytes;
        purged++;
      }
    }
    return purged;
  }

  /** 保持している件数（診断用。内容は公開しない）。 */
  get size(): number {
    return this.#entries.size;
  }

  get totalBytes(): number {
    return this.#totalBytes;
  }

  /** 掃除タイマーを止め、保持している暗号文をすべて破棄する。 */
  close(): void {
    clearInterval(this.#sweeper);
    this.#sweeper = undefined;
    this.#entries.clear();
    this.#totalBytes = 0;
  }
}
