/**
 * 暗号文ストア。
 *
 * サーバーが保持してよいのは「暗号文・IV・有効期限・表示用の種別ヒント・鍵確認値（任意）」だけ。
 * 平文も鍵そのものも、このプロセスには存在しない
 * （鍵確認値は鍵から一方向に導出した 32bit のヒントで、鍵は復元できない。crypto.ts 参照）。
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
import { createHash, timingSafeEqual } from 'node:crypto';

/** 表示用の種別。暗号化されないヒントで、信頼できる種別は暗号文の内部（認証済みタグ）にある。 */
export type PayloadType = 'text' | 'file';

export interface StoredPayload {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  type: PayloadType;
  /**
   * 鍵確認値（16進小文字 8 桁、任意）。共有リンクのコピペミス・途中欠損を受信側で検出するためのヒントで、
   * 暗号強度には寄与しない（クライアントが鍵から一方向に導出した値。詳細は crypto.ts の generateKeyCheckTag）。
   * 省略された場合（旧データ・未対応の送信側）は保存しない。
   */
  keyCheck?: string;
  /**
   * 消費用の秘密鍵（consumeSecret）の SHA-256（32 バイト、生のダイジェスト）。必須。
   * take() は、提示された consumeSecret をこの値と timingSafeEqual で比較し、一致したときだけ実行する
   * （ID だけを知る第三者が、鍵を知らなくてもデータを破棄できてしまう問題への対策）。
   * meta 応答や PayloadMeta には一切含めない（このフィールドは take() の内部でしか参照しない）。
   */
  consumeVerifier: Uint8Array;
}

/** 暗号文の中身に触れずに公開してよい情報だけ。暗号文・IV は含めない。 */
export interface PayloadMeta {
  type: PayloadType;
  /** 暗号文のバイト数。 */
  size: number;
  /** 有効期限（epoch ms）。 */
  expiresAt: number;
  /** 鍵確認値（任意）。StoredPayload.keyCheck 参照。 */
  keyCheck?: string;
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
   * 本文を読み始める前に、これから受信するバイト数分の容量を確保できるか確認し、確保できるなら
   * 予約する（件数枠も 1 つ消費する）。true を返した場合、呼び出し側は読み取り終了後に必ず
   * release() で解放すること（put() する場合も、その直前に release() してから put() する）。
   *
   * バイト数・件数のどちらかが上限に達していて確保できない場合は false を返し、何も変更しない。
   * 本文を読み始める前に呼ぶことで、どのみち入りきらない本文をバッファリングしてしまう無駄
   * （＝同時多数リクエストによるメモリ枯渇 DoS）を避けるためのもの。
   */
  reserve(bytes: number): boolean;
  /** reserve() で確保した分を解放する。reserve() が false を返した場合は呼ばないこと。 */
  release(bytes: number): void;
  /**
   * 取得と削除を不可分に行う。消費用の秘密鍵（consumeSecret の生バイト列）が一致した場合だけ実行する。
   * 存在しない・期限切れ・取得済み・秘密鍵が一致しないのいずれも null（区別しない）。
   * 戻り値を返した時点で、ストアからは既に完全に削除されている。
   */
  take(id: string, consumeSecret: Uint8Array): Promise<StoredPayload | null>;
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
  /**
   * 保持できる件数の上限。超える保存は StoreFullError（バイト数が十分でも、大量の小さな暗号文で
   * エントリ数そのものを枯渇させる DoS を防ぐ）。
   */
  maxEntries?: number;
  /** 期限切れの掃除間隔（ms）。0 で無効。 */
  sweepIntervalMs?: number;
}

const DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024;
/** 既定 10 万件。平均 1 件あたり数 KB 程度までの利用を想定した、素朴だが具体的な上限。 */
const DEFAULT_MAX_ENTRIES = 100_000;
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
  readonly #maxEntries: number;
  #totalBytes = 0;
  /** reserve() で確保済みだが、まだ put() で確定（または release() で解放）されていない分。 */
  #reservedBytes = 0;
  #reservedCount = 0;
  #sweeper: ReturnType<typeof setInterval> | undefined;

  constructor(options: InMemoryStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;

    const sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
    if (sweepIntervalMs > 0) {
      this.#sweeper = setInterval(() => this.purgeExpired(), sweepIntervalMs);
      this.#sweeper.unref(); // 掃除タイマーがプロセスの終了を妨げないように
    }
  }

  /** バイト数・件数のどちらも、確定済み（#totalBytes・エントリ数）+ 予約済み（reserve 中）で判定する。 */
  #fits(extraBytes: number, extraEntries: number): boolean {
    return (
      this.#totalBytes + this.#reservedBytes + extraBytes <= this.#maxTotalBytes &&
      this.#entries.size + this.#reservedCount + extraEntries <= this.#maxEntries
    );
  }

  reserve(bytes: number): boolean {
    if (!this.#fits(bytes, 1)) {
      this.purgeExpired(); // 期限切れで空きが作れるなら先に回収する
      if (!this.#fits(bytes, 1)) return false;
    }
    this.#reservedBytes += bytes;
    this.#reservedCount += 1;
    return true;
  }

  release(bytes: number): void {
    this.#reservedBytes = Math.max(0, this.#reservedBytes - bytes);
    this.#reservedCount = Math.max(0, this.#reservedCount - 1);
  }

  async put(id: string, payload: StoredPayload, ttlSeconds: number): Promise<{ expiresAt: number }> {
    if (this.#entries.has(id)) {
      throw new Error('Payload id collision.'); // 128bit の乱数 ID では起きない。黙って上書きするよりも失敗させる。
    }

    // reserve() されていたかどうかに関わらず、put() 自身も必ず確定分（reserve 中は含まない）だけで
    // 独立に検査する。reserve → release → put という順で呼ぶ限り、二重に数えられることはない
    // （release で reserve 分を先に手放してから put するため）。
    const bytes = payload.ciphertext.byteLength + payload.iv.byteLength;
    const fitsCommitted = (): boolean => this.#totalBytes + bytes <= this.#maxTotalBytes && this.#entries.size < this.#maxEntries;
    if (!fitsCommitted()) {
      this.purgeExpired(); // 期限切れで空きが作れるなら先に回収する
      if (!fitsCommitted()) throw new StoreFullError();
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
    const { type, ciphertext, keyCheck } = entry.payload;
    // keyCheck が無い保存分は、戻り値にもキー自体を持たせない（後方互換を型のレベルでも保つ）。
    return keyCheck === undefined
      ? { type, size: ciphertext.byteLength, expiresAt: entry.expiresAt }
      : { type, size: ciphertext.byteLength, expiresAt: entry.expiresAt, keyCheck };
  }

  async take(id: string, consumeSecret: Uint8Array): Promise<StoredPayload | null> {
    const entry = this.#entries.get(id);
    if (entry === undefined) return null;

    // 秘密鍵の検証を、削除の「前」に行う。一致しなければエントリには一切手を付けない
    // （ID だけを知る第三者が、鍵（consumeSecret）を知らずにデータを破棄できてしまうことを防ぐ）。
    // 期限切れのエントリに対しても同じ検証を行ってから判定することで、「期限切れ」と「秘密鍵の
    // 不一致」の応答時間の差を小さくする。比較は crypto.timingSafeEqual（タイミング攻撃対策）。
    const presented = createHash('sha256').update(consumeSecret).digest();
    const expected = entry.payload.consumeVerifier;
    const authorized = expected.byteLength === presented.byteLength && timingSafeEqual(expected, presented);
    if (!authorized) return null;

    // 先に削除する。get → 検証 → delete の間に await を挟まないので、並行する take() が同じエントリを
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
