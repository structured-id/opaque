/**
 * Where the client keeps what is costly to derive again: the commitment key's
 * points and the column commitments of each circuit shape. Both are public
 * and deterministic (anyone derives the same bytes from the circuit), so the
 * store needs no secrecy; a lost or damaged entry is derived again. IndexedDB
 * where the platform has it (a page or a worker), memory otherwise.
 */

/** One stored value and when it was last used (ms since the epoch). */
export interface KeyStoreEntry {
  name: string;
  bytes: Uint8Array;
  usedAt: number;
}

export interface KeyStore {
  get(name: string): Promise<Uint8Array | null>;
  put(name: string, bytes: Uint8Array): Promise<void>;
  /** Mark `name` as used now, so pruning keeps it. */
  touch(name: string): Promise<void>;
  delete(name: string): Promise<void>;
  /** Every entry's name and last use. */
  list(): Promise<{ name: string; usedAt: number }[]>;
}

/** Entries in this object only: lost with it. */
export class MemoryKeyStore implements KeyStore {
  private readonly entries = new Map<string, KeyStoreEntry>();

  async get(name: string): Promise<Uint8Array | null> {
    return this.entries.get(name)?.bytes ?? null;
  }

  async put(name: string, bytes: Uint8Array): Promise<void> {
    this.entries.set(name, { name, bytes, usedAt: Date.now() });
  }

  async touch(name: string): Promise<void> {
    const e = this.entries.get(name);
    if (e) e.usedAt = Date.now();
  }

  async delete(name: string): Promise<void> {
    this.entries.delete(name);
  }

  async list(): Promise<{ name: string; usedAt: number }[]> {
    return [...this.entries.values()].map(({ name, usedAt }) => ({
      name,
      usedAt,
    }));
  }
}

const DB_NAME = "structured-id-zkpp";
const STORE = "keys";

const request = <T>(r: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB request failed"));
  });

/** One object store of entries keyed by name. */
export class IndexedDbKeyStore implements KeyStore {
  private constructor(private readonly db: IDBDatabase) {}

  /** Open (creating if needed) the database; rejects where IndexedDB cannot be used. */
  static async open(
    factory: IDBFactory = indexedDB,
  ): Promise<IndexedDbKeyStore> {
    const open = factory.open(DB_NAME, 1);
    open.onupgradeneeded = () =>
      open.result.createObjectStore(STORE, { keyPath: "name" });
    return new IndexedDbKeyStore(await request(open));
  }

  private store(mode: IDBTransactionMode): IDBObjectStore {
    return this.db.transaction(STORE, mode).objectStore(STORE);
  }

  async get(name: string): Promise<Uint8Array | null> {
    const e = (await request(this.store("readonly").get(name))) as
      KeyStoreEntry | undefined;
    return e?.bytes ?? null;
  }

  async put(name: string, bytes: Uint8Array): Promise<void> {
    await request(
      this.store("readwrite").put({ name, bytes, usedAt: Date.now() }),
    );
  }

  async touch(name: string): Promise<void> {
    const store = this.store("readwrite");
    const e = (await request(store.get(name))) as KeyStoreEntry | undefined;
    if (e) await request(store.put({ ...e, usedAt: Date.now() }));
  }

  async delete(name: string): Promise<void> {
    await request(this.store("readwrite").delete(name));
  }

  async list(): Promise<{ name: string; usedAt: number }[]> {
    const all = (await request(
      this.store("readonly").getAll(),
    )) as KeyStoreEntry[];
    return all.map(({ name, usedAt }) => ({ name, usedAt }));
  }
}

/** IndexedDB when this platform opens it, memory otherwise. */
export async function openKeyStore(): Promise<KeyStore> {
  if (typeof indexedDB === "undefined") return new MemoryKeyStore();
  try {
    return await IndexedDbKeyStore.open();
  } catch {
    // Blocked storage (a private window, a denied origin): the key is derived
    // again on each visit, which only costs time.
    return new MemoryKeyStore();
  }
}
