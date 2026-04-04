/**
 * Storage factory -- returns browser (IndexedDB) or Node.js (encrypted file) backend
 * based on the current runtime environment.
 */

// Re-export IDB functions for direct use
export { saveKeypair, loadKeypair, loadAll, deleteKeypair } from './idb-storage.js';

export interface KeyStorage {
  save(id: string, data: Record<string, unknown>): Promise<void>;
  load(id: string): Promise<Record<string, unknown> | null>;
  loadAll(): Promise<Record<string, unknown>[]>;
  delete(id: string): Promise<void>;
}

/**
 * Create a key storage instance appropriate for the current runtime.
 * In a browser: uses IndexedDB.
 * In Node.js: uses AES-256-GCM encrypted files at ~/.bpc/keys/
 */
export function createStorage(): KeyStorage {
  const isBrowser = typeof window !== 'undefined' && typeof indexedDB !== 'undefined';

  if (isBrowser) {
    return {
      async save(id, data) { const m = await import('./idb-storage.js'); return m.saveKeypair(id, data); },
      async load(id) { const m = await import('./idb-storage.js'); return m.loadKeypair(id); },
      async loadAll() { const m = await import('./idb-storage.js'); return m.loadAll(); },
      async delete(id) { const m = await import('./idb-storage.js'); return m.deleteKeypair(id); },
    };
  } else {
    return {
      async save(id, data) { const m = await import('./node-storage.js'); return m.saveKeypairToFile(id, data); },
      async load(id) { const m = await import('./node-storage.js'); return m.loadKeypairFromFile(id); },
      async loadAll() { const m = await import('./node-storage.js'); return m.loadAllFromFile(); },
      async delete(id) { const m = await import('./node-storage.js'); return m.deleteKeypairFromFile(id); },
    };
  }
}
