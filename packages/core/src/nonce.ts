export function generateNonce(): string {
  return crypto.randomUUID();
}

export function generateId(prefix: string): string {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return prefix + '_' + [...arr].map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
}

export class NonceStore {
  private seen = new Map<string, number>(); // nonce -> expiry timestamp ms

  constructor(private windowMs: number = 120_000) {}

  has(nonce: string): boolean {
    this.evict();
    return this.seen.has(nonce);
  }

  add(nonce: string): void {
    this.seen.set(nonce, Date.now() + this.windowMs);
  }

  private evict(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.seen) {
      if (expiry < now) this.seen.delete(nonce);
    }
  }

  get size(): number {
    this.evict();
    return this.seen.size;
  }
}
