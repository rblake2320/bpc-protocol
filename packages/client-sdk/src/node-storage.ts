/**
 * Node.js file-based encrypted key storage for BPC pairs.
 * Keys are stored at ~/.bpc/keys/<pairId>.json
 * Encrypted with AES-256-GCM using PBKDF2(hostname + username, salt).
 */

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync, readdirSync } from 'node:fs';
import { homedir, hostname, userInfo } from 'node:os';
import { join } from 'node:path';

const KEY_DIR = join(homedir(), '.bpc', 'keys');
const ALGORITHM = 'aes-256-gcm';
const PBKDF2_ITERATIONS = 100_000;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function deriveKey(salt: Buffer): Buffer {
  const passphrase = `${hostname()}:${userInfo().username}:bpc-keys`;
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, 32, 'sha256');
}

function ensureDir(): void {
  if (!existsSync(KEY_DIR)) mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
}

function filePath(id: string): string {
  // Sanitize id to prevent path traversal
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, '_');
  return join(KEY_DIR, `${safe}.json`);
}

function encrypt(plaintext: string): string {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const key = deriveKey(salt);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
  });
}

function decrypt(ciphertext: string): string {
  const { salt, iv, tag, data } = JSON.parse(ciphertext) as {
    salt: string; iv: string; tag: string; data: string;
  };
  const key = deriveKey(Buffer.from(salt, 'hex'));
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return decipher.update(Buffer.from(data, 'hex')) + decipher.final('utf8');
}

export async function saveKeypairToFile(id: string, data: Record<string, unknown>): Promise<void> {
  ensureDir();
  const plaintext = JSON.stringify({ id, ...data });
  writeFileSync(filePath(id), encrypt(plaintext), { mode: 0o600 });
}

export async function loadKeypairFromFile(id: string): Promise<Record<string, unknown> | null> {
  const fp = filePath(id);
  if (!existsSync(fp)) return null;
  try {
    const ciphertext = readFileSync(fp, 'utf8');
    return JSON.parse(decrypt(ciphertext)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export async function loadAllFromFile(): Promise<Record<string, unknown>[]> {
  ensureDir();
  const results: Record<string, unknown>[] = [];
  for (const file of readdirSync(KEY_DIR)) {
    if (!file.endsWith('.json')) continue;
    try {
      const ciphertext = readFileSync(join(KEY_DIR, file), 'utf8');
      results.push(JSON.parse(decrypt(ciphertext)) as Record<string, unknown>);
    } catch {
      // skip corrupted files
    }
  }
  return results;
}

export async function deleteKeypairFromFile(id: string): Promise<void> {
  const fp = filePath(id);
  if (existsSync(fp)) unlinkSync(fp);
}
