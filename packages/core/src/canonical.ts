/**
 * BPC Canonical Payload Serialization
 *
 * Security hardening (IL4-7 / BPC-05 fix + BPC-07 fix):
 *  - Uses Object.create(null) so that assigning to the '__proto__' key creates
 *    an own property instead of mutating the prototype chain.
 *  - Explicitly rejects '__proto__', 'constructor', 'prototype', and all
 *    legacy accessor mutation keys to prevent any prototype pollution vector.
 *  - Enforces scalar-only values (string | number | boolean | null) to prevent
 *    nested-object injection.
 *  - BPC-07: Added assertNoForbiddenKeys() for pre-parse key scanning on raw
 *    JSON strings, preventing prototype pollution before JSON.parse() runs.
 */

/** Keys that must never appear in a BPC canonical payload. */
export const FORBIDDEN_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
]);

/**
 * Scan a raw JSON string for forbidden keys before parsing.
 * Belt-and-suspenders guard against prototype pollution that operates at the
 * string level, before JSON.parse() runs.
 *
 * BPC-07 FIX: Prevents constructor/prototype injection through the raw
 * signedData path where canonicalize() is not called first.
 *
 * @throws {TypeError} if any forbidden key pattern is detected.
 */
export function assertNoForbiddenKeys(rawJson: string): void {
  for (const key of FORBIDDEN_KEYS) {
    // Match the key as a JSON string key — simple indexOf, no ReDoS risk.
    if (rawJson.includes(`"${key}"`)) {
      throw new TypeError(`BPC: forbidden key "${key}" detected in payload`);
    }
  }
}

/**
 * Produce a deterministic, tamper-evident JSON string from a flat payload object.
 * @throws {TypeError} on forbidden keys or nested-object values.
 */
export function canonicalize(obj: Record<string, unknown>): string {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new TypeError('BPC canonicalize: input must be a plain object');
  }

  // Null-prototype accumulator — belt-and-suspenders against __proto__ mutation.
  const sorted: Record<string, unknown> = Object.create(null);

  for (const key of Object.keys(obj).sort()) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new TypeError(`BPC canonicalize: forbidden key "${key}" in payload`);
    }
    const value = (obj as Record<string, unknown>)[key];
    if (value !== null && typeof value === 'object') {
      throw new TypeError(`BPC canonicalize: nested object at key "${key}" is not allowed`);
    }
    sorted[key] = value;
  }

  return JSON.stringify(sorted);
}
