/**
 * BPC Canonical Payload Serialization
 *
 * Security hardening (IL4-7 / BPC-05 fix):
 *  - Uses Object.create(null) so that assigning to the '__proto__' key creates
 *    an own property instead of mutating the prototype chain.
 *  - Explicitly rejects '__proto__', 'constructor', and 'prototype' keys.
 *  - Enforces scalar-only values (string | number | boolean | null) to prevent
 *    nested-object injection.
 */

/** Keys that must never appear in a BPC canonical payload. */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

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
