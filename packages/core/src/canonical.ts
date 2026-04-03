export function canonicalize(obj: Record<string, unknown>): string {
  // BPC canonical payloads are always flat — sort keys for determinism
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = obj[key];
  }
  return JSON.stringify(sorted);
}
