export function b64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function b64urlDecode(str: string): ArrayBuffer {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - padded.length % 4) % 4;
  const bin = atob(padded + '='.repeat(padLen));
  return new Uint8Array([...bin].map(c => c.charCodeAt(0))).buffer;
}
