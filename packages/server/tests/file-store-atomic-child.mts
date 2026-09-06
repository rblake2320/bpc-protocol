import { FileNonceBackend } from '../src/file-store.ts';
const [path, nonce] = process.argv.slice(2);
if (!path || !nonce) throw new Error('usage: file-store-atomic-child.mts <path> <nonce>');
try { process.stdout.write(JSON.stringify({ replay: await new FileNonceBackend(path).checkAndConsume(nonce, 60_000) }) + '\n'); }
catch (error) { process.stdout.write(JSON.stringify({ error: error instanceof Error ? error.message.split(':')[0] : 'UNKNOWN' }) + '\n'); }
