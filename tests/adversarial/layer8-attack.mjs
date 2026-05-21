/**
 * Layer 8 Active Defense — Adversarial Verification Suite
 *
 * This suite attempts to BREAK the Layer 8 deception mechanisms:
 * 1. Ghost Pairs — can we detect we hit a canary? Can we bypass it?
 * 2. Shadow Mode — can we detect we're in shadow mode? Can we escape it?
 * 3. Cryptographic Tarpit — can we bypass the delay? Can we detect it?
 * 4. State Machine — can we force incorrect state transitions?
 * 5. Scope Isolation — does shadow state bleed to other IPs?
 *
 * A passing test means the deception mechanism WORKS (attacker is fooled/trapped).
 * A failing test means the mechanism has a gap that needs fixing.
 */

import { createHmac, createHash, generateKeyPairSync, randomUUID, timingSafeEqual } from 'node:crypto';
import { subtle } from 'node:crypto';

// ─── Minimal in-memory implementations of BPC+Layer8 ─────────────────────────

class InMemoryStore {
  constructor() {
    this.pairs = new Map();
    this.pending = new Map();
    this.counters = new Map();
    this.nonces = new Set();
  }
  async get(id) { return this.pairs.get(id); }
  async set(pair) { this.pairs.set(pair.id, pair); }
  async list() { return [...this.pairs.values()]; }
  async setPending(token, reg, ts) { this.pending.set(token, { registration: reg, ts }); }
  async getPending(token) { return this.pending.get(token); }
  async deletePending(token) { this.pending.delete(token); }
  async listPending() { return [...this.pending.values()]; }
  async increment(key, windowMs) {
    const now = Date.now();
    const entry = this.counters.get(key) || { count: 0, windowStart: now };
    if (now - entry.windowStart > windowMs) {
      entry.count = 1; entry.windowStart = now;
    } else {
      entry.count++;
    }
    this.counters.set(key, entry);
    return entry.count;
  }
  async get_counter(key) { return (this.counters.get(key) || { count: 0 }).count; }
}
// Alias for anomaly store interface
InMemoryStore.prototype.get = async function(key) {
  // Dual-use: pair store get AND anomaly counter get
  if (this.pairs.has(key)) return this.pairs.get(key);
  return (this.counters.get(key) || { count: 0 }).count;
};

class AnomalyStore {
  constructor() { this.counters = new Map(); }
  async increment(key, windowMs) {
    const now = Date.now();
    const entry = this.counters.get(key) || { count: 0, windowStart: now };
    if (now - entry.windowStart > windowMs) {
      entry.count = 1; entry.windowStart = now;
    } else {
      entry.count++;
    }
    this.counters.set(key, entry);
    return entry.count;
  }
  async get(key) { return (this.counters.get(key) || { count: 0 }).count; }
}

class NonceStore {
  constructor() { this.seen = new Set(); }
  async checkAndConsume(nonce) {
    if (this.seen.has(nonce)) return true;
    this.seen.add(nonce);
    return false;
  }
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function hmacRaw(secret, data) {
  return createHmac('sha256', Buffer.from(secret, 'hex')).update(data).digest('base64url');
}

function hashSecret(secret) {
  return createHash('sha256').update('bpc:' + secret).digest('base64url');
}

async function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  const privJwk = privateKey.export({ format: 'jwk' });
  return { pubJwk, privJwk };
}

async function signPayload(privJwk, payload) {
  const key = await subtle.importKey('jwk', privJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const canonical = JSON.stringify(Object.keys(payload).sort().reduce((acc, k) => { acc[k] = payload[k]; return acc; }, {}));
  const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(canonical));
  return Buffer.from(sig).toString('base64url');
}

async function importPubKey(pubJwk) {
  return subtle.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

async function verifyPayload(pubJwk, payload, sig) {
  const key = await importPubKey(pubJwk);
  const canonical = JSON.stringify(Object.keys(payload).sort().reduce((acc, k) => { acc[k] = payload[k]; return acc; }, {}));
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(sig, 'base64url'), Buffer.from(canonical));
}

function computeSecretHmac(secretHash, nonce, timestamp) {
  return createHmac('sha256', Buffer.from(secretHash, 'base64url'))
    .update(`${nonce}:${timestamp}`)
    .digest('base64url');
}

// ─── Layer 8 State Machine (mirrors the real implementation) ─────────────────

const TARPIT_DELAY_MS = { clean: 0, suspicious: 500, shadow: 2000, attack: 0 };
const SUSPICIOUS_THRESHOLD = 3;
const SHADOW_THRESHOLD = 7;
const SHADOW_PERSIST_MS = 86_400_000;

class AnomalyEngine {
  constructor(store) {
    this.store = store;
    this.shadowState = new Map();
    this.tarpitState = new Map();
  }
  async recordRequest(pairId) {
    await this.store.increment('global:total', 3_600_000);
    if (pairId) await this.store.increment(`pair:${pairId}:total`, 3_600_000);
  }
  async recordDenied(pairId) {
    await this.store.increment('global:denied', 3_600_000);
    if (pairId) await this.store.increment(`pair:${pairId}:denied`, 3_600_000);
  }
  async recordUnknownPair() { await this.store.increment('global:unknown_pair', 3_600_000); }
  async recordSigFailure(pairId) {
    await this.store.increment('global:sig_fail', 3_600_000);
    if (pairId) await this.store.increment(`pair:${pairId}:sig_fail`, 3_600_000);
  }
  async recordSigFailureForIp(pairId, sourceIp) {
    await this.store.increment(`ip:${sourceIp}:pair:${pairId}:sig_fail`, 3_600_000);
    await this.recordSigFailure(pairId);
  }
  async recordReplay(pairId) { await this.store.increment('global:replay', 3_600_000); }
  async recordExpiredTimestamp(pairId) { await this.store.increment('global:expired_ts', 3_600_000); }
  async getVerdict(pairId, sourceIp) {
    const shadowKey = `${pairId}:${sourceIp}`;
    if (this.shadowState.has(shadowKey)) return 'shadow';
    const ipFails = await this.store.get(`ip:${sourceIp}:pair:${pairId}:sig_fail`);
    if (ipFails >= SHADOW_THRESHOLD) {
      await this.enterShadowState(pairId, sourceIp, `auto:${ipFails}`);
      return 'shadow';
    }
    if (ipFails >= SUSPICIOUS_THRESHOLD) return 'suspicious';
    return 'clean';
  }
  async enterShadowState(pairId, sourceIp, reason) {
    this.shadowState.set(`${pairId}:${sourceIp}`, { enteredAt: Date.now(), sourceIp, pairId, reason });
    this.tarpitState.set(sourceIp, { verdict: 'shadow', since: Date.now() });
  }
  clearShadowState(pairId, sourceIp) {
    this.shadowState.delete(`${pairId}:${sourceIp}`);
    this.tarpitState.delete(sourceIp);
  }
  isInShadowState(pairId, sourceIp) { return this.shadowState.has(`${pairId}:${sourceIp}`); }
  listShadowState() { return [...this.shadowState.values()]; }
  async applyTarpit(sourceIp, verdict) {
    const delayMs = TARPIT_DELAY_MS[verdict] ?? 0;
    if (delayMs > 0) {
      this.tarpitState.set(sourceIp, { verdict, since: Date.now() });
      await new Promise(r => setTimeout(r, delayMs));
    }
    return delayMs;
  }
  getTarpitState(sourceIp) { return this.tarpitState.get(sourceIp); }
  async threatScore() {
    const total = await this.store.get('global:total');
    if (total === 0) return 0;
    const sigFail = await this.store.get('global:sig_fail');
    return Math.round(Math.min(sigFail / total, 1) * 100);
  }
}

function generateShadowToken() {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ sub: randomBytes(16).toString('hex'), shadowToken: true })).toString('base64url');
  const sig = randomBytes(32).toString('base64url');
  return `${header}.${payload}.${sig}`;
}

// ─── Registry ─────────────────────────────────────────────────────────────────

class PairRegistry {
  constructor(store) {
    this.store = store;
    this.ipFailureTracker = new Map();
    this.IP_FAILURE_WINDOW_MS = 5 * 60 * 1000;
    this.lockoutCount = 10;
  }
  async register(id, pubJwk, secretHash, options = {}) {
    const pair = {
      id, name: options.name ?? id, scope: options.scope ?? 'read',
      mode: options.mode ?? 'production', secretHash, pubJwk,
      status: 'active', created: Date.now(), lastActive: null,
      requests: 0, failedSigs: 0,
      kind: options.kind ?? 'legitimate',
      canaryClass: options.canaryClass,
    };
    await this.store.set(pair);
    return pair;
  }
  async get(pairId) { return this.store.get(pairId); }
  async recordActivity(pairId, success, ip) {
    const pair = await this.store.get(pairId);
    if (!pair) return;
    pair.requests++;
    pair.lastActive = Date.now();
    if (success) {
      pair.failedSigs = 0;
    } else if (ip) {
      const ipKey = `${pairId}:${ip}`;
      const now = Date.now();
      const tracker = this.ipFailureTracker.get(ipKey);
      if (!tracker || now - tracker.windowStart > this.IP_FAILURE_WINDOW_MS) {
        this.ipFailureTracker.set(ipKey, { count: 1, windowStart: now });
      } else { tracker.count++; }
      const ipFailures = this.ipFailureTracker.get(ipKey).count;
      pair.failedSigs = ipFailures;
      if (ipFailures >= this.lockoutCount && pair.status === 'active') pair.status = 'locked';
    } else {
      pair.failedSigs++;
      if (pair.failedSigs >= this.lockoutCount && pair.status === 'active') pair.status = 'locked';
    }
    await this.store.set(pair);
  }
}

// ─── Middleware (mirrors real implementation) ─────────────────────────────────

async function verifyBPCRequest(req, registry, nonceStore, anomaly, config = {}) {
  const pairId = req.pairId ?? undefined;
  const sourceIp = req.ip ?? 'unknown';
  const shadowEnabled = config.enableShadowMode !== false;
  const tarpitEnabled = config.enableTarpit !== false;

  await anomaly.recordRequest(pairId);

  async function deny(error, doSigFail = false) {
    await anomaly.recordDenied(pairId);
    if (doSigFail) {
      await anomaly.recordSigFailure(pairId);
      if (pairId) await anomaly.recordSigFailureForIp(pairId, sourceIp);
    }
    if (pairId && doSigFail) await registry.recordActivity(pairId, false, sourceIp);
    return { ok: false, error };
  }

  // Layer 8: Shadow state check (before all other checks)
  if (shadowEnabled && pairId && anomaly.isInShadowState(pairId, sourceIp)) {
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
    return { ok: true, pairId, shadow: true, tarpitDelayMs: delayMs };
  }

  if (!req.pairId || !req.signedData || !req.signature) return deny('missing_headers');

  const pair = await registry.get(req.pairId);
  if (!pair) { await anomaly.recordUnknownPair(); return deny('unknown_pair'); }

  // Step 5: Pair status
  if (pair.status === 'revoked') return deny('pair_revoked');
  if (pair.status === 'locked') {
    if (shadowEnabled) {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'pair_locked');
      const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
      return { ok: true, pairId: req.pairId, shadow: true, tarpitDelayMs: delayMs };
    }
    return deny('pair_locked');
  }
  if (pair.status !== 'active') return deny('pair_revoked');

  // Layer 8: Tarpit for suspicious IPs
  let tarpitDelayApplied = 0;
  if (tarpitEnabled && sourceIp !== 'unknown') {
    const verdict = await anomaly.getVerdict(req.pairId, sourceIp);
    if (verdict === 'suspicious') {
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'suspicious');
    } else if (verdict === 'shadow') {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'verdict_shadow');
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'shadow');
      return { ok: true, pairId: req.pairId, shadow: true, tarpitDelayMs: tarpitDelayApplied };
    } else if (verdict === 'attack') {
      return deny('rate_limit_exceeded');
    }
  }

  // Decode payload
  let payload;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = Buffer.from(padded + '='.repeat(padLen), 'base64').toString('utf8');
    payload = JSON.parse(json);
  } catch { return deny('invalid_signed_data', true); }

  const rawNonce = payload['nonce'];
  const rawTimestamp = payload['timestamp'];
  if (typeof rawNonce !== 'string') return deny('invalid_signed_data', true);
  if (typeof rawTimestamp !== 'number') return deny('invalid_signed_data', true);

  // HMAC check
  const secretHmac = payload['secret_hmac'];
  if (!secretHmac) return deny('missing_secret_hmac', true);
  const expectedHmac = computeSecretHmac(pair.secretHash, rawNonce, rawTimestamp);
  const hmacValid = timingSafeEqual(Buffer.from(secretHmac), Buffer.from(expectedHmac));
  if (!hmacValid) return deny('invalid_secret_hmac', true);

  // Timestamp
  const now = Date.now();
  if (Math.abs(now - rawTimestamp) > (config.sigWindowMs ?? 60_000)) {
    await anomaly.recordExpiredTimestamp(req.pairId);
    return deny('timestamp_expired', true);
  }

  // Nonce
  if (await nonceStore.checkAndConsume(rawNonce)) {
    await anomaly.recordReplay(req.pairId);
    return deny('replay_detected');
  }

  // Method/path
  if (payload['method'] !== req.method || payload['path'] !== req.path) {
    return deny('method_path_mismatch', true);
  }

  // Signature
  let valid = false;
  try { valid = await verifyPayload(pair.pubJwk, payload, req.signature); } catch { valid = false; }
  if (!valid) return deny('invalid_signature', true);

  // Layer 8: Ghost Pair trap (after full verification)
  if (pair.kind === 'ghost') {
    await anomaly.enterShadowState(req.pairId, sourceIp, `ghost:${pair.canaryClass}`);
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
    return { ok: true, pairId: req.pairId, shadow: true, ghostAlert: true, canaryClass: pair.canaryClass, tarpitDelayMs: delayMs };
  }

  await registry.recordActivity(req.pairId, true);
  return { ok: true, pairId: req.pairId, pair, tarpitDelayMs: tarpitDelayApplied > 0 ? tarpitDelayApplied : undefined };
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

async function makeValidRequest(pairId, privJwk, secretHash, method = 'GET', path = '/api/test') {
  const nonce = randomUUID();
  const timestamp = Date.now();
  const secretHmac = computeSecretHmac(secretHash, nonce, timestamp);
  const payload = { method, path, nonce, timestamp, secret_hmac: secretHmac };
  const signature = await signPayload(privJwk, payload);
  const signedData = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return { pairId, signedData, signature, method, path, version: '1.0', bodyHash: null };
}

// ─── Test runner ──────────────────────────────────────────────────────────────

const results = [];
let passed = 0, failed = 0, total = 0;

async function test(id, description, fn) {
  total++;
  try {
    const result = await fn();
    if (result.pass) {
      passed++;
      results.push({ id, description, status: 'PASS', detail: result.detail });
      console.log(`  ✓ [${id}] ${description}`);
    } else {
      failed++;
      results.push({ id, description, status: 'FAIL', detail: result.detail, severity: result.severity ?? 'HIGH' });
      console.log(`  ✗ [${id}] ${description} — ${result.detail}`);
    }
  } catch (e) {
    failed++;
    results.push({ id, description, status: 'ERROR', detail: e.message });
    console.log(`  ! [${id}] ${description} — ERROR: ${e.message}`);
  }
}

// ─── SECTION L8-A: Ghost Pair Tests ──────────────────────────────────────────
console.log('\n══════════════════════════════════════════════════════════════');
console.log('  LAYER 8 ADVERSARIAL VERIFICATION SUITE');
console.log('  Attempting to break Ghost Pairs, Shadow Mode, and Tarpit');
console.log('══════════════════════════════════════════════════════════════\n');

console.log('── SECTION L8-A: Ghost Pair Detection ──');

await test('L8-A1', 'Ghost pair (env_file) returns ok:true — attacker is NOT told it is a canary', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secret = 'ghost-env-secret-32byteslong1234';
  const secretHash = hashSecret(secret);
  await registry.register('ghost-env-001', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'env_file', scope: 'read' });
  const req = await makeValidRequest('ghost-env-001', privJwk, secretHash);
  req.ip = '10.0.0.1';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Attacker sees ok:true — they think they succeeded
  const attackerSeesSuccess = result.ok === true;
  // Server knows it was a ghost hit
  const serverKnows = result.ghostAlert === true && result.shadow === true && result.canaryClass === 'env_file';
  return { pass: attackerSeesSuccess && serverKnows, detail: `ok=${result.ok} ghostAlert=${result.ghostAlert} canaryClass=${result.canaryClass}` };
});

await test('L8-A2', 'Ghost pair (docs) returns ok:true with correct canaryClass', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('docs-secret-32byteslong12345678');
  await registry.register('ghost-docs-001', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'docs', scope: 'read' });
  const req = await makeValidRequest('ghost-docs-001', privJwk, secretHash);
  req.ip = '10.0.0.2';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok && result.ghostAlert && result.canaryClass === 'docs', detail: `canaryClass=${result.canaryClass}` };
});

await test('L8-A3', 'Ghost pair (registry_exfil) auto-routes attacker IP to shadow state', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('reg-exfil-secret-32byteslong1234');
  await registry.register('ghost-reg-001', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'registry_exfil', scope: 'read' });
  const req = await makeValidRequest('ghost-reg-001', privJwk, secretHash);
  req.ip = '192.168.1.100';
  await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // After ghost hit, the attacker's IP should be in shadow state for this pair
  const inShadow = anomaly.isInShadowState('ghost-reg-001', '192.168.1.100');
  return { pass: inShadow, detail: `IP 192.168.1.100 in shadow state: ${inShadow}` };
});

await test('L8-A4', 'Ghost pair does NOT leak canary status in response (error field absent)', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('ghost-leak-test-32byteslong12345');
  await registry.register('ghost-leak-001', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'env_file', scope: 'read' });
  const req = await makeValidRequest('ghost-leak-001', privJwk, secretHash);
  req.ip = '10.1.1.1';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // The response must not contain 'ghost', 'canary', or 'decoy' in any field the attacker sees
  const responseStr = JSON.stringify({ ok: result.ok, error: result.error });
  const leaksCanary = responseStr.toLowerCase().includes('ghost') || responseStr.toLowerCase().includes('canary');
  return { pass: !leaksCanary && result.ok, detail: `Response visible to attacker: ${responseStr}` };
});

await test('L8-A5', 'Legitimate pair with same pairId prefix as ghost pair is unaffected', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk: ghostPub, privJwk: ghostPriv } = await generateKeyPair();
  const { pubJwk: realPub, privJwk: realPriv } = await generateKeyPair();
  const ghostHash = hashSecret('ghost-secret-32byteslong1234567');
  const realHash = hashSecret('real-secret-32byteslong12345678');
  await registry.register('pair-ghost', ghostPub, ghostHash, { kind: 'ghost', canaryClass: 'docs', scope: 'read' });
  await registry.register('pair-real', realPub, realHash, { kind: 'legitimate', scope: 'read' });
  const req = await makeValidRequest('pair-real', realPriv, realHash);
  req.ip = '10.2.2.2';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok && !result.shadow && !result.ghostAlert, detail: `Legitimate pair result: ok=${result.ok} shadow=${result.shadow}` };
});

// ─── SECTION L8-B: Shadow Mode Tests ─────────────────────────────────────────
console.log('\n── SECTION L8-B: Shadow Mode State Machine ──');

await test('L8-B1', 'Locked pair returns ok:true in shadow mode (attacker not told pair is locked)', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('locked-pair-secret-32byteslong12');
  const pair = await registry.register('pair-locked-001', pubJwk, secretHash, { scope: 'read' });
  pair.status = 'locked';
  await store.set(pair);
  const req = await makeValidRequest('pair-locked-001', privJwk, secretHash);
  req.ip = '10.3.3.3';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok === true && result.shadow === true, detail: `ok=${result.ok} shadow=${result.shadow} error=${result.error}` };
});

await test('L8-B2', 'Shadow state is scoped to sourceIP+pairId — different IP gets real auth', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('scope-test-secret-32byteslong1234');
  await registry.register('pair-scope-001', pubJwk, secretHash, { scope: 'read' });
  // Put attacker IP in shadow state
  await anomaly.enterShadowState('pair-scope-001', '10.4.4.4', 'test');
  // Legitimate user from different IP should get real auth
  const req = await makeValidRequest('pair-scope-001', privJwk, secretHash);
  req.ip = '10.5.5.5';  // DIFFERENT IP
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok === true && result.shadow !== true, detail: `Legitimate IP result: ok=${result.ok} shadow=${result.shadow}` };
});

await test('L8-B3', 'Shadow state persists — attacker cannot escape by retrying', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('persist-test-secret-32byteslong12');
  await registry.register('pair-persist-001', pubJwk, secretHash, { scope: 'read' });
  await anomaly.enterShadowState('pair-persist-001', '10.6.6.6', 'test');
  // Try 5 more requests — all should return shadow mode
  let allShadow = true;
  for (let i = 0; i < 5; i++) {
    const req = await makeValidRequest('pair-persist-001', privJwk, secretHash);
    req.ip = '10.6.6.6';
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
    if (!result.shadow) allShadow = false;
  }
  return { pass: allShadow, detail: `All 5 retry attempts returned shadow mode: ${allShadow}` };
});

await test('L8-B4', 'Shadow state auto-triggers at 7+ sig failures from same IP', async () => {
  // Use a fresh anomaly engine and directly simulate 7 IP-scoped sig failures,
  // then verify getVerdict returns shadow and isInShadowState is true.
  // This tests the anomaly engine's auto-shadow logic in isolation from the
  // pair lockout path (which fires at 10 failures and takes a different code path).
  const anomaly = new AnomalyEngine(new AnomalyStore());
  const pairId = 'pair-auto-shadow-b4';
  const ip = '10.7.7.7';
  // Simulate 7 IP-scoped sig failures directly
  for (let i = 0; i < 7; i++) {
    await anomaly.recordSigFailureForIp(pairId, ip);
  }
  // getVerdict should return 'shadow' and auto-call enterShadowState
  const verdict = await anomaly.getVerdict(pairId, ip);
  const inShadow = anomaly.isInShadowState(pairId, ip);
  return { pass: verdict === 'shadow' && inShadow, detail: `After 7 IP sig fails: verdict=${verdict} isInShadowState=${inShadow}` };
});

await test('L8-B5', 'Shadow state does NOT bleed to other pairIds from same IP', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk: p1Pub, privJwk: p1Priv } = await generateKeyPair();
  const { pubJwk: p2Pub, privJwk: p2Priv } = await generateKeyPair();
  const hash1 = hashSecret('pair1-secret-32byteslong12345678');
  const hash2 = hashSecret('pair2-secret-32byteslong12345678');
  await registry.register('pair-bleed-001', p1Pub, hash1, { scope: 'read' });
  await registry.register('pair-bleed-002', p2Pub, hash2, { scope: 'read' });
  // Put IP in shadow state for pair-bleed-001 only
  await anomaly.enterShadowState('pair-bleed-001', '10.8.8.8', 'test');
  // Request to pair-bleed-002 from same IP should NOT be in shadow
  const req = await makeValidRequest('pair-bleed-002', p2Priv, hash2);
  req.ip = '10.8.8.8';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok && !result.shadow, detail: `Different pair from same IP: ok=${result.ok} shadow=${result.shadow}` };
});

await test('L8-B6', 'Operator clearShadowState removes shadow — legitimate user restored', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('clear-shadow-secret-32byteslong12');
  await registry.register('pair-clear-001', pubJwk, secretHash, { scope: 'read' });
  await anomaly.enterShadowState('pair-clear-001', '10.9.9.9', 'test');
  // Verify shadow is active
  const req1 = await makeValidRequest('pair-clear-001', privJwk, secretHash);
  req1.ip = '10.9.9.9';
  const r1 = await verifyBPCRequest(req1, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Operator clears shadow state
  anomaly.clearShadowState('pair-clear-001', '10.9.9.9');
  // Now request should succeed normally
  const req2 = await makeValidRequest('pair-clear-001', privJwk, secretHash);
  req2.ip = '10.9.9.9';
  const r2 = await verifyBPCRequest(req2, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: r1.shadow && !r2.shadow && r2.ok, detail: `Before clear: shadow=${r1.shadow}. After clear: shadow=${r2.shadow} ok=${r2.ok}` };
});

// ─── SECTION L8-C: Tarpit Tests ───────────────────────────────────────────────
console.log('\n── SECTION L8-C: Cryptographic Tarpit ──');

await test('L8-C1', 'Suspicious IP (3+ sig fails) receives tarpit delay', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('tarpit-test-secret-32byteslong123');
  await registry.register('pair-tarpit-001', pubJwk, secretHash, { scope: 'read' });
  // Send 3 bad sig requests from same IP to enter suspicious state
  for (let i = 0; i < 3; i++) {
    const req = await makeValidRequest('pair-tarpit-001', privJwk, secretHash);
    req.ip = '10.10.10.10'; req.signature = 'badsig' + i;
    await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  }
  // 4th request should be tarpitted (suspicious verdict = 500ms)
  const req = await makeValidRequest('pair-tarpit-001', privJwk, secretHash);
  req.ip = '10.10.10.10';
  const t0 = Date.now();
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: true });
  const elapsed = Date.now() - t0;
  return { pass: elapsed >= 490 && result.ok, detail: `Tarpit delay: ${elapsed}ms (expected ≥500ms), ok=${result.ok}` };
});

await test('L8-C2', 'Tarpit is per source IP — different IP not delayed', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('tarpit-ip-test-secret-32byteslong');
  await registry.register('pair-tarpit-002', pubJwk, secretHash, { scope: 'read' });
  // Put attacker IP in tarpit
  for (let i = 0; i < 3; i++) {
    const req = await makeValidRequest('pair-tarpit-002', privJwk, secretHash);
    req.ip = '10.11.11.11'; req.signature = 'badsig' + i;
    await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  }
  // Legitimate user from different IP should NOT be delayed
  const req = await makeValidRequest('pair-tarpit-002', privJwk, secretHash);
  req.ip = '10.12.12.12';  // DIFFERENT IP
  const t0 = Date.now();
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: true });
  const elapsed = Date.now() - t0;
  return { pass: elapsed < 100 && result.ok, detail: `Clean IP response time: ${elapsed}ms (expected <100ms)` };
});

await test('L8-C3', 'Tarpit can be disabled via config — no delay applied', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('tarpit-disable-secret-32byteslong');
  await registry.register('pair-tarpit-003', pubJwk, secretHash, { scope: 'read' });
  await anomaly.enterShadowState('pair-tarpit-003', '10.13.13.13', 'test');
  const req = await makeValidRequest('pair-tarpit-003', privJwk, secretHash);
  req.ip = '10.13.13.13';
  const t0 = Date.now();
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  const elapsed = Date.now() - t0;
  return { pass: elapsed < 100 && result.shadow, detail: `With tarpit disabled: ${elapsed}ms, shadow=${result.shadow}` };
});

// ─── SECTION L8-D: State Machine Integrity ────────────────────────────────────
console.log('\n── SECTION L8-D: State Machine Integrity ──');

await test('L8-D1', 'Shadow mode disabled — locked pair returns pair_locked error (no deception)', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('shadow-disabled-secret-32byteslon');
  const pair = await registry.register('pair-no-shadow', pubJwk, secretHash, { scope: 'read' });
  pair.status = 'locked'; await store.set(pair);
  const req = await makeValidRequest('pair-no-shadow', privJwk, secretHash);
  req.ip = '10.14.14.14';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: false, enableTarpit: false });
  return { pass: result.ok === false && result.error === 'pair_locked', detail: `Shadow disabled: ok=${result.ok} error=${result.error}` };
});

await test('L8-D2', 'Attacker cannot force shadow state on a clean pair via header manipulation', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('force-shadow-secret-32byteslong12');
  await registry.register('pair-force-shadow', pubJwk, secretHash, { scope: 'read' });
  // Attacker tries to inject shadow state via a crafted request
  const req = await makeValidRequest('pair-force-shadow', privJwk, secretHash);
  req.ip = '10.15.15.15';
  // Attacker adds shadow-related headers (these should be ignored)
  req['x-bpc-shadow'] = 'true';
  req['x-shadow-mode'] = '1';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  return { pass: result.ok && !result.shadow, detail: `Injected shadow headers ignored: ok=${result.ok} shadow=${result.shadow}` };
});

await test('L8-D3', 'Ghost pair with bad signature is denied — not silently trapped', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('ghost-badsig-secret-32byteslong12');
  await registry.register('ghost-badsig-001', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'docs', scope: 'read' });
  const req = await makeValidRequest('ghost-badsig-001', privJwk, secretHash);
  req.ip = '10.16.16.16';
  req.signature = 'invalidsignature'; // Bad sig
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Bad sig should be denied even on ghost pair — ghost trap only fires on VALID auth
  return { pass: result.ok === false, detail: `Ghost pair with bad sig: ok=${result.ok} error=${result.error}` };
});

await test('L8-D4', 'Shadow state list is accessible for SOC monitoring', async () => {
  const anomaly = new AnomalyEngine(new AnomalyStore());
  await anomaly.enterShadowState('pair-soc-001', '10.17.17.17', 'test1');
  await anomaly.enterShadowState('pair-soc-002', '10.18.18.18', 'test2');
  const shadowList = anomaly.listShadowState();
  return { pass: shadowList.length === 2, detail: `SOC shadow list has ${shadowList.length} entries` };
});

// ─── SECTION L8-E: War of the Worlds — Simple Overlooked Attacks ──────────────
console.log('\n── SECTION L8-E: War of the Worlds — Simple Overlooked Attacks ──');

await test('L8-E1', 'Attacker registers their own pair with kind=ghost to bypass ghost detection', async () => {
  // Can an attacker self-register a ghost pair to make the server think they are a canary?
  // This would be a privilege escalation — registerGhostPair should require admin access
  // In the current implementation, registerDirect is an internal API — not HTTP-exposed
  // This test verifies that a ghost pair registered by an attacker does NOT grant them
  // any special bypass — it still routes them to shadow mode on success
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('attacker-ghost-secret-32byteslong');
  // Attacker somehow registers a ghost pair (simulating a compromised admin endpoint)
  await registry.register('attacker-ghost', pubJwk, secretHash, { kind: 'ghost', canaryClass: 'registry_exfil', scope: 'read' });
  const req = await makeValidRequest('attacker-ghost', privJwk, secretHash);
  req.ip = '10.19.19.19';
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Even if attacker registers a ghost pair, they still get shadow mode — not real access
  // The ghost trap works against the attacker's own pair too
  return { pass: result.shadow === true && result.ghostAlert === true, detail: `Attacker's own ghost pair still traps them: shadow=${result.shadow}` };
});

await test('L8-E2', 'Replay attack against shadow mode — same request replayed does not escape shadow', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('replay-shadow-secret-32byteslong1');
  await registry.register('pair-replay-shadow', pubJwk, secretHash, { scope: 'read' });
  await anomaly.enterShadowState('pair-replay-shadow', '10.20.20.20', 'test');
  // Attacker replays the exact same request 3 times hoping to get real auth
  const req = await makeValidRequest('pair-replay-shadow', privJwk, secretHash);
  req.ip = '10.20.20.20';
  const r1 = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  const r2 = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  const r3 = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // All three should return shadow mode — shadow check runs before nonce check
  return { pass: r1.shadow && r2.shadow && r3.shadow, detail: `Replay in shadow: r1=${r1.shadow} r2=${r2.shadow} r3=${r3.shadow}` };
});

await test('L8-E3', 'IP spoofing attempt — attacker uses null/undefined IP to bypass tarpit', async () => {
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('ip-spoof-secret-32byteslong123456');
  await registry.register('pair-ip-spoof', pubJwk, secretHash, { scope: 'read' });
  // Put 'unknown' IP in shadow state
  await anomaly.enterShadowState('pair-ip-spoof', 'unknown', 'test');
  // Attacker sends request with no IP (ip=undefined) — maps to 'unknown'
  const req = await makeValidRequest('pair-ip-spoof', privJwk, secretHash);
  req.ip = undefined;  // No IP provided
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Should be caught by shadow state for 'unknown' IP
  return { pass: result.shadow === true, detail: `No-IP request shadow state: shadow=${result.shadow}` };
});

await test('L8-E4', 'Canary class field cannot be overridden via signed payload', async () => {
  // Can an attacker include a canaryClass field in their signed payload to confuse the server?
  const store = new InMemoryStore(); const anomaly = new AnomalyEngine(new AnomalyStore());
  const registry = new PairRegistry(store); const nonceStore = new NonceStore();
  const { pubJwk, privJwk } = await generateKeyPair();
  const secretHash = hashSecret('canary-override-secret-32byteslong');
  await registry.register('pair-canary-override', pubJwk, secretHash, { kind: 'legitimate', scope: 'read' });
  // Attacker includes canaryClass in their signed payload
  const nonce = randomUUID(); const timestamp = Date.now();
  const secretHmac = computeSecretHmac(secretHash, nonce, timestamp);
  const payload = { method: 'GET', path: '/api/test', nonce, timestamp, secret_hmac: secretHmac, canaryClass: 'env_file', kind: 'ghost' };
  const signature = await signPayload(privJwk, payload);
  const signedData = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const req = { pairId: 'pair-canary-override', signedData, signature, method: 'GET', path: '/api/test', version: '1.0', bodyHash: null, ip: '10.21.21.21' };
  const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60000, enableShadowMode: true, enableTarpit: false });
  // Should succeed normally — payload canaryClass field is ignored (pair kind comes from registry)
  return { pass: result.ok && !result.ghostAlert && !result.shadow, detail: `Payload canaryClass injection: ok=${result.ok} ghostAlert=${result.ghostAlert}` };
});

// ─── Results ──────────────────────────────────────────────────────────────────

console.log('\n══════════════════════════════════════════════════════════════');
console.log(`  RESULTS: ${passed}/${total} passed, ${failed} failed`);
console.log('══════════════════════════════════════════════════════════════\n');

const breaches = results.filter(r => r.status === 'FAIL');
if (breaches.length > 0) {
  console.log('BREACHES FOUND:');
  breaches.forEach(b => console.log(`  [${b.id}] ${b.description}\n    → ${b.detail}`));
} else {
  console.log('  ALL LAYER 8 MECHANISMS VERIFIED — ZERO BREACHES');
}

import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const __dirname = dirname(fileURLToPath(import.meta.url));
const outPath = join(__dirname, 'layer8-results.json');
writeFileSync(outPath, JSON.stringify({
  timestamp: new Date().toISOString(),
  summary: { total, passed, failed, breaches: breaches.length },
  results,
}, null, 2));
console.log(`\nResults written to ${outPath}`);
