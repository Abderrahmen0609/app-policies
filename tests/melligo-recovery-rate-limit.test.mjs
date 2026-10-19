import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  COOLDOWN_KEY, DEFAULT_RETRY_DELAY, MAX_RETRY_DELAY, RECOVERY_URL, PROJECT_URL,
  STORAGE_KEY, REQUEST_LIFETIME, RecoveryError, retryDelay, createAuthApi, createRecovery,
} from '../melligo/auth/recovery/recovery-core.mjs';

const NOW = Date.parse('2026-10-19T00:00:00Z');
const NONCE = 'N'.repeat(43);
const OTHER = 'X'.repeat(43);
const CODE = 'fictional-auth-code-00000000000000001';
const callback = (nonce) => `${RECOVERY_URL}?state=${nonce}&code=${CODE}`;
const accepted = { schema: 1, phase: 'pending', nonce: NONCE, verifier: 'V'.repeat(43), createdAt: NOW };
const memory = () => {
  const entries = new Map();
  return { entries, getItem: (key) => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, value), removeItem: (key) => entries.delete(key) };
};
function mutex() {
  let tail = Promise.resolve();
  let held = 0;
  return {
    held: () => held,
    async run(signal, action) {
      const previous = tail;
      let release;
      tail = new Promise((resolve) => { release = resolve; });
      await previous;
      try {
        if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
        held++;
        try { return await action(); } finally { held--; }
      } finally { release(); }
    },
  };
}
function fixture({ storage = memory(), lock = mutex(), api = {}, clock = { now: NOW } } = {}) {
  const controller = createRecovery({
    storage, crypto: webcrypto, api, contextLock: lock.run.bind(lock), now: () => clock.now,
  });
  return { controller, storage, lock, api, clock };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function started(storage) {
  for (let count = 0; count < 100; count++) {
    const value = JSON.parse(storage.getItem(STORAGE_KEY) ?? 'null');
    if (value?.phase === 'requesting') return value;
    await tick();
  }
  throw Error('Synthetic request did not reach its staged context.');
}

test('Retry-After accepts bounded seconds and exact HTTP-date without trusting arbitrary date strings', () => {
  assert.deepEqual(retryDelay('120', NOW), { delay: 120_000, source: 'server' });
  assert.deepEqual(retryDelay(' 2 ', NOW), { delay: 2000, source: 'server' });
  assert.deepEqual(retryDelay('0', NOW), { delay: 1000, source: 'server' });
  assert.deepEqual(retryDelay(new Date(NOW + 90_000).toUTCString(), NOW), { delay: 90_000, source: 'server' });
  assert.deepEqual(retryDelay('9999999999', NOW), { delay: MAX_RETRY_DELAY, source: 'server' });
  assert.deepEqual(retryDelay(new Date(NOW + MAX_RETRY_DELAY * 2).toUTCString(), NOW), { delay: MAX_RETRY_DELAY, source: 'server' });
  for (const value of [null, '', '-1', '0.5', '1e9', 'Infinity', '1'.repeat(129), '2026-10-19',
    'Sun, 19 Oct 2026 00:01:00 GMT', new Date(NOW - 1000).toUTCString(), 'Mon, 32 Oct 2026 00:01:00 GMT']) {
    assert.deepEqual(retryDelay(value, NOW), { delay: DEFAULT_RETRY_DELAY, source: 'local' });
  }
});

test('Auth adapter carries only validated Retry-After metadata, never provider body text', async () => {
  const anon = `e30.${Buffer.from(JSON.stringify({ role: 'anon', ref: 'wodjmlcczrjxeexyhwpr' })).toString('base64url')}.fictional`;
  const api = createAuthApi({ anonKey: anon, now: () => NOW, fetch: async () => new Response('fictional private provider body', {
    status: 429, headers: { 'retry-after': '75' },
  }) });
  await assert.rejects(api.request('fictional@example.test', 'C'.repeat(43), NONCE), (error) => {
    assert.equal(error.code, 'rate_limited');
    assert.deepEqual(error.retry, { delay: 75_000, source: 'server' });
    assert.equal(JSON.stringify(error).includes('provider body'), false);
    return true;
  });
  const unknown = createAuthApi({ anonKey: anon, now: () => NOW, fetch: async () => new Response('{}', { status: 503 }) });
  await assert.rejects(unknown.request('fictional@example.test', 'C'.repeat(43), NONCE), (error) => error.code === 'connection_error');
});

test('rejected429 preserves an earlier pending verifier, pauses across reload, and never auto-retries', async () => {
  let sends = 0;
  const f = fixture({ api: { async request() { sends++; throw new RecoveryError('rate_limited', { delay: 5000, source: 'server' }); } } });
  f.storage.setItem(STORAGE_KEY, JSON.stringify(accepted));
  await f.controller.request('fictional@example.test');
  assert.deepEqual(JSON.parse(f.storage.getItem(STORAGE_KEY)), accepted);
  assert.equal(f.controller.state().error, 'rate_limited');
  assert.equal(f.controller.state().cooldownUntil, NOW + 5000);
  const pause = JSON.parse(f.storage.getItem(COOLDOWN_KEY));
  assert.deepEqual(Object.keys(pause).sort(), ['at', 'schema', 'source', 'until']);
  await f.controller.request('fictional@example.test');
  assert.equal(sends, 1);
  const reloaded = fixture(f);
  await reloaded.controller.initialize(RECOVERY_URL, () => {});
  assert.equal(reloaded.controller.state().error, 'rate_limited');
  await reloaded.controller.request('fictional@example.test');
  assert.equal(sends, 1);
  f.clock.now += 5000;
  assert.equal(sends, 1);
  await reloaded.controller.request('fictional@example.test');
  assert.equal(sends, 2);
});

test('observed newer pending or exchanging nonce is never overwritten by a rejected send', async () => {
  for (const phase of ['pending', 'exchanging']) {
    const f = fixture();
    f.storage.setItem(STORAGE_KEY, JSON.stringify(accepted));
    const newer = { ...accepted, phase, nonce: OTHER };
    f.api.request = async () => {
      assert.equal(f.lock.held(), 0);
      f.storage.setItem(STORAGE_KEY, JSON.stringify(newer));
      throw new RecoveryError('rate_limited');
    };
    await f.controller.request('fictional@example.test');
    assert.deepEqual(JSON.parse(f.storage.getItem(STORAGE_KEY)), newer);
    assert.equal(f.controller.state().error, 'rate_limited');
  }
});

test('a late429 never shortens another observed longer pause', async () => {
  const f = fixture();
  f.api.request = async () => {
    f.storage.setItem(COOLDOWN_KEY, JSON.stringify({ schema: 1, at: NOW, until: NOW + 300_000, source: 'server' }));
    throw new RecoveryError('rate_limited', { delay: 1000, source: 'server' });
  };
  await f.controller.request('fictional@example.test');
  assert.equal(f.controller.state().cooldownUntil, NOW + 300_000);
  assert.equal(JSON.parse(f.storage.getItem(COOLDOWN_KEY)).until, NOW + 300_000);
});

test('an expired previous context is never resurrected on429', async () => {
  const f = fixture({ api: { async request() { throw new RecoveryError('rate_limited'); } } });
  f.storage.setItem(STORAGE_KEY, JSON.stringify({ ...accepted, createdAt: NOW - REQUEST_LIFETIME }));
  await f.controller.request('fictional@example.test');
  assert.equal(f.storage.getItem(STORAGE_KEY), null);
  assert.equal(f.controller.state().cooldownSource, 'local');
});

test('unknown network outcome retains its new verifier and check-inbox error without retry or restoring old context', async () => {
  let sends = 0;
  const f = fixture({ api: { async request() { sends++; throw new RecoveryError('connection_error'); } } });
  f.storage.setItem(STORAGE_KEY, JSON.stringify(accepted));
  await f.controller.request('fictional@example.test');
  const retained = JSON.parse(f.storage.getItem(STORAGE_KEY));
  assert.equal(retained.phase, 'pending');
  assert.notEqual(retained.nonce, NONCE);
  assert.equal('previous' in retained, false);
  assert.equal(f.controller.state().error, 'connection_error');
  assert.equal(sends, 1);
});

test('a second tab cannot replace another in-flight send and performs no additional Auth request', async () => {
  let reject;
  let sends = 0;
  const storage = memory();
  const lock = mutex();
  storage.setItem(STORAGE_KEY, JSON.stringify(accepted));
  const first = fixture({ storage, lock, api: { request() { sends++; return new Promise((_resolve, no) => { reject = no; }); } } });
  const second = fixture({ storage, lock, api: { async request() { sends++; } } });
  const pending = first.controller.request('fictional@example.test');
  const staged = await started(storage);
  await second.controller.request('other-fictional@example.test');
  assert.equal(second.controller.state().error, 'request_in_progress');
  assert.equal(JSON.parse(storage.getItem(STORAGE_KEY)).nonce, staged.nonce);
  assert.equal(sends, 1);
  reject(new RecoveryError('rate_limited'));
  await pending;
  assert.deepEqual(JSON.parse(storage.getItem(STORAGE_KEY)), accepted);
});

test('the previous callback is not blocked by a request network wait and late429 never resurrects consumed state', async () => {
  let reject;
  const storage = memory();
  const lock = mutex();
  storage.setItem(STORAGE_KEY, JSON.stringify(accepted));
  const sender = fixture({ storage, lock, api: { request() {
    assert.equal(lock.held(), 0);
    return new Promise((_resolve, no) => { reject = no; });
  } } });
  let exchanges = 0;
  const receiver = fixture({ storage, lock, api: {
    async exchange(_code, verifier) {
      assert.equal(lock.held(), 0); exchanges++;
      assert.equal(verifier, accepted.verifier);
      return { token: 'fictional-RAM-only', expiresAt: NOW + 600_000 };
    }, async logout() {},
  } });
  const pending = sender.controller.request('fictional@example.test');
  await started(storage);
  await receiver.controller.initialize(callback(NONCE), () => {});
  assert.equal(receiver.controller.state().phase, 'password');
  assert.equal(exchanges, 1);
  assert.equal(storage.getItem(STORAGE_KEY), null);
  reject(new RecoveryError('rate_limited'));
  await pending;
  assert.equal(storage.getItem(STORAGE_KEY), null);
  assert.equal(receiver.controller.state().phase, 'password');
});

test('a callback for a newly delivered email may also complete before the send response returns', async () => {
  let resolve;
  const storage = memory();
  const lock = mutex();
  const sender = fixture({ storage, lock, api: { request() { return new Promise((yes) => { resolve = yes; }); } } });
  const pending = sender.controller.request('fictional@example.test');
  const staged = await started(storage);
  const receiver = fixture({ storage, lock, api: {
    async exchange(_code, verifier) { assert.equal(verifier, staged.verifier); return { token: 'fictional-RAM-only', expiresAt: NOW + 600_000 }; },
    async logout() {},
  } });
  await receiver.controller.initialize(callback(staged.nonce), () => {});
  assert.equal(receiver.controller.state().phase, 'password');
  resolve(); await pending;
  assert.equal(storage.getItem(STORAGE_KEY), null);
  assert.equal(sender.controller.state().phase, 'handled');
});

test('missing coordinator fails closed and stored hostile cooldowns cannot impose an unbounded pause', async () => {
  assert.throws(() => createRecovery({}), (error) => error.code === 'compatible_browser');
  for (const invalid of ['{', JSON.stringify({ schema: 1, at: NOW, until: Number.MAX_SAFE_INTEGER, source: 'server' }),
    JSON.stringify({ schema: 1, at: NOW + 120_000, until: NOW + 180_000, source: 'server' }),
    JSON.stringify({ schema: 1, at: NOW + 60_000, until: NOW + MAX_RETRY_DELAY + 60_000, source: 'server' })]) {
    let sends = 0;
    const f = fixture({ api: { async request() { sends++; } } });
    f.storage.setItem(COOLDOWN_KEY, invalid);
    await f.controller.request('fictional@example.test');
    assert.equal(sends, 1);
    assert.equal(f.controller.state().phase, 'sent');
  }
});
