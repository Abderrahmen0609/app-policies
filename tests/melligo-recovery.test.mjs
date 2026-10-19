import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import {
  RECOVERY_URL, PROJECT_URL, STORAGE_KEY, REQUEST_LIFETIME,
  RecoveryError, makePkce, parseReturn, validatePassword, createAuthApi, createRecovery,
} from '../melligo/auth/recovery/recovery-core.mjs';

const NOW = Date.parse('2026-10-19T00:00:00Z');
const USER = '11111111-1111-4111-8111-111111111111';
const NONCE = 'N'.repeat(43);
const VERIFIER = 'V'.repeat(43);
const CODE = 'fictional-auth-code-00000000000000001';
const jwt = (claims) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.fictional-signature`;
const ANON = jwt({ role: 'anon', ref: 'wodjmlcczrjxeexyhwpr' });
const TOKEN = jwt({ sub: USER, role: 'authenticated', iss: `${PROJECT_URL}/auth/v1`, exp: NOW / 1000 + 600 });
const callback = `${RECOVERY_URL}?state=${NONCE}&code=${CODE}`;
const memory = () => {
  const values = new Map();
  return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key), values };
};
function saved(storage, patch = {}) {
  storage.setItem(STORAGE_KEY, JSON.stringify({ schema: 1, phase: 'pending', nonce: NONCE, verifier: VERIFIER, createdAt: NOW, ...patch }));
}
function fakeApi() {
  const calls = [];
  return {
    calls,
    async request(...args) { calls.push(['request', ...args]); },
    async exchange(...args) { calls.push(['exchange', ...args]); return { token: TOKEN, expiresAt: NOW + 600_000 }; },
    async update(...args) { calls.push(['update', ...args]); },
    async logout(...args) { calls.push(['logout', ...args]); },
  };
}
function fixture({ storage = memory(), api = fakeApi(), now = () => NOW } = {}) {
  const notices = [];
  const controller = createRecovery({ storage, api, now, crypto: webcrypto, notify: (state) => notices.push(state) });
  return { controller, storage, api, notices };
}
const response = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

test('PKCE uses two independent 256-bit values and S256 matches the RFC7636 vector', async () => {
  const pair = await makePkce(webcrypto);
  assert.match(pair.verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.match(pair.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(pair.verifier, pair.nonce);
  const expected = Buffer.from(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(pair.verifier))).toString('base64url');
  assert.equal(pair.challenge, expected);
  const vector = Buffer.from(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'))).toString('base64url');
  assert.equal(vector, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('only exact HTTPS callback and single code/state are accepted', () => {
  assert.equal(parseReturn(RECOVERY_URL).kind, 'request');
  assert.equal(parseReturn(callback).kind, 'callback');
  for (const href of [
    callback.replace('https:', 'http:'), callback.replace('abderrahmen0609.github.io', 'example.test'),
    callback.replace('/recovery/', '/'), `${callback}&code=duplicate`, `${callback}&state=duplicate`,
    `${callback}&next=https://example.test`, `${callback}#access_token=fictional`, `${RECOVERY_URL}?code=${CODE}`,
    `${RECOVERY_URL}?state=${NONCE}&code=%0Aunsafe`, `${RECOVERY_URL}?state=${NONCE}`,
  ]) assert.throws(() => parseReturn(href), RecoveryError);
  assert.equal(parseReturn(`${RECOVERY_URL}?error_code=otp_expired&error_description=untrusted`).kind, 'failed');
});

test('password mismatch, controls and size are rejected without modifying the supplied password', () => {
  assert.equal(validatePassword('  long password  ', '  long password  '), null);
  assert.equal(validatePassword('short', 'short'), 'password_rules');
  assert.equal(validatePassword('eight123', 'different'), 'password_mismatch');
  assert.equal(validatePassword('eight\n123', 'eight\n123'), 'password_rules');
  assert.equal(validatePassword('x'.repeat(257), 'x'.repeat(257)), 'password_rules');
});

test('request stores only verifier/nonce/clock then makes one S256 request, generic acknowledgement', async () => {
  const f = fixture();
  await f.controller.initialize(RECOVERY_URL, () => {});
  await f.controller.request(' fictional@example.test ');
  assert.equal(f.controller.state().phase, 'sent');
  const entry = JSON.parse(f.storage.getItem(STORAGE_KEY));
  assert.deepEqual(Object.keys(entry).sort(), ['createdAt', 'nonce', 'phase', 'schema', 'verifier']);
  assert.equal(f.api.calls.length, 1);
  assert.equal(f.api.calls[0][0], 'request');
  assert.equal(f.api.calls[0][1], 'fictional@example.test');
  assert.match(f.api.calls[0][2], /^[A-Za-z0-9_-]{43}$/);
  assert.equal(f.notices.some((notice) => JSON.stringify(notice).includes('example.test')), false);
});

test('invalid email/storage failure never calls Auth', async () => {
  const f = fixture();
  await f.controller.request('invalid');
  assert.equal(f.controller.state().error, 'invalid_email');
  assert.equal(f.api.calls.length, 0);
  const broken = fixture({ storage: { setItem() { throw Error('fictional'); } } });
  await broken.controller.request('fictional@example.test');
  assert.equal(broken.controller.state().error, 'storage_unavailable');
  assert.equal(broken.api.calls.length, 0);
});

test('same-browser recovery consumes verifier, clears URL before exchange, token stays RAM-only', async () => {
  const f = fixture();
  saved(f.storage);
  let urlCleared = false;
  f.api.exchange = async () => {
    assert.equal(urlCleared, true);
    assert.equal(JSON.parse(f.storage.getItem(STORAGE_KEY)).verifier, undefined);
    return { token: TOKEN, expiresAt: NOW + 600_000 };
  };
  await f.controller.initialize(callback, () => { urlCleared = true; });
  assert.equal(f.controller.state().phase, 'password');
  assert.equal(f.storage.values.size, 0);
  assert.equal(JSON.stringify(f.notices).includes(TOKEN), false);
  await f.controller.update('new fictional password', 'new fictional password');
  assert.equal(f.controller.state().phase, 'complete');
  assert.deepEqual(f.api.calls.map((call) => call[0]), ['update', 'logout']);
  assert.equal(f.storage.values.size, 0);
});

test('a separate browser, nonce mismatch, expired/future/corrupt context never exchanges', async () => {
  for (const patch of [null, { nonce: 'X'.repeat(43) }, { createdAt: NOW - REQUEST_LIFETIME }, { createdAt: NOW + 60_001 }, { phase: 'exchanging' }, { verifier: 'short' }]) {
    const f = fixture();
    if (patch) saved(f.storage, patch);
    let cleared = false;
    await f.controller.initialize(callback, () => { cleared = true; });
    assert.equal(cleared, true);
    assert.equal(f.controller.state().phase, 'request');
    assert.equal(f.api.calls.length, 0);
  }
});

test('error and implicit bearer callbacks are scrubbed and never exchanged', async () => {
  for (const href of [`${RECOVERY_URL}?error=access_denied`, `${RECOVERY_URL}#access_token=fictional&type=recovery`]) {
    const f = fixture(); saved(f.storage);
    let cleaned = false;
    await f.controller.initialize(href, () => { cleaned = true; });
    assert.equal(cleaned, true); assert.equal(f.api.calls.length, 0);
    assert.equal(f.controller.state().phase, 'request');
  }
});

test('an uncertain exchange is consumed and cannot be replayed on reload', async () => {
  const f = fixture(); saved(f.storage);
  f.api.exchange = async () => { f.api.calls.push(['exchange']); throw new RecoveryError('connection_error'); };
  await f.controller.initialize(callback, () => {});
  await f.controller.initialize(callback, () => {});
  assert.equal(f.api.calls.length, 1);
  assert.equal(f.controller.state().error, 'same_browser_required');
});

test('observed newer nonce during an outstanding exchange rejects its earlier result', async () => {
  const f = fixture(); saved(f.storage);
  f.api.exchange = async () => {
    saved(f.storage, { nonce: 'X'.repeat(43) });
    return { token: TOKEN, expiresAt: NOW + 600_000 };
  };
  await f.controller.initialize(callback, () => {});
  assert.equal(f.controller.state().error, 'newer_request');
  assert.equal(f.api.calls[0][0], 'logout');
  assert.equal(JSON.parse(f.storage.getItem(STORAGE_KEY)).nonce, 'X'.repeat(43));
});

test('late exchange after disposal never opens a password form', async () => {
  const f = fixture(); saved(f.storage);
  let release;
  f.api.exchange = () => new Promise((resolve) => { release = resolve; });
  const pending = f.controller.initialize(callback, () => {});
  f.controller.dispose(); release({ token: TOKEN, expiresAt: NOW + 600_000 }); await pending;
  assert.equal(f.notices.some((notice) => notice.phase === 'password'), false);
  assert.equal(f.api.calls[0][0], 'logout');
});

test('no update before recovery, expired session, mismatch and double submission are blocked', async () => {
  const f = fixture();
  await f.controller.update('new password', 'new password');
  assert.equal(f.api.calls.length, 0);
  saved(f.storage); await f.controller.initialize(callback, () => {});
  await f.controller.update('new password', 'not matching');
  assert.equal(f.api.calls.filter((call) => call[0] === 'update').length, 0);
  let release;
  f.api.update = () => new Promise((resolve) => { f.api.calls.push(['update']); release = resolve; });
  const pending = f.controller.update('new password', 'new password');
  await f.controller.update('new password', 'new password');
  release(); await pending;
  assert.equal(f.api.calls.filter((call) => call[0] === 'update').length, 1);
  const expired = fixture({ now: () => NOW + 601_000 }); saved(expired.storage);
  await expired.controller.initialize(callback, () => {}); await expired.controller.update('new password', 'new password');
  assert.equal(expired.controller.state().error, 'expired_link');
});

test('unknown password-change outcome is not offered a blind retry; cleanup failure keeps known success', async () => {
  const f = fixture(); saved(f.storage); await f.controller.initialize(callback, () => {});
  f.api.update = async () => { f.api.calls.push(['update']); throw new RecoveryError('connection_error'); };
  await f.controller.update('new password', 'new password');
  assert.equal(f.controller.state().phase, 'uncertain');
  await f.controller.update('new password', 'new password');
  assert.equal(f.api.calls.filter((call) => call[0] === 'update').length, 1);
  const success = fixture(); saved(success.storage); await success.controller.initialize(callback, () => {});
  success.api.logout = async () => { throw new RecoveryError('connection_error'); };
  await success.controller.update('new password', 'new password');
  assert.equal(success.controller.state().phase, 'complete');
});

test('cancel is serialized, clears only its own request and never globally logs out', async () => {
  const f = fixture(); saved(f.storage); await f.controller.initialize(callback, () => {});
  let release;
  f.api.logout = () => new Promise((resolve) => { f.api.calls.push(['logout']); release = resolve; });
  const pending = f.controller.cancel(); await f.controller.cancel();
  saved(f.storage, { nonce: 'X'.repeat(43) }); release(); await pending;
  assert.equal(f.api.calls.filter((call) => call[0] === 'logout').length, 1);
  assert.equal(JSON.parse(f.storage.getItem(STORAGE_KEY)).nonce, 'X'.repeat(43));
  assert.equal(f.controller.state().phase, 'request');
});

test('Auth adapter emits only fixed own-project endpoints and password-only update/local logout', async () => {
  const calls = [];
  const api = createAuthApi({ anonKey: ANON, now: () => NOW, fetch: async (url, options) => {
    calls.push({ url, options });
    if (url.includes('/token?')) return response({ access_token: TOKEN, refresh_token: 'fictional-never-stored', token_type: 'bearer', user: { id: USER } });
    return response(url.endsWith('/user') ? { id: USER } : {});
  } });
  await api.request('fictional@example.test', 'C'.repeat(43), NONCE);
  const session = await api.exchange(CODE, VERIFIER);
  await api.update('new password', session.token); await api.logout(session.token);
  assert.equal(calls.length, 4);
  const recovery = new URL(calls[0].url);
  assert.equal(recovery.origin, PROJECT_URL);
  assert.equal(recovery.searchParams.get('redirect_to'), `${RECOVERY_URL}?state=${NONCE}`);
  assert.deepEqual(JSON.parse(calls[0].options.body), { email: 'fictional@example.test', code_challenge: 'C'.repeat(43), code_challenge_method: 's256' });
  assert.deepEqual(JSON.parse(calls[1].options.body), { auth_code: CODE, code_verifier: VERIFIER });
  assert.deepEqual(JSON.parse(calls[2].options.body), { password: 'new password' });
  assert.equal(calls[3].url, `${PROJECT_URL}/auth/v1/logout?scope=local`);
  for (const { options } of calls) assert.deepEqual([options.redirect, options.credentials, options.cache, options.referrerPolicy], ['error', 'omit', 'no-store', 'no-referrer']);
  assert.equal('refresh_token' in session, false);
});

test('foreign/nonanon config, wrong/expired session, oversized response and HTTP errors fail closed', async () => {
  assert.throws(() => createAuthApi({ anonKey: jwt({ role: 'service_role', ref: 'wodjmlcczrjxeexyhwpr' }), fetch() {} }), RecoveryError);
  for (const [body, status, code] of [
    [{}, 429, 'rate_limited'], [{}, 400, 'expired_link'], [{}, 403, 'expired_link'], [{}, 500, 'request_rejected'],
    [{ access_token: jwt({ sub: USER, role: 'authenticated', iss: 'https://example.test/auth/v1', exp: NOW / 1000 + 100 }), user: { id: USER }, token_type: 'bearer' }, 200, 'invalid_response'],
    [{ access_token: TOKEN, user: { id: '22222222-2222-4222-8222-222222222222' }, token_type: 'bearer' }, 200, 'invalid_response'],
    [{ huge: 'x'.repeat(65_536) }, 200, 'invalid_response'],
  ]) {
    const api = createAuthApi({ anonKey: ANON, now: () => NOW, fetch: async () => response(body, status) });
    await assert.rejects(api.exchange(CODE, VERIFIER), (error) => error.code === code);
  }
});

test('actual original return scripts erase code and display support instead of recovery completion', async () => {
  const html = await readFile(new URL('../melligo/auth/index.html', import.meta.url), 'utf8');
  const elements = new Map(['steps', 'heading', 'description'].map((id) => [id, { hidden: false, textContent: '' }]));
  const location = { search: `?code=${CODE}&state=${NONCE}&type=recovery`, hash: '', pathname: '/app-policies/melligo/auth/' };
  const context = vm.createContext({ URLSearchParams, location, window: {}, document: { getElementById: (id) => elements.get(id) }, history: { replaceState() { location.search = ''; location.hash = ''; } }, addEventListener() {} });
  for (const [, script] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) vm.runInContext(script, context);
  assert.equal(location.search, '');
  assert.match(elements.get('description').textContent, /does not reset passwords/);
  assert.equal(elements.has('password-form'), false);
});
