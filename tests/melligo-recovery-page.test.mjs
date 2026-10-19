import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { mountRecovery } from '../melligo/auth/recovery/recovery-page.mjs';
import { RECOVERY_URL, PROJECT_URL, STORAGE_KEY } from '../melligo/auth/recovery/recovery-core.mjs';

const jwt = (claims) => `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.fictional-signature`;
const ANON = jwt({ role: 'anon', ref: 'wodjmlcczrjxeexyhwpr' });
const USER = '11111111-1111-4111-8111-111111111111';
const NONCE = 'N'.repeat(43);
function element() {
  return { hidden: true, disabled: false, value: '', textContent: '', handlers: {}, addEventListener(name, action) { this.handlers[name] = action; } };
}
function browser(href = RECOVERY_URL) {
  const ids = ['request-form', 'password-form', 'status', 'restart', 'email', 'password', 'confirmation'];
  const elements = new Map(ids.map((id) => [id, element()]));
  const values = new Map();
  const calls = [];
  const listeners = {};
  const document = { querySelector: (selector) => elements.get(selector.slice(1)), querySelectorAll: () => [...elements.values()] };
  const window = {
    location: { href, replace(value) { this.href = value; } }, crypto: webcrypto,
    localStorage: { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) },
    addEventListener: (name, handler) => { listeners[name] = handler; },
    fetch: async (url, options) => {
      calls.push({ path: new URL(url).pathname, method: options.method });
      const body = url.includes('/token?')
        ? { access_token: jwt({ sub: USER, role: 'authenticated', iss: `${PROJECT_URL}/auth/v1`, exp: Math.floor(Date.now() / 1000) + 600 }), token_type: 'bearer', user: { id: USER } }
        : url.endsWith('/user') ? { id: USER } : {};
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  };
  window.self = window; window.top = window;
  const history = { replaceState(_state, _title, path) { window.location.href = new URL(path, RECOVERY_URL).href; } };
  return { document, window, history, elements, calls, values, listeners };
}

test('actual page request form is reachable and sends only on explicit submission', async () => {
  const b = browser();
  await mountRecovery({ ...b, publicAnon: ANON });
  assert.equal(b.elements.get('request-form').hidden, false);
  assert.equal(b.elements.get('password-form').hidden, true);
  assert.equal(b.calls.length, 0);
  b.elements.get('email').value = 'fictional@example.test';
  let prevented = false;
  await b.elements.get('request-form').handlers.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.deepEqual(b.calls, [{ path: '/auth/v1/recover', method: 'POST' }]);
  assert.match(b.elements.get('status').textContent, /If this email has a MelliGo account/);
  assert.equal(b.elements.get('restart').hidden, false);
});

test('actual callback form completes mocked password update, clears inputs and returns no tokens to DOM', async () => {
  const b = browser(`${RECOVERY_URL}?state=${NONCE}&code=fictional-code-0000000000000001`);
  b.values.set(STORAGE_KEY, JSON.stringify({ schema: 1, phase: 'pending', nonce: NONCE, verifier: 'V'.repeat(43), createdAt: Date.now() }));
  await mountRecovery({ ...b, publicAnon: ANON });
  assert.equal(b.window.location.href, RECOVERY_URL);
  assert.equal(b.elements.get('password-form').hidden, false);
  assert.equal(b.values.size, 0);
  b.elements.get('password').value = 'fictional new password'; b.elements.get('confirmation').value = 'fictional new password';
  await b.elements.get('password-form').handlers.submit({ preventDefault() {} });
  assert.deepEqual(b.calls.map((call) => call.path), ['/auth/v1/token', '/auth/v1/user', '/auth/v1/logout']);
  assert.match(b.elements.get('status').textContent, /Your password has changed/);
  assert.equal(b.elements.get('password').value, ''); assert.equal(b.elements.get('confirmation').value, '');
  assert.equal(b.elements.get('password-form').hidden, true);
  assert.equal([...b.elements.values()].some((el) => /fictional-signature|11111111/.test(el.textContent)), false);
});

test('missing same-browser state and hostile errors remain useful text, no network or HTML injection', async () => {
  const b = browser(`${RECOVERY_URL}?state=${NONCE}&code=fictional-code-0000000000000001`);
  await mountRecovery({ ...b, publicAnon: ANON });
  assert.match(b.elements.get('status').textContent, /browser where you requested it/);
  assert.equal(b.calls.length, 0);
  const hostile = browser(`${RECOVERY_URL}?error=denied&error_description=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`);
  await mountRecovery({ ...hostile, publicAnon: ANON });
  assert.equal(hostile.elements.get('status').textContent.includes('<img'), false);
  assert.equal(hostile.calls.length, 0);
});

test('embedding is blocked before Auth requests and existing return page remains separate', async () => {
  const b = browser(`${RECOVERY_URL}?state=${NONCE}&code=fictional-code-0000000000000001`); b.window.top = {};
  await mountRecovery({ ...b, publicAnon: ANON });
  assert.equal(b.window.location.href, RECOVERY_URL);
  assert.equal(b.elements.get('request-form').hidden, true);
  assert.equal(b.elements.get('password-form').hidden, true);
  assert.equal(b.calls.length, 0);
  const html = await readFile(new URL('../melligo/auth/recovery/index.html', import.meta.url), 'utf8');
  for (const id of ['request-form', 'password-form', 'status', 'restart', 'email', 'password', 'confirmation']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(html, /script-src 'self'/); assert.match(html, /form-action 'none'/); assert.match(html, /name="referrer" content="no-referrer"/);
  assert.equal(/https:\/\/(?:cdn|www\.google|.*analytics)/.test(html), false);
});

test('actual mount scrubs callback before a throwing localStorage getter, with no Auth setup', async () => {
  const b = browser(`${RECOVERY_URL}?state=${NONCE}&code=fictional-code-0000000000000001`);
  let reads = 0;
  Object.defineProperty(b.window, 'localStorage', { get() {
    reads++;
    assert.equal(b.window.location.href, RECOVERY_URL);
    throw new Error('fictional blocked storage');
  } });
  const controller = await mountRecovery({ ...b, publicAnon: ANON });
  assert.equal(reads, 1);
  assert.equal(controller, undefined);
  assert.equal(b.window.location.href, RECOVERY_URL);
  assert.equal(b.elements.get('request-form').hidden, true);
  assert.equal(b.elements.get('password-form').hidden, true);
  assert.equal(b.calls.length, 0);
});

test('a failed history scrub fails closed before storage or Auth is accessed', async () => {
  const b = browser(`${RECOVERY_URL}?state=${NONCE}&code=fictional-code-0000000000000001`);
  let reads = 0;
  Object.defineProperty(b.window, 'localStorage', { get() { reads++; throw Error('must not be reached'); } });
  b.history.replaceState = () => { throw Error('fictional blocked history'); };
  const controller = await mountRecovery({ ...b, publicAnon: ANON });
  assert.equal(controller, undefined);
  assert.equal(reads, 0);
  assert.equal(b.calls.length, 0);
  assert.equal(b.elements.get('request-form').hidden, true);
  assert.equal(b.elements.get('password-form').hidden, true);
});

test('page hiding clears private inputs; BFCache return loads clean request URL without replay', async () => {
  const b = browser(); await mountRecovery({ ...b, publicAnon: ANON });
  for (const id of ['email', 'password', 'confirmation']) b.elements.get(id).value = 'fictional private input';
  b.listeners.pagehide();
  for (const id of ['email', 'password', 'confirmation']) assert.equal(b.elements.get(id).value, '');
  assert.equal(b.elements.get('password-form').hidden, true);
  b.listeners.pageshow({ persisted: true });
  assert.equal(b.window.location.href, RECOVERY_URL);
  assert.equal(b.calls.length, 0);
});
