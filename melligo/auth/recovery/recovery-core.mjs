export const RECOVERY_URL = 'https://abderrahmen0609.github.io/app-policies/melligo/auth/recovery/';
export const PROJECT_URL = 'https://wodjmlcczrjxeexyhwpr.supabase.co';
export const STORAGE_KEY = 'melligo-password-recovery-pkce-v1';
export const REQUEST_LIFETIME = 30 * 60 * 1000;
const SAFE = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export class RecoveryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = (code) => { throw new RecoveryError(code); };
const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const decode = (value) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '=')), (c) => c.charCodeAt(0)),
));

export async function makePkce(crypto) {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  return { verifier, nonce, challenge };
}

// No arbitrary return URLs, implicit bearer fragments, duplicate values, or other flows.
export function parseReturn(href) {
  let url;
  try { url = new URL(href); } catch { fail('invalid_link'); }
  const expected = new URL(RECOVERY_URL);
  if (url.origin !== expected.origin || url.pathname !== expected.pathname || url.username || url.password) fail('invalid_link');
  if (url.hash) fail('invalid_link');
  if (!url.search) return { kind: 'request' };
  const allowed = new Set(['code', 'state', 'error', 'error_code', 'error_description']);
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) fail('invalid_link');
  }
  if (url.searchParams.has('error') || url.searchParams.has('error_code')) return { kind: 'failed' };
  const code = url.searchParams.get('code');
  const nonce = url.searchParams.get('state');
  if (!code || !/^[A-Za-z0-9._~-]{20,2048}$/.test(code) || !nonce || !SAFE.test(nonce) || url.searchParams.size !== 2) fail('invalid_link');
  return { kind: 'callback', code, nonce };
}

export function validatePassword(password, confirmation) {
  if (typeof password !== 'string' || [...password].length < 8 || password.length > 256 || /[\x00-\x1f\x7f]/.test(password)) return 'password_rules';
  if (password !== confirmation) return 'password_mismatch';
  return null;
}

function readContext(storage, now) {
  let raw;
  try { raw = storage.getItem(STORAGE_KEY); } catch { fail('storage_unavailable'); }
  if (!raw) fail('same_browser_required');
  if (raw.length > 1024) fail('invalid_link');
  let value;
  try { value = JSON.parse(raw); } catch { fail('invalid_link'); }
  if (!value || value.schema !== 1 || !SAFE.test(value.nonce) || !Number.isSafeInteger(value.createdAt) || value.createdAt > now + 60_000) fail('invalid_link');
  if (now >= value.createdAt + REQUEST_LIFETIME) {
    try { storage.removeItem(STORAGE_KEY); } catch { fail('storage_unavailable'); }
    fail('expired_link');
  }
  return value;
}

// This adapter is limited to this project's Auth routes. It never logs API bodies.
export function createAuthApi({ anonKey, fetch: fetcher, now = Date.now }) {
  let claims;
  try { claims = decode(anonKey.split('.')[1]); } catch { fail('configuration'); }
  if (claims.role !== 'anon' || claims.ref !== 'wodjmlcczrjxeexyhwpr') fail('configuration');
  async function call(path, method, body, bearer, signal) {
    const headers = { apikey: anonKey, 'Content-Type': 'application/json', 'X-Supabase-Api-Version': '2024-01-01' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    let response;
    try {
      response = await fetcher(`${PROJECT_URL}/auth/v1/${path}`, {
        method, headers, body: body === null ? undefined : JSON.stringify(body), signal,
        credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
    } catch { fail('connection_error'); }
    if (!response.ok) {
      if (response.status === 429) fail('rate_limited');
      if (response.status === 401 || response.status === 403 || (response.status === 400 && path.startsWith('token?'))) fail('expired_link');
      fail('request_rejected');
    }
    if (path.startsWith('recover?') || path.startsWith('logout?')) {
      await response.body?.cancel().catch(() => {});
      return null;
    }
    if (!response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) fail('invalid_response');
    const reader = response.body.getReader();
    let size = 0;
    const parts = [];
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 65_536) fail('invalid_response');
        parts.push(value);
      }
    } finally { await reader.cancel().catch(() => {}); }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
    catch { fail('invalid_response'); }
  }
  return {
    request(email, challenge, nonce, signal) {
      const redirect = `${RECOVERY_URL}?state=${nonce}`;
      return call(`recover?redirect_to=${encodeURIComponent(redirect)}`, 'POST', {
        email, code_challenge: challenge, code_challenge_method: 's256',
      }, null, signal);
    },
    async exchange(code, verifier, signal) {
      const result = await call('token?grant_type=pkce', 'POST', { auth_code: code, code_verifier: verifier }, null, signal);
      let jwt;
      try { jwt = decode(result.access_token.split('.')[1]); } catch { fail('invalid_response'); }
      if (result.token_type !== 'bearer' || !UUID.test(result.user?.id) || jwt.sub !== result.user.id || jwt.role !== 'authenticated'
        || jwt.iss !== `${PROJECT_URL}/auth/v1` || !Number.isSafeInteger(jwt.exp) || jwt.exp * 1000 <= now()) fail('invalid_response');
      // The refresh token and user profile are deliberately not retained.
      return { token: result.access_token, expiresAt: jwt.exp * 1000 };
    },
    async update(password, token, signal) {
      const user = await call('user', 'PUT', { password }, token, signal);
      if (!UUID.test(user?.id) || user.id !== decode(token.split('.')[1]).sub) fail('invalid_response');
    },
    async logout(token, signal) {
      const cleanup = new AbortController();
      const timeout = setTimeout(() => cleanup.abort(), 10_000);
      try { return await call('logout?scope=local', 'POST', null, token, signal ?? cleanup.signal); }
      finally { clearTimeout(timeout); }
    },
  };
}

export function createRecovery({ storage, crypto, api, now = Date.now, notify = () => {} }) {
  let state = { phase: 'request', error: null };
  let session = null;
  let busy = false;
  let disposed = false;
  let operation = null;
  let flowNonce = null;
  const emit = (phase, error = null) => { if (!disposed) { state = { phase, error }; notify({ ...state }); } };
  const store = (value) => { try { storage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch { fail('storage_unavailable'); } };
  const remove = () => { try { storage.removeItem(STORAGE_KEY); } catch { fail('storage_unavailable'); } };
  const run = async (phase, action) => {
    if (busy || disposed) return;
    busy = true;
    operation = new AbortController();
    const timeout = setTimeout(() => operation?.abort(), 30_000);
    emit(phase);
    try { await action(operation.signal); }
    catch (error) { emit(session ? 'password' : 'request', error instanceof RecoveryError ? error.code : 'request_rejected'); }
    finally { clearTimeout(timeout); busy = false; operation = null; }
  };
  return {
    state: () => ({ ...state, busy }),
    initialize(href, clearUrl) {
      return run('checking', async (signal) => {
        let parsed;
        try { parsed = parseReturn(href); } finally { clearUrl(); }
        if (parsed.kind === 'request') { emit('request'); return; }
        if (parsed.kind === 'failed') fail('expired_link');
        const saved = readContext(storage, now());
        if (saved.phase !== 'pending' || !SAFE.test(saved.verifier) || saved.nonce !== parsed.nonce) fail('same_browser_required');
        flowNonce = saved.nonce;
        // Consume the verifier before exchange; a reload/uncertain exchange needs a new request.
        store({ schema: 1, phase: 'exchanging', nonce: saved.nonce, createdAt: saved.createdAt });
        const received = await api.exchange(parsed.code, saved.verifier, signal);
        try {
          if (disposed) fail('cancelled');
          const current = readContext(storage, now());
          if (current.phase !== 'exchanging' || current.nonce !== flowNonce) fail('newer_request');
          remove();
        } catch (error) {
          await api.logout(received.token).catch(() => {});
          throw error;
        }
        session = received;
        emit('password');
      });
    },
    request(email) {
      return run('sending', async (signal) => {
        if (session) fail('request_rejected');
        const normalized = typeof email === 'string' ? email.trim() : '';
        if (normalized.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) fail('invalid_email');
        const pair = await makePkce(crypto);
        if (disposed) return;
        flowNonce = pair.nonce;
        store({ schema: 1, phase: 'pending', nonce: pair.nonce, verifier: pair.verifier, createdAt: now() });
        await api.request(normalized, pair.challenge, pair.nonce, signal);
        if (!disposed) emit('sent'); // Same acknowledgement whether or not the account exists.
      });
    },
    update(password, confirmation) {
      return run('saving', async (signal) => {
        const issue = validatePassword(password, confirmation);
        if (issue) fail(issue);
        if (!session || session.expiresAt <= now()) { session = null; fail('expired_link'); }
        const token = session.token;
        try { await api.update(password, token, signal); }
        catch {
          // A lost response might follow a completed change. Do not offer a blind retry.
          session = null;
          await api.logout(token).catch(() => {});
          emit('uncertain');
          return;
        }
        // Password update is complete even if local-session cleanup loses its connection.
        session = null;
        await api.logout(token, signal).catch(() => {});
        emit('complete');
      });
    },
    cancel() {
      return run('checking', async (signal) => {
        const old = session;
        session = null;
        if (old) await api.logout(old.token, signal).catch(() => {});
        try {
          const saved = readContext(storage, now());
          if (saved.nonce === flowNonce) remove();
        } catch { /* Expired/missing storage has no reusable local session. */ }
        emit('request');
      });
    },
    dispose() { disposed = true; operation?.abort(); session = null; },
  };
}
