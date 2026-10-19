export const RECOVERY_URL = 'https://abderrahmen0609.github.io/app-policies/melligo/auth/recovery/';
export const PROJECT_URL = 'https://wodjmlcczrjxeexyhwpr.supabase.co';
export const STORAGE_KEY = 'melligo-password-recovery-pkce-v1';
export const REQUEST_LIFETIME = 30 * 60 * 1000;
export const COOLDOWN_KEY = 'melligo-password-recovery-cooldown-v1';
export const CONTEXT_LOCK = 'melligo-password-recovery-context-v1';
export const DEFAULT_RETRY_DELAY = 60_000;
export const MAX_RETRY_DELAY = 60 * 60 * 1000;
const SAFE = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

export class RecoveryError extends Error {
  constructor(code, retry = null) { super(code); this.code = code; this.retry = retry; }
}
const fail = (code) => { throw new RecoveryError(code); };

// Retry-After is untrusted and may be hidden by CORS. Never use it as a timer
// outside this bounded local pause, or promise that the next send will succeed.
export function retryDelay(value, now) {
  const fallback = { delay: DEFAULT_RETRY_DELAY, source: 'local' };
  if (typeof value !== 'string' || value.length > 128) return fallback;
  const text = value.trim();
  let delay;
  if (/^\d{1,10}$/.test(text)) delay = Number(text) * 1000;
  else if (/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(text)) {
    const date = Date.parse(text);
    if (!Number.isFinite(date) || new Date(date).toUTCString() !== text || date <= now) return fallback;
    delay = date - now;
  } else return fallback;
  return { delay: Math.max(1000, Math.min(delay, MAX_RETRY_DELAY)), source: 'server' };
}
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
      if (response.status === 429) throw new RecoveryError('rate_limited', retryDelay(response.headers.get('retry-after'), now()));
      if (response.status >= 500 && path.startsWith('recover?')) fail('connection_error');
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

export function createRecovery({ storage, crypto, api, contextLock, now = Date.now, notify = () => {} }) {
  if (typeof contextLock !== 'function') fail('compatible_browser');
  let state = { phase: 'request', error: null };
  let session = null;
  let busy = false;
  let disposed = false;
  let operation = null;
  let flowNonce = null;
  let cooldownUntil = 0;
  let cooldownSource = null;
  const snapshot = () => ({ ...state, busy, cooldownUntil, cooldownSource });
  const emit = (phase, error = null) => { if (!disposed) { state = { phase, error }; notify(snapshot()); } };
  const store = (value) => { try { storage.setItem(STORAGE_KEY, JSON.stringify(value)); } catch { fail('storage_unavailable'); } };
  const remove = () => { try { storage.removeItem(STORAGE_KEY); } catch { fail('storage_unavailable'); } };
  const readCooldown = () => {
    try {
      const raw = storage.getItem(COOLDOWN_KEY);
      if (!raw || raw.length > 256) return;
      const saved = JSON.parse(raw);
      if (saved.schema !== 1 || !Number.isSafeInteger(saved.at) || !Number.isSafeInteger(saved.until)
        || saved.at > now() + 60_000 || saved.until <= saved.at || saved.until > saved.at + MAX_RETRY_DELAY
        || saved.until > now() + MAX_RETRY_DELAY
        || !['local', 'server'].includes(saved.source)) return;
      if (saved.until > now() && saved.until > cooldownUntil) {
        cooldownUntil = saved.until; cooldownSource = saved.source;
      }
    } catch { /* A pause is advisory; request-context storage must still pass. */ }
  };
  const pause = (retry) => {
    const safe = retry && Number.isFinite(retry.delay) && ['local', 'server'].includes(retry.source)
      ? { delay: Math.max(1000, Math.min(retry.delay, MAX_RETRY_DELAY)), source: retry.source }
      : { delay: DEFAULT_RETRY_DELAY, source: 'local' };
    const at = now();
    readCooldown();
    if (at + safe.delay > cooldownUntil) { cooldownUntil = at + safe.delay; cooldownSource = safe.source; }
    try { storage.setItem(COOLDOWN_KEY, JSON.stringify({ schema: 1, at, until: cooldownUntil, source: cooldownSource })); }
    catch { /* Keep the RAM pause even if saving the advisory deadline fails. */ }
  };
  const pendingCopy = (value) => {
    if (!value || value.schema !== 1 || !['pending', 'requesting'].includes(value.phase)
      || !SAFE.test(value.nonce) || !SAFE.test(value.verifier) || !Number.isSafeInteger(value.createdAt)
      || value.createdAt > now() + 60_000 || now() >= value.createdAt + REQUEST_LIFETIME) return null;
    return { schema: 1, phase: 'pending', nonce: value.nonce, verifier: value.verifier, createdAt: value.createdAt };
  };
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
    state: snapshot,
    initialize(href, clearUrl) {
      return run('checking', async (signal) => {
        let parsed;
        try { parsed = parseReturn(href); } finally { clearUrl(); }
        if (parsed.kind === 'request') {
          await contextLock(signal, readCooldown);
          emit('request', cooldownUntil > now() ? 'rate_limited' : null); return;
        }
        if (parsed.kind === 'failed') fail('expired_link');
        const saved = await contextLock(signal, () => {
          const current = readContext(storage, now());
          // A callback need not wait behind another tab's network send. Its old
          // verifier remains available until that replacement is accepted.
          const candidate = current.nonce === parsed.nonce ? pendingCopy(current)
            : current.phase === 'requesting' ? pendingCopy(current.previous) : null;
          if (!candidate || candidate.nonce !== parsed.nonce) fail('same_browser_required');
          flowNonce = candidate.nonce;
          // Consume before exchange; an uncertain exchange cannot be replayed.
          store({ schema: 1, phase: 'exchanging', nonce: candidate.nonce, createdAt: candidate.createdAt });
          return candidate;
        });
        const received = await api.exchange(parsed.code, saved.verifier, signal);
        try {
          if (disposed) fail('cancelled');
          await contextLock(signal, () => {
            const current = readContext(storage, now());
            if (current.phase !== 'exchanging' || current.nonce !== flowNonce) fail('newer_request');
            remove();
          });
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
        let previous = null;
        const pair = await makePkce(crypto);
        if (disposed) return;
        await contextLock(signal, () => {
          readCooldown();
          if (cooldownUntil > now()) fail('rate_limited');
          try {
            const saved = readContext(storage, now());
            if (saved.phase === 'requesting' && now() < saved.createdAt + 30_000) fail('request_in_progress');
            previous = pendingCopy(saved);
          } catch (error) {
            if (['storage_unavailable', 'request_in_progress'].includes(error.code)) throw error;
          }
          flowNonce = pair.nonce;
          store({ schema: 1, phase: 'requesting', nonce: pair.nonce, verifier: pair.verifier, createdAt: now(), ...(previous ? { previous } : {}) });
        });
        const finish = (rejected) => contextLock(signal, () => {
          if (rejected) pause(rejected.retry);
          let current;
          try { current = readContext(storage, now()); } catch { return false; }
          // The lock covers only storage transitions, never a network request.
          // A consumed or newer observed nonce always wins over this cleanup.
          if (current.phase !== 'requesting' || current.nonce !== pair.nonce) return false;
          if (rejected) {
            const retained = pendingCopy(previous);
            if (retained) { store(retained); flowNonce = retained.nonce; }
            else remove();
          } else {
            const retained = pendingCopy(current);
            if (retained) store(retained);
          }
          return true;
        });
        try { await api.request(normalized, pair.challenge, pair.nonce, signal); }
        catch (error) {
          if (error instanceof RecoveryError && error.code === 'rate_limited') {
            await finish(error);
          } else await finish(null).catch(() => {});
          // A network timeout may have sent an email. Keep its verifier and the
          // check-inbox message; never restore an old flow or resend blindly.
          throw error;
        }
        const pending = await finish(null);
        // A link can be opened before this HTTP response arrives. Do not tell
        // that sender to reopen an already-consumed email or discard its form.
        if (!disposed) emit(pending ? 'sent' : 'handled');
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
        await contextLock(signal, () => {
          try {
            const saved = readContext(storage, now());
            if (saved.nonce === flowNonce) remove();
          } catch { /* Expired/missing storage has no reusable local session. */ }
        });
        emit('request');
      });
    },
    dispose() { disposed = true; operation?.abort(); session = null; },
  };
}
