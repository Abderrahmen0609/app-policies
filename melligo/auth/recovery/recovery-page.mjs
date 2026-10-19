import { RECOVERY_URL, createAuthApi, createRecovery } from './recovery-core.mjs';
import { anonKey } from './public-config.mjs';

export async function mountRecovery({ document, window, history, publicAnon = anonKey }) {
  let originalHref = window.location.href;
  let urlCleared = false;
  try {
    history.replaceState(null, '', new URL(RECOVERY_URL).pathname);
    urlCleared = true;
  } catch { /* Do not initialize recovery if the callback cannot be scrubbed. */ }
  const requestForm = document.querySelector('#request-form');
  const passwordForm = document.querySelector('#password-form');
  const status = document.querySelector('#status');
  const restart = document.querySelector('#restart');
  const messages = {
    checking: 'Checking your recovery linkâ€¦',
    sending: 'Requesting your recovery emailâ€¦',
    sent: 'If this email has a MelliGo account, a recovery email will arrive. Open the latest link in this same browser. Keep this browser available.',
    saving: 'Changing your passwordâ€¦',
    complete: 'Your password has changed. Close this page and sign in to MelliGo with your new password.',
    uncertain: 'The password change could not be confirmed. Try signing in to MelliGo before requesting another recovery link. This page will not repeat the change.',
  };
  const errors = {
    invalid_email: 'Enter a valid email address.',
    password_rules: 'Use 8 to 256 characters without line breaks. Your accountâ€™s additional password rules still apply.',
    password_mismatch: 'The two passwords do not match.',
    same_browser_required: 'Open the latest link in the browser where you requested it. If you used another browser or device, start a new request here.',
    expired_link: 'This link or recovery session is invalid or has expired. Start a new request and use its latest email.',
    invalid_link: 'This recovery link is incomplete or invalid. Start a new request.',
    newer_request: 'A newer recovery request was started. Use the latest email in this browser.',
    rate_limited: 'Too many requests. Wait before making another request; no automatic retry was made.',
    storage_unavailable: 'This browser could not keep the temporary recovery request. Allow site storage or use another browser, then start again.',
    connection_error: 'The request could not be confirmed. Check your inbox before making another request.',
    request_rejected: 'The request could not be completed. Try again later or contact support.',
    invalid_response: 'Recovery could not be confirmed. Start a new request or contact support.',
    configuration: 'Recovery is temporarily unavailable. Contact support.',
  };
  let controller;
  function render(state) {
    const working = ['checking', 'sending', 'saving'].includes(state.phase);
    requestForm.hidden = !['request'].includes(state.phase);
    passwordForm.hidden = !['password', 'saving'].includes(state.phase);
    restart.hidden = working || state.phase === 'complete' || state.phase === 'request';
    for (const element of document.querySelectorAll('button,input')) element.disabled = working;
    status.textContent = state.error ? (errors[state.error] ?? errors.request_rejected) : (messages[state.phase] ?? 'Enter your new password.');
    if (state.phase === 'request' && !state.error) status.textContent = 'Request a recovery email, then open its latest link in this same browser.';
  }
  try {
    if (!urlCleared) throw new Error('url-not-cleared');
    if (window.top !== window.self) throw new Error('embedded');
    controller = createRecovery({
      storage: window.localStorage,
      crypto: window.crypto,
      api: createAuthApi({ anonKey: publicAnon, fetch: window.fetch.bind(window) }),
      notify: render,
    });
    await controller.initialize(originalHref, () => {});
  } catch {
    requestForm.hidden = true;
    passwordForm.hidden = true;
    status.textContent = errors.configuration;
  } finally { originalHref = null; }
  requestForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    await controller?.request(document.querySelector('#email').value);
  });
  passwordForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = document.querySelector('#password');
    const confirmation = document.querySelector('#confirmation');
    try { await controller?.update(password.value, confirmation.value); }
    finally { password.value = ''; confirmation.value = ''; }
  });
  restart.addEventListener('click', () => controller?.cancel());
  window.addEventListener('pagehide', () => {
    controller?.dispose();
    for (const id of ['email', 'password', 'confirmation']) document.querySelector(`#${id}`).value = '';
    requestForm.hidden = true;
    passwordForm.hidden = true;
  }, { once: true });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) window.location.replace(RECOVERY_URL);
  });
  return controller;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  await mountRecovery({ document, window, history });
}
