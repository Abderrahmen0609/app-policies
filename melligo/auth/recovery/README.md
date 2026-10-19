# MelliGo recovery candidate — source only

This new page is a separate request-and-completion flow. The existing
`melligo/auth/index.html` confirmation/magic-link return page is unchanged.
No app entry, app Auth behavior, app version, or hosted configuration is changed.

The page requests recovery only after the visitor submits an email. It generates
a random 256-bit PKCE verifier and an independent request nonce using Web Crypto,
then sends an S256 challenge to the existing project's `/auth/v1/recover` route.
The verifier, nonce, phase, and creation time are stored in a uniquely named
local-storage record. A send in progress may retain one previous pending record
inside it until the replacement is accepted. This permits an email link to open
in another tab of the same browser. No email, password, session token, or refresh
token is stored there.
The record expires locally after 30 minutes and is removed when consumed or when
an expired record is next used. A newer request replaces the pending local
verifier after acceptance. A definite HTTP429 restores its still-valid previous
pending context; an unknown response retains the attempted context because an
email may already have been sent. It does not revoke a recovery session that was
already exchanged in another page's memory.

The page requires the browser's same-origin Web Locks API to serialize short
context read/write transitions between current pages. The lock is never held
across an Auth network call: an old or newly delivered callback can complete
while a send response is pending. A second send started within an in-flight
send's 30-second request timeout is refused locally without an extra Auth call.
A callback consumes only its matching pending verifier. Cleanup checks the
current nonce and never replaces a consumed or newer observed context. Older
already-open page versions do not participate in the lock, so their unobserved
storage interleavings cannot be promised transactional protection. Browsers
without Web Locks fail closed with a current-compatible-browser instruction
before storage or Auth is accessed.

On HTTP429, only a validated Retry-After delay is retained, with a one-second
minimum and one-hour local maximum. Exact HTTP-date and integer-seconds values
are accepted; absent, hidden, invalid, or past-date values use a clearly labeled
60-second local pause. A separate non-sensitive storage record contains only the
pause's timestamp, deadline, source label and schema. The deadline survives reload
and is checked before any send. The form counts down and permits another manual
attempt after the local deadline, while explicitly warning that the server may
require a longer wait. It never automatically sends or claims the rate limit has
reset. No rate-limit, SMTP, password-policy, or hosted Auth setting is changed.

The callback accepts only the exact HTTPS page, one code, and a matching nonce.
It captures and clears the callback URL before fallible frame/storage/Auth setup,
and fails closed if URL clearing fails. It consumes the verifier before making the
one-use exchange, and rejects implicit bearer fragments or other return routes.
A missing verifier in another browser/device produces a request-again message.
The five-minute server Auth-code expiry remains enforced by Supabase; no expiry
or security setting is changed here. Request success uses a generic response to
avoid revealing whether an account exists.

The returned access token exists only in controller memory. The page accepts
only a same-project authenticated user response and uses that token to submit a
password-only update. The server's password policy still applies. The local form
requires 8–256 characters and matching confirmation, and does not trim passwords.
After a confirmed update it requests logout with **scope=local**, clears the
temporary session, and asks the visitor to sign in to MelliGo. It never globally
logs out an existing app/browser session. Password-update responses that cannot
be confirmed produce an explicit uncertain state and no blind retry. A failed
local logout does not turn a confirmed password change into a false failure.
Unloading a page loses its memory session; remote revocation cannot be guaranteed
if the browser/network closes before cleanup. No refresh token is retained.

All Auth requests use the app's existing **public anon** key and fixed project.
They are bounded, omit cookies, reject redirects, and have no automatic retries.
The page never logs links, codes, tokens, passwords, raw provider errors, or Auth
response bodies. It loads no third-party script, analytics, or assets. Its CSP
allows connections only under the project's Auth path. The form refuses to run
when embedded in a frame. Other app preferences and Auth-storage keys are untouched.

## Owner review and deployment holds

1. Review the exact source/pins and offline evidence before any publication.
2. Deploy only the new `melligo/auth/recovery/` files. Serve `.mjs` files with a
   JavaScript MIME type, verify the page/asset hashes and CSP, and preserve the
   existing return page/logo. Do not add an app button to an unpublished page.
3. No Auth configuration change is included. Current upstream Supabase Auth
   accepts same-origin Site URL redirects, including this new path. The actual
   hosted version and retention of the nonce query remain owner acceptance gates.
   If it falls back to the informational return page, stop and review the exact
   redirect configuration; do not add broad wildcards or weaken protections.
4. A later app entry can open this fixed page, so PKCE starts and ends in the
   browser. Do not call the app's default-PKCE reset method and then expect its
   private verifier to exist in the browser.
5. Actual email/recovery/password-change testing needs a separately reviewed
   owned-account case. No such action or deployment has been run by this candidate.
   A password change may have normal Auth session/security-email effects.

## Offline verification

Run the existing Node runtime, without installing packages:

```text
node --test tests/melligo-recovery.test.mjs tests/melligo-recovery-page.test.mjs tests/melligo-recovery-rate-limit.test.mjs
```

The tests use synthetic values, injected storage/fetch, the real form bindings,
Web Crypto, and an RFC7636 S256 vector. No hosted request or browser is opened.
They also execute the original informational return scripts in a fake DOM to
prove why that page cannot complete recovery. Offline checks do not establish
live email delivery, redirect acceptance, CSP/browser behavior, or password changes.

## Primary-source semantics checked

- [Supabase PKCE flow](https://supabase.com/docs/guides/auth/sessions/pkce-flow):
  same browser/device, locally held verifier, one-use short-lived Auth code.
- [Password reset](https://supabase.com/docs/reference/javascript/auth-resetpasswordforemail)
  and [password guide](https://supabase.com/docs/guides/auth/passwords): request,
  redirect, then authenticated password update; generic request acknowledgement.
- [Redirect URLs](https://supabase.com/docs/guides/auth/redirect-urls) and
  [upstream redirect validation](https://github.com/supabase/auth/blob/master/internal/utilities/request.go):
  review the exact destination and same-origin behavior rather than broadening it.
- Installed app SDK source: `gotrue` 2.13.0 `gotrue_client.dart` request/exchange/
  update/logout methods. This small Auth-only adapter follows those wire operations;
  it does not vendor a new SDK, change app dependencies, or use a server key.
