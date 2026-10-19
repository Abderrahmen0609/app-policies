# Shared Melliti Nexus recovery candidate

Source only. This page recovers the shared account used by CoParent,
CleanRoutine, NexusConnect and NomadNest. A password change affects all four
apps. It does not create a family, grant access to shared records, or change
an app's sharing choice. Existing confirmation and email-code sign-in flows
are unchanged.

The isolated page adapts the published MelliGo recovery implementation at
app-policies main `35af9d411095793141b31bcee06e4dfa4d763e92`. The PKCE,
same-browser nonce, Web Locks, bounded timeout, 429 pause, one-use exchange,
memory-only token, password-only update, and local logout behavior are retained.
See `../../../melligo/auth/recovery/README.md` for the protocol rationale.

Suite uses the exact public publishable key from the reviewed CoParent client
and fixed project `tcyzzjhhvilcqzfbuwzk`. The key is public configuration, not a
server credential. Arbitrary keys, project URLs and return destinations are
not accepted from input. Its storage keys and Web Lock name are independent of
MelliGo. No SMTP, rate limit, password policy, or hosted Auth setting is changed.

The email request runs only after explicit form submission. The CoParent
candidate opens this fixed URL externally without an email query, session or
password. Both request and completion stay in that browser. The callback URL
is scrubbed before fallible setup; missing or mismatched same-browser state
fails closed. Tokens, emails and passwords are never stored or logged.

## Deployment prerequisites

1. Review the source and offline evidence. This candidate makes no hosted calls.
2. Publish only this new route and its assets, preserving existing routes and
   confirmation templates. Verify HTTPS, asset hashes, JavaScript MIME, CSP,
   logo and mobile layout before delivering an app link to it.
3. Freshly verify the exact Suite project and Auth configuration with a protected
   before snapshot. The saved Oct18 projection has localhost as Site URL and no
   redirect allowlist. It is insufficient for this callback. The exact recovery
   path and its nonce query must be accepted by the provider before live use.
   A reviewed change to a branded Suite Site URL affects fallback redirects for
   all four apps and all default-return email types; coordinate that separately.
   If using the prepared informational `/suite/auth/` Site URL, publish and
   verify that separate page first. Do not point the global Site URL at this
   recovery-only page, where confirmation/magic-link callbacks do not belong.
   Do not substitute a broad wildcard or change confirmation/password policy.
4. Branded recovery email subject/body is a separate reviewed provider patch.
   The existing portfolio confirmation/magic-link factory deliberately forbids
   recovery changes; do not enable or repurpose it silently. Company SMTP was
   present in the saved snapshot; actual delivery remains unproved here.
5. Only after routing is accepted, test one separately reviewed owned-account
   recovery from email through password update and fresh app sign-in. Changing
   this account's password affects all four apps and may have normal provider
   session/security-email effects. No password has been reset by this candidate.
6. Then build and deliver the CoParent entry change. No Android version,
   signed build, Play release, live provider setting or owner record is changed.

## Offline checks

`node --test tests/suite-recovery*.test.mjs`

The synthetic tests cover fixed project/key/token validation, callback and
nonce isolation, no update before recovery, wrong/missing tokens, uncertain
outcomes, concurrent tabs, 429 preservation, form bindings and shared-account
wording. They do not establish actual email delivery or redirect acceptance.
