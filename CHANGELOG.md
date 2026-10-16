# Changelog

## Unreleased

- Group the admin sidebar into collapsible workspace, mail, delivery, operations, and access sections; preserve per-role filtering and active-page highlighting, keep labels horizontal on narrow screens, and link to the separate mailbox login.
- Replace mandatory TOTP enrollment with direct username/password login, 8-hour secure sessions, and password-only reauthentication for sensitive changes; upgrade existing password-authenticated pending sessions to the direct-login role.
- Remove the MFA enrollment UI and endpoints, and update admin/session views to show password authentication.
- Resolve client addresses from the TCP peer by default; accept one validated `X-Real-IP` only from explicitly configured trusted proxy CIDRs, and use the resolved address for login/setup limits and source-IP policy.
- Isolate validation artifacts by run ID and record scope, timestamps, source identity, environment versions, logs, and JUnit output under `validation/runs/<run-id>/`.
- Coalesce simultaneous CSRF refreshes, reject missing or malformed token responses, and report network failures as retryable security-session errors.
- Distinguish an unauthenticated session from a backend outage; keep the credential form hidden until the management API is reachable and provide a retry action.
- Add an integration regression test that denies DNS plan apply/rollback to Auditor and Operator roles even with a fresh authenticated session.

## 0.1.0 — 2026-10-15

Initial engineering source delivery from the supplied Astrogate Mail Admin specifications. Implemented control-plane/Agent code and explicitly scoped independent tests. Full production acceptance remains blocked by unverified builds/integration and the missing functionality enumerated in docs/ACCEPTANCE.md. No production systems or DNS were modified.
