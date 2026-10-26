# Production deployment record — OIDC login-label fix (2026-10-26)

The `hermes` production host's checkout (`local/security-pins` branch) was 472 commits
behind `origin/main` at deploy time, so a straight cherry-pick of
`fix/oidc-login-label-full-subject` (commit `0f6f448e19`) onto it conflicted: that
commit calls a `gateway.session_identity.is_authenticated_identity` helper that doesn't
exist yet in that old tree.

**Adaptation applied** (deployed as `local/security-pins@f5fef1ce80` on `hermes`):
kept the checkout's existing, functionally-identical validity predicate
(`_methods_browser_control._is_authenticated_identity`, confirmed to check the same
fields — non-empty `user_id`+`provider`, excludes the internal server identity) and
only swapped the *payload* to the full-subject form via `gateway.session_identity.
authenticated_subject` (which already existed in that tree). The validity gate itself
is untouched from pre-fix code.

Verified against the live production `state.db`: three real pre-fix session rows
stamped in the old lossy `self-hosted:userid:...` form now pass `authorize_history`
for the owning OIDC subject (previously `permission_denied`).

The patch file alongside this note (`oidc-login-label-prod-adapted-20261026.patch`,
`git format-patch` output for the exact commit) is kept for audit/record purposes only.
The real fix for upstream contribution is the unmodified `fix/oidc-login-label-full-subject`
branch/commit `0f6f448e19` — this adaptation is specific to that one stale host and should
not be used as the basis for any PR.
