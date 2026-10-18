# Changelog

## 0.3.2 — 2026-10-19

- Accept multiline UTF-8 queries, CRLF and tabs without trimming or rewriting
  quoted whitespace. Restricted frozen packages preserve source/transport text,
  both SHA-256 digests and the versioned identity-utf8-v1 rule; legacy packages
  remain supported. Illegal controls report safe codepoint and 1-based location.
- Add interactive stderr summaries for initialization, previews, status,
  export, quota and run outcomes while preserving stdout JSON and exit codes.
- Unify Keychain reading and writing on Security.framework. Preserve generic
  credential error codes with allowlisted reason/stage/backend/OSStatus and
  network-activity details. Bound read waits and discard late secret values.

## 0.3.1 — 2026-10-18

- Fixed per-user offline wheel installation and upgrades, with one PATH entry
  independent of the source checkout. Upgrade failures retain the active CLI.
- Removed implicit environment/user/tool-repository configuration fallback.
- Enforced project-folder bindings in simple and advanced commands; all commands
  use the policy-bound database and refuse to recreate lost bound state.
- Repaired project Git ignores and refused operations on tracked runtime data.
- Added installed console, source-independent execution, upgrade preservation,
  malformed nearest configuration and advanced-entry regression coverage.
- Prepared a standalone source repository with installation, usage, recovery,
  quota, compatibility, development and upload documentation. Added repository
  publication checks; no personal configuration, live payloads or source history
  are included.

## 0.3.0

- Completed the generic local init → check/search → execute → status/export/
  resume/usage workflow.
- Added folder-bound identities and credential references, native Keychain
  initialization, offline UNVERIFIED state, interrupted-init recovery and shared
  local quota accounting.
- Preserved legacy configuration and evidence compatibility while removing
  organizational notification requirements from newly initialized projects.
