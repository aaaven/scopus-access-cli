# Changelog

## 0.4.0 — 2026-10-19

- Expose whitelist-only quota validation states, reconciliation reasons and safe service error summaries. Keep HTTP 200 data on unknown telemetry and charge failed requests.
- Add local inspect/audit/capabilities, serialized start of original unadmitted executions and offline parameter revision. Late Terminal children share the same start gate.
- Expose explicit cursor, frozen sort, larger bounded budgets, COMPLETE Search and frozen-ID detail requests. Report saved-page identity/offset/total checks and actual field coverage without claiming entitlement or full references.
- Keep reference pagination, complete author/reference verification and real multi-page acceptance explicitly unfinished.

## 0.3.4 — 2026-10-19

- Let an agent run the usual init command without asking the user to copy a
  shell command. A missing interactive input terminal opens macOS Terminal,
  accepts the hidden key there, and returns the original initialization JSON.
- Keep credentials in the interactive child and native Keychain. Exchange only
  bounded non-secret completion metadata; no credential argv, environment,
  temporary files, agent output, or API requests.
- Preserve ready/pending bindings, cancellation and retry safety. Serialize
  per-project handoffs to prevent duplicate windows; bound waiting to five
  minutes and report launch, timeout, and in-progress failures safely.

- Add explicit execute/resume --terminal for already bounded, approved work.
  Return validated control events to the caller; keep preflight recovery on its
  original reservation and grant. Never enable this as an automatic permission
  fallback, retry a send, or report unknown IPC activity as zero requests.
- Stabilize upgrade-preservation test snapshots after SQLite finalization on
  Python 3.12 and compare file digests to avoid expensive binary error diffs.

- Open recovery locks by exclusive creation or reuse of their persistent inode;
  avoid a macOS concurrent O_CREAT lookup failure without retrying any request.

## 0.3.3 — 2026-10-19

- Dispatch resume by the original validated task type. A dedicated minimal
  preflight recovery path reuses its reservation only after secret_unavailable
  with zero attempts/pages, unchanged hash pins and no raw response files.
- Serialize preflight recovery validation through receipt publication across
  processes; preserve the one-request, one-record, zero-retry boundary and
  reject recorded attempts instead of repeating initial admission.
- Report expired releases as RELEASE_EXPIRED, requiring explicit reauthorization
  without automatic renewal. Existing survey recovery behavior is retained.

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
