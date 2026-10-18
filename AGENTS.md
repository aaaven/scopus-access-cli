# Repository operating rules

This repository implements **Scopus Access Tool**, a reusable local Python
package and CLI. It is not a project data repository. Existing identifiers
such as **UAEU Survey Research Access Layer** remain compatible with already
configured deployments; they do not restrict the intended audience.

Product scope is a reusable Scopus API tool: caller-supplied queries or
identifiers, bounded retrieval, quota accounting, and local exports. Research
topics, corpus construction, study screening, and bibliometric analysis belong
to consuming projects outside this repository. Keep registered application
and credential identifiers compatible with existing configurations.

## Product architecture

- Users supply their own API credentials. Do not build a shared-key service
  or require users to belong to the original institution.
- Bind credential references, local state, and output to the actual consuming
  project folder, not to a Codex chat or sidebar project. Multiple local
  callers of the same project must share that project's state.
- The target interface discovers the project from its root or descendants;
  it must not silently fall back to another project's key or quota state.
- SRC/PI notifications, organizational identity/approval workflows, remote Mac
  invocation, and remote result transfer are out of scope. Remove legacy
  dependencies during migration rather than extending those workflows.
- Deliver an installable CLI for terminals, scripts, and coding agents.
  Do not add a Codex skill, plugin, or HTTP/MCP service to the delivery scope.
- Keep explicit bounded live consent, safe credential handling, real quota
  observations, and recovery integrity when simplifying the legacy gates.
- ARCHITECTURE.md records the target design. Do not describe planned commands
  or configuration as implemented until the code and offline checks support it.

## Non-negotiable boundaries

- Development and automated tests are offline.  Tests must inject a mock secret
  provider and mock transport; they must fail if any socket connection is
  attempted.
- Never place an API key, cookie, bearer token, query secret, title, abstract,
  reference list, or raw Elsevier/Scopus payload in source control, SQLite
  control ledgers, control JSONL, stdout, exceptions, receipts, or manifests.
- A key alias is non-secret metadata. Persist credentials only in the system
  credential store. Outside that store, the value may exist only in process
  memory and the fixed `X-ELS-APIKey` request header; never pass it through argv,
  environment variables, or temporary files during initialization.
- Live access is fail-closed.  Code readiness, a Keychain item, a policy file,
  or quota capacity is not execution authority.
- The initial quota state is `UNVERIFIED`.  Planning baselines must never be
  turned into fabricated live quota observations.
- Evidence ledgers are append-only.  Reconciliation appends a successor linked
  to its predecessor; it never rewrites history.
- All required API buckets are reserved atomically with `BEGIN IMMEDIATE`.
- Raw responses and checkpoints belong only under the policy-allowlisted
  project `restricted_metadata` directory.  Resolve paths and reject traversal
  and symlink escapes before writing.
- Do not implement automatic scientific substitutions, cross-window splitting,
  key rotation, alternate endpoints, arbitrary headers, or redirects.

## Engineering constraints

- Support Python 3.9 and prefer the standard library.
- Keep the Python package under `src/scopus_access` and tests under `tests`.
- CLI stdout is a bounded JSONL control stream.  Human diagnostics go to
  stderr and must also be content/secret safe.
- Run the complete offline test suite and syntax compilation before committing.
- Never commit runtime databases, event logs, receipts, restricted data, raw
  responses, checkpoints, or secrets.
