# Contributing

Keep this project a generic local CLI. Caller projects own queries, research
design and corpus decisions. The package owns bounded retrieval, quota state,
recovery and local exports. Runtime must support Python 3.9+ and use the standard
library where possible.

Read [the development guide](docs/DEVELOPMENT.md) before changing code. Run the
complete offline suite, including installed-wheel subprocess tests, and syntax
compilation. Every credential store and transport in automated tests must be
mocked; socket or DNS attempts must fail the run. Never use a real API as a unit
test, and never commit local runtime state or licensed responses.

Preserve explicit bounded consent, append-only evidence, atomic bucket
reservation, secret-safe diagnostics and restricted-path validation. Keep the
existing distribution, application and credential identifiers compatible.

Document observable behavior and limitations. Do not describe a planned feature
as implemented, or a mocked result as a successful live API acceptance.
