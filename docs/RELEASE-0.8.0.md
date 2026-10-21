# 0.8.0 — optional Zotero synchronization

2026-10-21. This release adds optional Zotero synchronization to the published
0.7.0 CLI. It retains default DOI-priority deliveries, publisher HTML enrichment,
original-budget task recovery across upgrades, both console entry points and the
optional `browser` extra. Zotero adds no runtime dependencies; the base runtime
continues to use Python 3.9+ and the standard library on macOS.

新增本地不可变数据集和可选 Zotero 同步，保留 0.7.0 的 DOI 默认交付及出版社任务
升级兼容。普通检索、补全、交付和导出不会自动调用 Zotero。写入只补空值，保留
手工编辑；须提供已审阅的冻结计划、处理上限及 `--execute-live`。

## Implemented behavior

- `dataset create` freezes caller-selected saved JSON/JSONL/CSV, versioned DOI
  representatives, secondary records and provenance. Existing delivery
  `publications.jsonl`/CSV and DOI/publisher enrichment exports are supported;
  all original EIDs and source wrappers remain local.
- `zotero configure` binds an existing numeric user/group target and a separate
  project/target-specific native Keychain reference. `prepare` freezes local
  conversion without network access. Existing keys are not read or migrated.
- `check` and `plan` read only. Plans contain exact identity matches, official
  templates, a consistent complete library snapshot, create/fill-empty/skip/hold
  actions and reviewable nonempty conflicts in restricted storage.
- `push` requires a one-use unexpired plan, positive item limit and explicit live
  execution. Batches contain at most 50 items with version preconditions.
  Partial responses are classified per item. Lost responses and interruptions
  require read-only reconciliation and a fresh plan; writes are never retried
  automatically. Project locks and persisted server cooldowns coordinate callers.

Detailed commands, field semantics, path boundaries and recovery instructions
are in [ZOTERO.md](ZOTERO.md). Attachments, PDFs and notes are not uploaded.

## Offline acceptance

All acceptance uses synthetic records, mock credential stores and mock HTTP
services. Socket/DNS guards are installed before test discovery and independently
inside installed console subprocesses. Every completed run below passed without
skips or connection attempts.

| Validation | Python | Tests | Seconds |
| --- | --- | --- | --- |
| Integrated source and installed consoles | 3.9.6 | 602/602 | 299.185 |
| Integrated source and installed consoles | 3.12.3 | 602/602 | 201.884 |
| Final wheel package and installed consoles | 3.9.6 | 602/602 | 150.513 |
| Final wheel installed consoles | 3.12.3 | 17/17 | 38.100 |

Python 3.9 and 3.12 syntax compilation passed. Publication checks reject runtime
files, local paths, symlinks and broken documentation links. Archive audits check
all 39 package modules byte for byte against current source and enforce an
allowlist for source archive members. SHA-256 checksums accompany the archives.

Coverage includes initial/repeated/manual imports, DOI and missing-ID conflicts,
manual-field preservation, paginated snapshot changes/omissions, 50-item batches,
partial outcomes, throttling, server success with a lost response, pre-send
crashes, stale/edited plans, process locks, edited outcome evidence, source/config
tampering, delivery JSONL/CSV and enrichment conversion, and all existing search,
export, publisher task upgrade, quota and recovery regressions. The installed CLI
workflow covers `deliver` → dataset → prepare → check → plan → bounded mock push,
replay rejection and a subsequent skip, without changing Scopus usage.

Final wheel: `uaeu_scopus_access_layer-0.8.0-py3-none-any.whl`.
SHA-256: `04ed5c73536eeb1b0de9ae7e6119e94c112c26016249fa8bf8dcf521570744f8`.

The acceptance environment variables select test installations only; they do not
carry credentials. With a wheel installed in a disposable environment, run:

```sh
SCOPUS_TEST_INSTALLED_PYTHON=/path/to/validation/bin/python \
SCOPUS_TEST_INSTALLED_BIN=/path/to/validation/bin \
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_offline_tests.py

SCOPUS_TEST_PACKAGE_ROOT=/path/to/validation/lib/python3.9/site-packages \
SCOPUS_TEST_INSTALLED_PYTHON=/path/to/validation/bin/python \
SCOPUS_TEST_INSTALLED_BIN=/path/to/validation/bin \
/path/to/validation/bin/python -B scripts/run_offline_tests.py
```

## Build and upgrade

With setuptools and wheel available locally, build without an index:

```sh
python3 -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir dist/cli-0.8.0
python3 -c 'import setuptools.build_meta as b; b.build_sdist("dist/cli-0.8.0")'
python3 scripts/verify_zotero_release.py dist/cli-0.8.0/*.whl dist/cli-0.8.0/*.tar.gz
```

Upgrade the existing per-user CLI from the verified local wheel:

```sh
scopus-access install --wheel /path/to/uaeu_scopus_access_layer-0.8.0-py3-none-any.whl
~/.local/share/scopus-access/current/bin/python -I -c 'import scopus_access; print(scopus_access.__version__)'
scopus-access zotero --help
```

The installer validates a separate environment before atomically switching the
fixed entry point. It retains the previous version and does not discover or
modify consuming projects. It makes no Scopus/Zotero requests or key reads.

## Live acceptance boundary

No real library was accessed or modified, no saved real key was read or migrated,
no group permissions were changed and no Scopus request was made during this
acceptance. Actual native Keychain prompts, account/group editing rights, server
template compatibility and real write/recovery behavior remain unverified.
Successful offline tests and declared permissions do not establish live write
acceptance. A real account check needs an explicitly chosen target; a real write
also needs a reviewed restricted plan and a specific item bound.
