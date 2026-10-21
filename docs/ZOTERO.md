# Optional Zotero synchronization (0.8.0)

The local, versioned bibliography remains the reproducible analysis input.
Zotero is an optional sharing and reference-management destination. Search,
enrichment, export, project initialization and dataset creation never invoke
Zotero synchronization. A Zotero failure cannot roll back a completed search.

This release was developed offline using synthetic records, a mock credential
store and mock HTTP responses. No real library, saved key, group permission or
research dataset was used for acceptance. Read or write commands below require
the user's separate authorization before use against a real account.

## Local workflow

Run from the consuming project's root or a descendant. The closest
`.scopus-access/policy.json` binds project identity, allowed data directories
and shared local state. An incomplete nearer project is an error; there is no
fallback to another project's credentials. Initialize the project with the
existing `scopus-access init` workflow when necessary.

```sh
# Local operations; substitute paths to your own restricted saved exports.
scopus-access dataset create --source /project/restricted_metadata/scopus/records.jsonl
scopus-access zotero configure --library-type group --library-id 123456
scopus-access zotero prepare --dataset <dataset-path-from-control-output>

# Optional: selected IDs, not a scientific inclusion decision by the CLI.
scopus-access zotero prepare --dataset <dataset-path> --selection /project/restricted_metadata/selected-ids.json
```

Configure binds an **existing** numeric group ID or personal user ID
(`--library-type user`). Group names are not unique identifiers and no name is
hardcoded. It never creates a group or changes group permissions. Key entry
requires a non-echoing interactive terminal. The native macOS Security.framework
backend stores the credential directly in Keychain, with a Zotero-specific
service and project/target-specific alias. There is no file, argv, environment
or temporary-file credential fallback. Repeated configuration does not read,
migrate or overwrite a saved key. The current platform implementation requires
macOS Keychain and POSIX locks; Python 3.9 is the minimum version.

The source may be a saved JSON, JSONL or CSV bibliography, including existing
Scopus record exports, delivery `publications.jsonl`/CSV, DOI enrichment and
publisher HTML wrappers. Delivery representatives retain all original EIDs;
the complete source wrapper and field provenance remain in local sidecars. Dataset creation freezes input,
conversion implementation, content hashes and the versioned DOI representative
policy. Same-DOI preference is Article > Book Chapter > Conference Paper >
Preprint, then nonempty bibliographic field count, then stable EID order.
This preference applies only inside a DOI group: other types remain candidates,
and it does not imply scientific quality or study eligibility. Invalid or
missing DOI records retain their stable local identity. Similar titles never
cause merging. Secondary records, original EIDs, source runs, raw references
and field provenance stay in the restricted local data plane.

Prepare freezes field conversion and a selected dataset version. The default
is all representatives; a selection file contains an explicit JSON array of
stable record IDs. Missing titles and unsupported types remain visible as
held records with reasons. Preparation does not claim that authors, abstracts,
keywords, references or affiliations are complete.

Supported source types currently map Article to journalArticle, Book Chapter
to bookSection, Conference Paper to conferencePaper, Preprint to preprint and
Book to book. Other types stay in the dataset and enter hold. For types whose
official template lacks a DOI field, DOI is preserved in a standard `DOI:`
Extra line; remote matching also checks that representation.

## Explicit read requests and a reviewable plan

```sh
scopus-access zotero check
scopus-access zotero plan --prepared <prepared-path>
```

These commands perform read requests only. Check reads the target and
`/keys/current`, verifies the target's declared access and reports that no
write test was performed. A write permission declaration is not a successful
write acceptance test and cannot override group membership restrictions.
Scanning is bounded to 100,000 remote items and 64 MiB per response; larger or
incomplete snapshots fail closed and require a separately designed workflow.

Plan retrieves a consistent paginated library snapshot, checks counts, unique
keys, library/item versions and final key inventory, and freezes official
item templates. A reviewable restricted plan lists create, fill-empty update,
skip and hold actions, reasons and nonempty-field conflicts. Existing manually
imported items participate in DOI matching. Local identity markers and target
isolated item mappings also participate. Multiple matches, conflicting IDs,
type mismatches and deleted matches stop that record in hold. No fuzzy title
deduplication or automatic scientific substitution occurs.

Existing nonempty Zotero values, including manual edits, are preserved. Only
empty fields are filled; this version has no overwrite switch. A STANDARD
first creator is never advertised as a full author list. Structured author
lists require appropriate source evidence. Author keywords, index keywords,
model-generated keywords, human topics and workflow tags remain distinct in
local sidecars. Item-level institutions do not imply author-affiliation links.
Zotero tags are not imported as analysis author keywords. Unsupported
structured metadata stays local. PDF, raw responses, notes, sidecars and
attachments are never uploaded by this module; attachment sync is unimplemented.

## Bounded writes and recovery

```sh
# Review the restricted plan and choose the item bound before authorizing writes.
scopus-access zotero push --plan <reviewed-plan-path> --max-items 5 --execute-live
```

Both an explicit execution switch and a positive processing bound are
mandatory. The plan fixes project, target, inputs, templates, implementation,
expiry and library version. A changed target, input, code, expired plan or
changed remote library requires a fresh plan. Batch requests contain at most
50 items and use version preconditions. The maximum bounds changes, not the
number of read requests needed to validate the library. Plans are one-use;
processing only part of a larger plan requires replanning the remainder.

Plans expire after one hour. Keep the original local source export available
and unchanged: this release revalidates its hash, the dataset manifest and the
prepared package before planning or sending a batch. To synchronize a changed
source, create a new dataset version. The frozen old version remains local.

Project-wide cross-process locking covers planning, attempts and mapping
publication. Before a write is sent, its frozen payload hash and attempt are
durable. Evidence is append-only and linked to its predecessor. Each response
index is classified independently as successful, unchanged or failed; HTTP
200 alone never makes all items successful. Detailed results and target
isolated local-ID/item-key mappings remain restricted. Control output contains
bounded safe status, counts, hashes and generated paths only.

There are no automatic write retries. Backoff and Retry-After, including
successful responses carrying Backoff, persist a cooldown across processes.
429/503 stop the operation. After interruption, a crash, partial failure or
unknown server outcome, never replay the old plan. Run a new read-only plan
after cooldown: it checks the predetermined keys and intended fields against
remote state, appends reconciliation evidence and either recognizes completed
changes or holds unresolved identities. Conflicting results require manual
review; they are never blindly resent. Existing retrieval reservations and
Scopus quota observations are untouched by Zotero activity.

## Security and public API references

All requests use fixed `https://api.zotero.org`, API v3 and the fixed
`Zotero-API-Key` header; no redirects, arbitrary endpoints or caller-supplied
headers are accepted. Scopus continues using its existing credential service
and `X-ELS-APIKey` header. Zotero counters and evidence are separate from
Scopus quota/state; no fabricated quota observation is introduced.

Content, detailed diffs, local datasets and sidecars may only be stored under
the project's policy-allowlisted `restricted_metadata` directory. Reads and
writes reject traversal and symlink escapes. Control ledgers, stdout,
exceptions and manifests must not contain keys, titles, abstracts, references
or raw publisher payloads. The existing application/distribution identifiers
remain compatible.

Implementation references checked on 2026-10-21:
[authentication, pagination and throttling](https://www.zotero.org/support/dev/web_api/v3/basics),
[permissions and versioned syncing](https://www.zotero.org/support/dev/web_api/v3/syncing),
[official templates and per-item batch writes](https://www.zotero.org/support/dev/web_api/v3/write_requests).

Live target access, Keychain interaction, account/group editing rights, server
template compatibility, actual write behavior and recovery against a real
library remain unverified. They require separate user authorization and a
bounded, reviewed plan. The prototype preparation counts are version-specific
observations and are not built into this package.
