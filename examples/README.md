# Offline fixtures only

The JSON files in this directory are synthetic compatibility examples. They
contain no user's key, real research query or live API response. The policy
disables live capability and the release is marked OFFLINE_DEMO_ONLY.

Do not edit these fixtures into production authority. New users should run
`scopus-access init` in their own consuming project and provide their own exact
query. See the [usage guide](../docs/USAGE.md).
