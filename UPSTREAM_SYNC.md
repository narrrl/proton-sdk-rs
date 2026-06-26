# Upstream sync

Tracks reconciliation of this pure-Rust port against the canonical **C#** SDK
(`ProtonDriveApps/sdk`, subtree `client/cs/sdk/src`). The `sdk/` checkout is
gitignored, so this file is the only durable record of what we last reviewed.

- **Upstream**: https://github.com/ProtonDriveApps/sdk
- **Reconciled subtree**: `client/cs/sdk/src`
- **Pinned**: `36430318919c30fac42ec8577036a6d6e9de916f`
- **Date**: 2026-06-26

## Workflow

1. `./scripts/upstream-sync.sh` — fetches upstream, lists cs-relevant commits
   since the pinned SHA, drops noise (chore/docs/test/ci/build), prints diffs.
2. Triage each surviving commit: behavioral change to port, or structural/cosmetic.
3. Port the behavioral diffs into `crates/`.
4. Bump **Pinned** (and **Date**) above to the new upstream HEAD; commit.

## Log

| date | from → to | ported | notes |
|------|-----------|--------|-------|
| 2026-06-25 | initial pin `fb4173ab` | — | baseline; delta reviewed, 0 behavioral changes outstanding |
| 2026-06-26 | `fb4173ab` → `36430318` | `36430318` | ported: enumeration returns `NodeUid`s (`enumerate_folder_children_node_uids` / `enumerate_trash_node_uids`), caller materializes via `enumerate_nodes`. noise dropped: BOM/deps/kt-enum-order/cs-account-refactor |
