# Upstream sync

Tracks reconciliation of this pure-Rust port against the canonical **C#** SDK
(`ProtonDriveApps/sdk`, subtree `client/cs/sdk/src`). The `sdk/` checkout is
gitignored, so this file is the only durable record of what we last reviewed.

- **Upstream**: https://github.com/ProtonDriveApps/sdk
- **Reconciled subtree**: `client/cs/sdk/src`
- **Pinned**: `f2496161c2f704b72511aa1b804961285993850c`
- **Date**: 2026-07-10

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
| 2026-07-10 | `36430318` → `f2496161` | `9a1c39b3` | ported: validation check in `Thumbnail::new` returning `Result` instead of panicking. noise dropped: projects reorg / C# Account client move to incubating. deferred: device support (`32a8eed0`). |
