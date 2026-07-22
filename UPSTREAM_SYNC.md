# Upstream sync

Tracks reconciliation of this pure-Rust port against the canonical **C#** SDK
(`ProtonDriveApps/sdk`, subtree `client/cs/sdk/src`). The `sdk/` checkout is
gitignored, so this file is the only durable record of what we last reviewed.

- **Upstream**: https://github.com/ProtonDriveApps/sdk
- **Reconciled subtree**: `client/cs/src` (was `client/cs/sdk/src` before the
  mid-2026 projects reorg; the script watches both)
- **Pinned**: `1b6ff83566d73b331e6842f683f1c9afe2d5b4ee`
- **Date**: 2026-07-22

> **Note**: upstream force-pushes — the SHAs in rows before 2026-07-14 no longer
> exist in its history. Triage by commit subject/date when a pin goes stale.

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
| 2026-07-14 | `f2496161` → `2219a42f` | `d15fa9b9`, `bead8f65`, `f6b12911`, `c0940f52`, `b88b8041`, `2eb69c46` | upstream force-pushed + moved the cs subtree, so the old pin was dangling and the script silently reported "up to date" (both fixed). ported: **devices** (`devices.rs` + `enumerate_devices` / `create_device` / `rename_device` / `delete_device`; volume-free `DeviceUid`), **node sharing flags** (`Node::is_shared` / `is_shared_publicly` from the link `Sharing` block), **revision state** (`NodeKind::File::active_revision_state`), **shared-with-me** (`enumerate_shared_with_me_node_uids`, `GET v2/sharedwithme`), **leave shared node** (`leave_shared_node`, `DELETE v2/shares/{sid}/members/{mid}`). no-op: `15fa845e` (non-JSON error bodies — `http.rs` already falls back to a status-only error when the envelope won't parse). diverged deliberately: `9a7f1d02` + `b4dadf02` removed the C# entity cache and its tags; ours stays. cosmetic, not ported: `30ab32c1` / `388d3900` (C# field renames), `1a781ade` (buffer lengths). |
| 2026-07-22 | `2219a42f` → `1b6ff835` | `ded1b716`, `071f976f` | ported: **atomic small uploads** for buffered new files and revisions (`DriveSmallFileUpload` is an explicit opt-in because this crate has no remote feature-flag provider), and **photo duplicate detection** using name/content HMAC matching. already covered/no-op: `ee0b3fba` (Rust rename accepts `Option<&str>`), `193c26f1` (Rust in-memory cache already has bounded LRU eviction), `29d359e0` (digest representation refactor retains hex JSON), `5c370289` (C# disposal lifetime only), `95752055` (Photos cache construction only). deliberately not ported: `2bf49aae` / `2590d227` cache storage-format changes; Rust exposes a distinct string repository contract and ships no persistent backend to migrate/reset. |
