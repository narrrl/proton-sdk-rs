# Upstream sync

Tracks reconciliation of this pure-Rust port against the canonical **C#** SDK
(`ProtonDriveApps/sdk`, subtree `client/cs/sdk/src`). The `sdk/` checkout is
gitignored, so this file is the only durable record of what we last reviewed.

- **Upstream**: https://github.com/ProtonDriveApps/sdk
- **Reconciled subtree**: `client/cs/sdk/src`
- **Pinned**: `fb4173ab823a62c1c9f5a11d1b8320d4ce0ea4dc`
- **Date**: 2026-06-25

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
