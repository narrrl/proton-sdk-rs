#!/usr/bin/env bash
#
# upstream-sync.sh — list C#-relevant upstream commits since our pinned SHA.
#
# Our pure-Rust port mirrors the canonical C# SDK only, so we watch the subtree
# client/cs/sdk/src and drop noise (chore/docs/test/ci/build) commits. The sdk/
# checkout is gitignored; UPSTREAM_SYNC.md holds the last-reconciled SHA.
#
# Usage:
#   ./scripts/upstream-sync.sh            # triage table only
#   ./scripts/upstream-sync.sh --diffs    # also print per-commit cs diffs
#   ./scripts/upstream-sync.sh --all      # don't drop noise commits
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="$ROOT/sdk"
PIN_FILE="$ROOT/UPSTREAM_SYNC.md"
SUBTREE="client/cs/sdk/src"
REMOTE_REF="origin/main"

# noise = conventional-commit prefixes that never carry portable behavior
NOISE='^[a-f0-9]+ (chore|docs|test|ci|build|style)(\(|:)'

show_diffs=false
keep_noise=false
for arg in "$@"; do
  case "$arg" in
    --diffs) show_diffs=true ;;
    --all)   keep_noise=true ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

[ -d "$SDK/.git" ] || { echo "error: $SDK is not a git checkout" >&2; exit 1; }

PIN="$(grep -oE '[0-9a-f]{40}' "$PIN_FILE" | head -1)"
[ -n "$PIN" ] || { echo "error: no 40-char SHA found in $PIN_FILE" >&2; exit 1; }

echo "fetching upstream..." >&2
git -C "$SDK" fetch --quiet origin

HEAD_SHA="$(git -C "$SDK" rev-parse --short "$REMOTE_REF")"
echo "pinned:  ${PIN:0:8}"
echo "head:    $HEAD_SHA  ($REMOTE_REF)"
echo "subtree: $SUBTREE"
echo

RANGE="$PIN..$REMOTE_REF"
commits="$(git -C "$SDK" log --oneline --no-decorate "$RANGE" -- "$SUBTREE" || true)"

if [ -z "$commits" ]; then
  echo "up to date — no cs commits since pin."
  exit 0
fi

if $keep_noise; then
  relevant="$commits"
else
  relevant="$(echo "$commits" | grep -vE "$NOISE" || true)"
fi

dropped="$(echo "$commits" | grep -cE "$NOISE" || true)"
echo "cs commits since pin: $(echo "$commits" | grep -c . || true)  (noise dropped: ${dropped:-0})"
echo

if [ -z "$relevant" ]; then
  echo "no behavioral commits to review (all noise). bump pin to $HEAD_SHA."
  exit 0
fi

echo "=== to triage ==="
echo "$relevant"

if $show_diffs; then
  echo
  echo "=== diffs (scoped to $SUBTREE) ==="
  echo "$relevant" | awk '{print $1}' | while read -r sha; do
    echo
    echo "----- $sha -----"
    git -C "$SDK" show --stat --format="%H%n%an %ci%n%n    %s%n" "$sha" -- "$SUBTREE"
  done
fi

echo
echo "after porting: update Pinned in UPSTREAM_SYNC.md to $HEAD_SHA"
