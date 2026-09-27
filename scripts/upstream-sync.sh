#!/usr/bin/env bash
#
# upstream-sync.sh — list C#-relevant upstream commits since our pinned SHA.
#
# Our pure-Rust port mirrors the canonical C# SDK only, so we watch the C#
# subtree (see SUBTREE) and drop noise (chore/docs/test/ci/build) commits. The sdk/
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
# The C# sources moved from client/cs/sdk/src to client/cs/src in the mid-2026
# projects reorg; watch both so ranges spanning the move stay complete.
SUBTREE=(client/cs/src client/cs/sdk/src)
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

git -C "$SDK" rev-parse --git-dir >/dev/null 2>&1 || { echo "error: $SDK is not a git checkout" >&2; exit 1; }

# first 7-40 char SHA on the Pinned line; the rest of the file is history
PIN="$(grep -m1 'Pinned' "$PIN_FILE" | grep -oE '[0-9a-f]{7,40}' | head -1 || true)"
[ -n "$PIN" ] || { echo "error: no Pinned SHA found in $PIN_FILE" >&2; exit 1; }

echo "fetching upstream..." >&2
git -C "$SDK" fetch --quiet origin

# Upstream force-pushes: a dangling pin used to read as "up to date", and a
# rewritten-away pin still resolves locally until gc. Require ancestry instead.
PIN="$(git -C "$SDK" rev-parse --verify --quiet "${PIN}^{commit}" || true)"
if [ -z "$PIN" ] || ! git -C "$SDK" merge-base --is-ancestor "$PIN" "$REMOTE_REF"; then
  echo "error: pinned commit is not in the upstream history of $REMOTE_REF." >&2
  echo "       upstream rewrote its history; re-pin from a commit date in the log." >&2
  exit 1
fi

HEAD_SHA="$(git -C "$SDK" rev-parse "$REMOTE_REF")"
echo "pinned:  ${PIN:0:8}"
echo "head:    ${HEAD_SHA:0:8}  ($REMOTE_REF)"
echo "subtree: ${SUBTREE[*]}"
echo

RANGE="$PIN..$REMOTE_REF"
commits="$(git -C "$SDK" log --oneline --no-decorate "$RANGE" -- "${SUBTREE[@]}")"

if [ -z "$commits" ]; then
  echo "up to date — no cs commits since pin."
  exit 0
fi

if $keep_noise; then
  relevant="$commits"
else
  relevant="$(echo "$commits" | grep -vE "$NOISE" || true)"
fi

if $keep_noise; then
  dropped=0
else
  dropped="$(echo "$commits" | grep -cE "$NOISE" || true)"
fi
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
  echo "=== diffs (scoped to ${SUBTREE[*]}) ==="
  echo "$relevant" | awk '{print $1}' | while read -r sha; do
    echo
    echo "----- $sha -----"
    git -C "$SDK" show --stat --patch --format="%H%n%an %ci%n%n    %s%n" "$sha" -- "${SUBTREE[@]}"
  done
fi

echo
echo "after porting: update Pinned in UPSTREAM_SYNC.md to $HEAD_SHA"
