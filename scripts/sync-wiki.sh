#!/usr/bin/env bash
# Sync the in-repo docs/wiki/ directory to the GitHub Wiki.
#
# The GitHub Wiki is a separate git repository (<owner>/<repo>.wiki.git),
# so it must be pushed to explicitly. This script clones it, mirrors
# docs/wiki/ into it, and pushes.
#
# Requirements:
#   - GitHub CLI (`gh`) installed and authenticated: `gh auth login`
#
# Usage:
#   ./scripts/sync-wiki.sh
#   ./scripts/sync-wiki.sh blueokanna/TypeBit   # explicit target
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    REMOTE="$(git remote get-url origin 2>/dev/null || true)"
    if [[ "$REMOTE" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
        TARGET="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
    fi
fi
if [[ -z "$TARGET" ]]; then
    echo "error: could not determine repo; pass it explicitly: $0 <owner>/<repo>" >&2
    exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
    echo "error: GitHub CLI 'gh' is required (https://cli.github.com) — run: gh auth login" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "cloning wiki for $TARGET ..."
gh repo clone "$TARGET.wiki" "$TMP" -- --quiet

echo "mirroring docs/wiki -> wiki ..."
find "$TMP" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
cp -R docs/wiki/. "$TMP"/

git -C "$TMP" add -A
if git -C "$TMP" diff --cached --quiet; then
    echo "no wiki changes"
else
    git -C "$TMP" commit -m "sync wiki from docs/wiki"
    git -C "$TMP" push
    echo "wiki synced: https://github.com/$TARGET/wiki"
fi
