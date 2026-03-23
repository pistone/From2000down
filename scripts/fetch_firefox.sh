#!/usr/bin/env bash
# Download and extract Firefox 147 source (the version before the Anthropic fixes).
# Usage: ./scripts/fetch_firefox.sh [target_dir]

set -euo pipefail

VERSION="147.0"
TARBALL="firefox-${VERSION}.source.tar.xz"
URL="https://archive.mozilla.org/pub/firefox/releases/${VERSION}/source/${TARBALL}"
TARGET_DIR="${1:-$(pwd)/data/firefox-${VERSION}}"

if [ -d "$TARGET_DIR" ]; then
    echo "Already exists: $TARGET_DIR"
    echo "To re-download, remove it first: rm -rf $TARGET_DIR"
    exit 0
fi

echo "=== Downloading Firefox ${VERSION} source ==="
echo "URL: $URL"
echo "This is ~500MB, may take a few minutes..."
echo ""

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -L --progress-bar -o "$TMPDIR/$TARBALL" "$URL"

echo ""
echo "=== Extracting to $TARGET_DIR ==="
mkdir -p "$(dirname "$TARGET_DIR")"
tar xf "$TMPDIR/$TARBALL" -C "$(dirname "$TARGET_DIR")"

# Mozilla tarballs extract to firefox-VERSION/
EXTRACTED="$(dirname "$TARGET_DIR")/firefox-${VERSION}"
if [ "$EXTRACTED" != "$TARGET_DIR" ] && [ -d "$EXTRACTED" ]; then
    mv "$EXTRACTED" "$TARGET_DIR"
fi

echo ""
echo "=== Done ==="
echo "Firefox source at: $TARGET_DIR"

# Count C++ files in key directories
for dir in js/src dom gfx image media; do
    if [ -d "$TARGET_DIR/$dir" ]; then
        count=$(find "$TARGET_DIR/$dir" -name '*.cpp' -o -name '*.cc' -o -name '*.h' | wc -l | tr -d ' ')
        echo "  $dir/: $count C/C++ files"
    fi
done
