#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$ROOT/native/Resources/Info.plist")"
NAME="$(plutil -extract CFBundleName raw -o - "$ROOT/native/Resources/Info.plist")"
DMG="$ROOT/dist/${NAME// /-}-$VERSION.dmg"
STAGE="$(mktemp -d "$ROOT/native/work/dmg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
ditto "$ROOT/dist/$NAME.app" "$STAGE/$NAME.app"
ln -s /Applications "$STAGE/Applications"
cp "$ROOT/native/Resources/Install.txt" "$STAGE/Read me.txt"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
if [ -n "${SIGN_IDENTITY:-}" ]; then codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG"; fi
(cd "$ROOT/dist" && shasum -a 256 "$(basename "$DMG")") > "$ROOT/dist/SHA256SUMS.txt"
