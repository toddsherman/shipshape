#!/bin/bash
set -euo pipefail
if [ "$#" -ne 1 ]; then printf '%s\n' 'Usage: bash native/notarize.sh SAVED_KEYCHAIN_PROFILE' >&2; exit 2; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$ROOT/native/Resources/Info.plist")"
NAME="$(plutil -extract CFBundleName raw -o - "$ROOT/native/Resources/Info.plist")"
DMG="$ROOT/dist/${NAME// /-}-$VERSION.dmg"
APP="$ROOT/dist/$NAME.app"
RESULT="$ROOT/native/work/notarization-result.json"
xcrun notarytool submit "$DMG" --keychain-profile "$1" --wait --output-format json > "$RESULT"
STATUS="$(plutil -extract status raw -o - "$RESULT")"
if [ "$STATUS" != 'Accepted' ]; then printf 'Notarization status: %s. See native/work/notarization-result.json.\n' "$STATUS" >&2; exit 1; fi
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
(cd "$ROOT/dist" && shasum -a 256 "$(basename "$DMG")") > "$ROOT/dist/SHA256SUMS.txt"
printf '%s\n' 'Notarization accepted and tickets stapled. Update the distribution notes before sharing.'
