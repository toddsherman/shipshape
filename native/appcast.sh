#!/bin/bash
# Writes dist/appcast.xml for the notarized DMG: Sparkle's feed of this release, with the DMG's EdDSA signature
# and the version's CHANGELOG.md notes, then signs the feed itself. Attach it to the GitHub release with the DMG.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACCOUNT="${SPARKLE_KEY_ACCOUNT:-shipshape}"
PLIST="$ROOT/native/Resources/Info.plist"
VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$PLIST")"
NAME="$(plutil -extract CFBundleName raw -o - "$PLIST")"
DMG="$ROOT/dist/${NAME// /-}-$VERSION.dmg"
FEED="$ROOT/dist/appcast.xml"
SPARKLE="$(bash "$ROOT/native/sparkle.sh")"
xcrun stapler validate "$DMG" >/dev/null
KEY="$("$SPARKLE/bin/generate_keys" --account "$ACCOUNT" -p)"
if [ "$KEY" != "$(plutil -extract SUPublicEDKey raw -o - "$PLIST")" ]; then
  printf '%s\n' "The Keychain's $ACCOUNT key doesn't match SUPublicEDKey in Info.plist. Nothing was written." >&2
  exit 1
fi
SIGNATURE="$("$SPARKLE/bin/sign_update" --account "$ACCOUNT" -p "$DMG")"
xcrun swiftc -swift-version 5 -O -parse-as-library "$ROOT/native/Release/Appcast.swift" "$ROOT/native/Release/AppcastTool.swift" -o "$ROOT/native/work/appcast"
"$ROOT/native/work/appcast" "$PLIST" "$ROOT/CHANGELOG.md" "$DMG" "$SIGNATURE" > "$FEED"
"$SPARKLE/bin/sign_update" --account "$ACCOUNT" "$FEED"
"$SPARKLE/bin/sign_update" --account "$ACCOUNT" --verify "$FEED"
"$SPARKLE/bin/sign_update" --account "$ACCOUNT" --verify "$DMG" "$SIGNATURE"
printf '%s\n' "$FEED"
